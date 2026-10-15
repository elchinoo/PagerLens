"""OTLP/HTTP receiver: any OpenTelemetry SDK or Collector can send logs and metrics here.

Accepts protobuf and JSON bodies (optionally gzip, with a bounded decompression), maps them onto the same tables the
ingest API fills, and goes through the same validation and PII scrubbing. Traces are acknowledged but not stored.

Mapping: resource `service.name` -> service; `service.version` -> a deploy when it CHANGES (the first sighting is only
a baseline, so connecting a service never invents a deploy); optional resource `pagerlens.depends_on` (comma list) ->
dependencies. Metric attributes are not kept: series that differ only by attributes collapse into one.
"""
import json
import math
import re
import zlib
from datetime import UTC, datetime

from google.protobuf.json_format import MessageToDict
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
    ExportLogsServiceRequest,
    ExportLogsServiceResponse,
)
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import (
    ExportMetricsServiceRequest,
    ExportMetricsServiceResponse,
)
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
    ExportTraceServiceResponse,
)

from . import ingest
from . import settings_store as store
from .scrub import normalise_level

MAX_DECOMPRESSED = 8 * 1024 * 1024
_STATE_LIMIT = 10_000
_prev: dict[tuple, tuple] = {}     # cumulative -> rate/delta conversion; in memory, so one point is lost per restart


class OtlpError(ValueError):
    pass


def decode(body: bytes, content_type: str, encoding: str, request_cls) -> dict:
    """Bytes -> the OTLP JSON structure (camelCase dict) whether the sender used protobuf or JSON."""
    if encoding in ("gzip", "x-gzip"):
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            body = d.decompress(body, MAX_DECOMPRESSED)
        except zlib.error as exc:
            raise OtlpError("body is not valid gzip") from exc
        if d.unconsumed_tail or not d.eof and len(body) >= MAX_DECOMPRESSED:
            raise OtlpError("decompressed body is too large")
    elif encoding not in ("", "identity"):
        raise OtlpError(f"unsupported Content-Encoding {encoding!r}")
    ct = content_type.split(";")[0].strip().lower()
    if ct == "application/json":
        try:
            data = json.loads(body or b"{}")
        except ValueError as exc:
            raise OtlpError("body is not valid JSON") from exc
        if not isinstance(data, dict):
            raise OtlpError("JSON body must be an object")
        return data
    if ct in ("application/x-protobuf", "application/protobuf"):
        msg = request_cls()
        try:
            msg.ParseFromString(body)
        except Exception as exc:  # noqa: BLE001 - protobuf raises DecodeError and others
            raise OtlpError("body is not a valid OTLP protobuf message") from exc
        return MessageToDict(msg)
    raise OtlpError("Content-Type must be application/x-protobuf or application/json")


def _any(v: dict):
    if not isinstance(v, dict):
        return None
    for k in ("stringValue", "boolValue", "doubleValue"):
        if k in v:
            return v[k]
    if "intValue" in v:
        try:
            return int(v["intValue"])
        except (TypeError, ValueError):
            return None
    if "arrayValue" in v:
        return [_any(x) for x in (v["arrayValue"].get("values") or [])][:30]
    if "kvlistValue" in v:
        return _attrs(v["kvlistValue"].get("values"))
    return None


def _attrs(items) -> dict:
    return {str(kv.get("key", ""))[:60]: _any(kv.get("value", {})) for kv in (items or [])[:60] if isinstance(kv, dict)}


def _service_name(attrs: dict) -> str | None:
    raw = str(attrs.get("service.name") or "").lower().split(":")[0]
    name = re.sub(r"[^a-z0-9._-]+", "-", raw).strip("-._")[:63]
    return name if ingest.NAME.match(name or "-") else None


def _ts(nanos, now: datetime) -> str:
    try:
        ts = datetime.fromtimestamp(int(nanos) / 1e9, UTC)
        ingest.parse_ts(ts.isoformat())
        return ts.isoformat()
    except (TypeError, ValueError, OverflowError, OSError, ingest.IngestError):
        return now.isoformat()


def _severity(rec: dict) -> str:
    text = str(rec.get("severityText") or "").strip().lower()
    if text:
        return normalise_level(text)
    raw = rec.get("severityNumber")
    if isinstance(raw, str) and (m := re.match(r"SEVERITY_NUMBER_([A-Z]+)(\d?)$", raw)):   # protobuf -> JSON gives enum names
        n = {"TRACE": 1, "DEBUG": 5, "INFO": 9, "WARN": 13, "ERROR": 17, "FATAL": 21}.get(m.group(1), 9) + (int(m.group(2) or 1) - 1)
    else:
        try:
            n = int(raw or 9)
        except (TypeError, ValueError):
            n = 9
    return "debug" if n < 9 else "info" if n < 13 else "warn" if n < 17 else "error" if n < 21 else "fatal"


def _track_version(conn, service: str, res_attrs: dict) -> None:
    version = res_attrs.get("service.version")
    if not version:
        return
    version, key = str(version)[:80], f"otlp_version:{service}"
    seen = store.get(conn, key)
    if seen is None:
        store.put(conn, key, version)            # baseline only
    elif seen != version:
        store.put(conn, key, version)
        ingest.ingest_deploy(conn, service, {"version": version, "author": "telemetry",
                                             "summary": "detected: service.version changed in telemetry"})


def _register(conn, service: str, res_attrs: dict) -> None:
    deps = [d.strip() for d in str(res_attrs.get("pagerlens.depends_on") or "").split(",") if d.strip()]
    ingest.upsert_service(conn, service, depends_on=deps if "pagerlens.depends_on" in res_attrs else None)
    _track_version(conn, service, res_attrs)


def store_logs(conn, data: dict) -> tuple[int, int]:
    now, accepted, rejected = datetime.now(UTC), 0, 0
    for rl in data.get("resourceLogs") or []:
        res = _attrs((rl.get("resource") or {}).get("attributes"))
        service = _service_name(res)
        records = [r for sl in rl.get("scopeLogs") or [] for r in sl.get("logRecords") or []]
        if not service:
            rejected += len(records)
            continue
        _register(conn, service, res)
        events = []
        for r in records:
            body = _any(r.get("body") or {})
            msg = body if isinstance(body, str) else json.dumps(body, default=str)
            fields = _attrs(r.get("attributes"))
            if r.get("traceId"):
                fields["trace_id"] = r["traceId"]
            events.append({"ts": _ts(r.get("timeUnixNano") or r.get("observedTimeUnixNano"), now),
                           "level": _severity(r), "message": msg, "fields": fields})
        for i in range(0, len(events), ingest.MAX_BATCH):
            accepted += ingest.ingest_logs(conn, service, events[i:i + ingest.MAX_BATCH])
    return accepted, rejected


def _name(raw: str) -> str | None:
    n = re.sub(r"[^a-z0-9_]+", "_", str(raw).lower()).strip("_")[:48]
    n = n if not n[:1].isdigit() else "m_" + n
    return n if ingest.METRIC_NAME.match(n or "0") else None


def _value(dp: dict) -> float | None:
    for k in ("asDouble", "asInt"):
        if k in dp:
            try:
                v = float(dp[k])
                return v if math.isfinite(v) else None
            except (TypeError, ValueError):
                return None
    return None


def _remember(key: tuple, value: tuple) -> tuple | None:
    if len(_prev) > _STATE_LIMIT:
        _prev.clear()
    old, _prev[key] = _prev.get(key), value
    return old


def _p95(bounds: list[float], counts: list[float]) -> float | None:
    total = sum(counts)
    if total <= 0 or len(counts) != len(bounds) + 1:
        return None
    target, acc = 0.95 * total, 0.0
    for i, c in enumerate(counts):
        if acc + c >= target and c > 0:
            lo = bounds[i - 1] if i > 0 else 0.0
            hi = bounds[i] if i < len(bounds) else (bounds[-1] if bounds else 0.0)
            return lo + (hi - lo) * ((target - acc) / c)
        acc += c
    return bounds[-1] if bounds else None


def store_metrics(conn, data: dict) -> tuple[int, int]:
    now, accepted, rejected = datetime.now(UTC), 0, 0
    for rm in data.get("resourceMetrics") or []:
        res = _attrs((rm.get("resource") or {}).get("attributes"))
        service = _service_name(res)
        metrics = [m for sm in rm.get("scopeMetrics") or [] for m in sm.get("metrics") or []]
        if not service:
            rejected += len(metrics)
            continue
        _register(conn, service, res)
        points: list[dict] = []
        for m in metrics:
            name = _name(m.get("name", ""))
            if not name:
                rejected += 1
                continue
            if "gauge" in m:
                for dp in m["gauge"].get("dataPoints") or []:
                    if (v := _value(dp)) is not None:
                        points.append({"name": name, "value": v, "ts": _ts(dp.get("timeUnixNano"), now)})
            elif "sum" in m:
                s = m["sum"]
                cumulative = str(s.get("aggregationTemporality", "")).endswith("CUMULATIVE") or s.get("aggregationTemporality") == 2
                for dp in s.get("dataPoints") or []:
                    v, end = _value(dp), int(dp.get("timeUnixNano") or 0)
                    if v is None:
                        continue
                    if s.get("isMonotonic") and cumulative:     # counter -> per-second rate
                        old = _remember((service, name, json.dumps(dp.get("attributes"), sort_keys=True)), (v, end))
                        if old and end > old[1] and v >= old[0]:
                            points.append({"name": name + "_rate", "value": (v - old[0]) / ((end - old[1]) / 1e9), "ts": _ts(end, now)})
                    else:
                        points.append({"name": name, "value": v, "ts": _ts(end, now)})
            elif "histogram" in m:
                h = m["histogram"]
                cumulative = str(h.get("aggregationTemporality", "")).endswith("CUMULATIVE") or h.get("aggregationTemporality") == 2
                for dp in h.get("dataPoints") or []:
                    bounds = [float(b) for b in dp.get("explicitBounds") or []]
                    counts = [float(c) for c in dp.get("bucketCounts") or []]
                    if cumulative:
                        old = _remember((service, name, json.dumps(dp.get("attributes"), sort_keys=True), "h"), (counts, 0))
                        if not old or len(old[0]) != len(counts):
                            continue
                        counts = [max(0.0, c - o) for c, o in zip(counts, old[0], strict=True)]
                    if (q := _p95(bounds, counts)) is not None:
                        points.append({"name": name + "_p95", "value": q, "ts": _ts(dp.get("timeUnixNano"), now)})
            else:
                rejected += 1
        for i in range(0, len(points), ingest.MAX_BATCH):
            accepted += ingest.ingest_metrics(conn, service, points[i:i + ingest.MAX_BATCH])
    return accepted, rejected


def ack(kind: str, rejected: int, message: str, protobuf: bool) -> tuple[bytes, str]:
    """The OTLP response: empty on success, or a partialSuccess describing what was not stored."""
    cls = {"logs": ExportLogsServiceResponse, "metrics": ExportMetricsServiceResponse, "traces": ExportTraceServiceResponse}[kind]
    field = {"logs": "rejected_log_records", "metrics": "rejected_data_points", "traces": "rejected_spans"}[kind]
    msg = cls()
    if rejected:
        getattr(msg.partial_success, field)
        setattr(msg.partial_success, field, rejected)
        msg.partial_success.error_message = message[:200]
    if protobuf:
        return msg.SerializeToString(), "application/x-protobuf"
    return json.dumps(MessageToDict(msg)).encode(), "application/json"


REQUESTS = {"logs": ExportLogsServiceRequest, "metrics": ExportMetricsServiceRequest, "traces": ExportTraceServiceRequest}
