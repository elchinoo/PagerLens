// Tiny dependency-free SVG line charts. Presentation attributes only (the CSP forbids inline styles).
const NS = "http://www.w3.org/2000/svg";
const el = (tag, attrs = {}) => { const e = document.createElementNS(NS, tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); return e; };

export const LABELS = { error_rate: "Error rate (%)", latency_p95_ms: "p95 latency (ms)", request_rate: "Requests/s", cpu_pct: "CPU (%)", mem_pct: "Memory (%)", db_connections: "DB connections" };

export function lineChart(points, { anchor, deploys = [], label }) {
  const W = 320, H = 110, PAD = 6;
  const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img", "aria-label": label });
  if (!points.length) return svg;
  const xs = points.map(([t]) => new Date(t).getTime());
  const ys = points.map(([, v]) => v);
  const x0 = Math.min(...xs), x1 = Math.max(...xs), y1 = Math.max(...ys, 1e-9), y0 = Math.min(0, ...ys);
  const X = (t) => PAD + ((new Date(t).getTime() - x0) / Math.max(x1 - x0, 1)) * (W - 2 * PAD);
  const Y = (v) => H - PAD - ((v - y0) / Math.max(y1 - y0, 1e-9)) * (H - 2 * PAD);
  svg.append(el("line", { x1: PAD, x2: W - PAD, y1: Y(0), y2: Y(0), class: "axis" }));
  for (const d of deploys) svg.append(el("line", { x1: X(d.deployed_at), x2: X(d.deployed_at), y1: PAD, y2: H - PAD, class: "deploy" }));
  if (anchor) svg.append(el("line", { x1: X(anchor), x2: X(anchor), y1: PAD, y2: H - PAD, class: "alert" }));
  svg.append(el("polyline", { points: points.map(([t, v]) => `${X(t).toFixed(1)},${Y(v).toFixed(1)}`).join(" "), class: "series", fill: "none" }));
  const last = points[points.length - 1][1];
  const txt = el("text", { x: W - PAD, y: 12, class: "peak", "text-anchor": "end" });
  txt.textContent = `max ${Math.round(y1 * 10) / 10} · now ${Math.round(last * 10) / 10}`;
  svg.append(txt);
  return svg;
}

// ---- dashboard charts ---------------------------------------------------------------------------
export const METRIC_LABELS = {
  request_rate: ["Requests per second", ""], error_rate: ["Error rate", "%"], latency_p95_ms: ["p95 latency", " ms"], cpu_pct: ["CPU", "%"],
  mem_pct: ["Memory", "%"], db_connections: ["Database connections", ""], up: ["Health probe (1 = ok)", ""],
  sandbox_running: ["Sandbox running (1 = yes)", ""], db_up: ["Database reachable (1 = yes)", ""],
  fleet_health_pct: ["Fleet health", "%"], offline_pct: ["Sensors offline", "%"], stale_pct: ["Sensors stale", "%"],
  fault_pct: ["Sensors faulty", "%"], stuck_pct: ["Sensors stuck", "%"], worst_district_pct: ["Worst district health", "%"],
  ingest_rate: ["Readings ingested per second", ""], overloaded_pct: ["Batches refused (overloaded)", "%"], reject_pct: ["Readings rejected", "%"],
};

export function metricLabel(name) {
  const m = METRIC_LABELS[name];
  return m ? { title: m[0], unit: m[1] } : { title: name.replace(/_/g, " "), unit: "" };
}

const fmtNum = (v) => (v == null ? "–" : Math.abs(v) >= 100 ? Math.round(v).toLocaleString() : String(Math.round(v * 100) / 100));
const clock = (ms) => new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

// A fixed time window [from, to] (ms) so every chart on a page lines up, with optional deploy / incident markers.
export function seriesChart(points, { label, unit = "", from, to, markers = [], yMax, name = "" }) {
  const W = 420, H = 150, L = 8, R = 8, T = 22, B = 22;
  const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart series-chart", role: "img", "aria-label": label });
  const ts = points.map(([t]) => new Date(t).getTime());
  const ys = points.map(([, v]) => v);
  const X = (t) => L + ((t - from) / Math.max(to - from, 1)) * (W - L - R);
  const top = yMax ?? (name.endsWith("_pct") ? Math.max(100, ...ys) : Math.max(...ys, 1e-9) * 1.1);
  const lo = Math.min(0, ...ys);
  const Y = (v) => H - B - ((Math.min(v, top) - lo) / Math.max(top - lo, 1e-9)) * (H - T - B);
  svg.append(el("line", { x1: L, x2: W - L, y1: H - B, y2: H - B, class: "axis" }));
  for (const [t, text] of [[from, clock(from)], [to, clock(to)]]) {
    const x = el("text", { x: t === from ? L : W - R, y: H - 6, class: "peak", "text-anchor": t === from ? "start" : "end" });
    x.textContent = text;
    svg.append(x);
  }
  for (const m of markers) {
    const t = new Date(m.ts).getTime();
    if (t < from || t > to) continue;
    const line = el("line", { x1: X(t), x2: X(t), y1: T, y2: H - B, class: m.kind === "incident" ? "alert" : "deploy" });
    const title = el("title");
    title.textContent = m.title;
    line.append(title);
    svg.append(line);
  }
  if (points.length) {
    svg.append(el("polyline", { points: points.map(([t, v], i) => `${X(ts[i]).toFixed(1)},${Y(v).toFixed(1)}`).join(" "), class: "series", fill: "none" }));
    if (points.length === 1) svg.append(el("circle", { cx: X(ts[0]), cy: Y(ys[0]), r: 3, class: "dot-point" }));
    const t = el("text", { x: W - R, y: 13, class: "peak", "text-anchor": "end" });
    t.textContent = `now ${fmtNum(ys[ys.length - 1])}${unit} · min ${fmtNum(Math.min(...ys))} · max ${fmtNum(Math.max(...ys))}`;
    svg.append(t);
  } else {
    const t = el("text", { x: W / 2, y: H / 2, class: "peak", "text-anchor": "middle" });
    t.textContent = "no data in this window";
    svg.append(t);
  }
  return svg;
}

export function sparkline(points, { yMax, name = "" } = {}) {
  const W = 150, H = 34, P = 3;
  const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, class: "spark-mini", role: "img", "aria-label": "last hour" });
  if (points.length < 2) return svg;
  const xs = points.map(([t]) => new Date(t).getTime());
  const ys = points.map(([, v]) => v);
  const x0 = Math.min(...xs), x1 = Math.max(...xs);
  const top = yMax ?? (name.endsWith("_pct") ? Math.max(100, ...ys) : Math.max(...ys, 1e-9));
  const lo = Math.min(0, ...ys);
  const Y = (v) => H - P - ((v - lo) / Math.max(top - lo, 1e-9)) * (H - 2 * P);
  svg.append(el("polyline", { points: points.map(([, v], i) => `${(P + ((xs[i] - x0) / Math.max(x1 - x0, 1)) * (W - 2 * P)).toFixed(1)},${Y(v).toFixed(1)}`).join(" "), class: "series", fill: "none" }));
  return svg;
}
