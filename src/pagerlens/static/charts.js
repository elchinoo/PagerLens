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
