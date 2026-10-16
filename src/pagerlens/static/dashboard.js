import { api } from "/static/api.js";
import { metricLabel, sparkline } from "/static/charts.js";
import { $, fill, h } from "/static/ui.js";

const STATUS_LABEL = { down: "Down", degraded: "Degraded", stale: "No data", unknown: "Unknown", healthy: "Healthy" };
const ORDER = ["down", "degraded", "stale", "unknown", "healthy"];
const state = { data: null, filter: "all", q: "" };
let timer = null;

export const ago = (iso) => {
  if (!iso) return "never";
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  return s < 90 ? `${s}s ago` : s < 5400 ? `${Math.round(s / 60)} min ago` : s < 172800 ? `${Math.round(s / 3600)} h ago` : `${Math.round(s / 86400)} d ago`;
};
export const dot = (status) => h("span", { class: `dot ${status}`, role: "img", "aria-label": STATUS_LABEL[status] || status });
const num = (v) => (v == null ? "–" : Math.abs(v) >= 100 ? Math.round(v).toLocaleString() : String(Math.round(v * 10) / 10));

function card(s) {
  const sparks = Object.entries(s.sparks).map(([name, pts]) => {
    const { title, unit } = metricLabel(name);
    return h("div", { class: "spark" }, h("div", { class: "spark-head" }, h("span", { class: "muted" }, title), h("b", {}, `${num(s.latest[name])}${unit}`)), sparkline(pts, { name }));
  });
  return h("a", { class: `svc-card ${s.status}`, href: `#service/${s.name}` },
    h("div", { class: "row" }, h("h3", {}, dot(s.status), " ", s.name),
      h("span", { class: "badges" }, s.tier ? h("span", { class: "badge plain" }, s.tier) : null,
        s.open_incidents ? h("span", { class: `badge sev ${s.worst_severity || "sev3"}` }, `${s.open_incidents} open`) : null)),
    h("p", { class: `why ${s.status}` }, s.reasons.length ? s.reasons.join(" · ") : STATUS_LABEL[s.status]),
    sparks.length ? h("div", { class: "sparks" }, ...sparks) : h("p", { class: "muted small-text" }, s.description || "No metrics yet."),
    h("div", { class: "row foot" }, h("span", { class: "muted small-text" }, `last data ${ago(s.last_seen)}`),
      s.depends_on.length ? h("span", { class: "muted small-text" }, `depends on ${s.depends_on.join(", ")}`) : null));
}

function draw(box) {
  const { summary, services } = state.data;
  const chips = [["all", `All ${summary.services}`], ...ORDER.filter((k) => summary[k]).map((k) => [k, `${STATUS_LABEL[k]} ${summary[k]}`])].map(([k, t]) =>
    h("button", { type: "button", class: `chip ${state.filter === k ? "active" : ""} ${k}`, onclick: () => { state.filter = k; draw(box); } }, t));
  const q = h("input", { id: "svc-q", type: "search", placeholder: "Filter services…", value: state.q, "aria-label": "Filter services",
    oninput: (e) => { state.q = e.target.value; const pos = e.target.selectionStart; draw(box); const n = $("svc-q"); n.focus(); n.setSelectionRange(pos, pos); } });
  const shown = services.filter((s) => (state.filter === "all" || s.status === state.filter) && s.name.includes(state.q.trim().toLowerCase()));
  const worst = ORDER.find((k) => summary[k]) || "healthy";
  const headline = summary.down ? `${summary.down} down` : summary.degraded ? `${summary.degraded} degraded` : summary.services ? "All systems healthy" : "Nothing monitored yet";
  fill(box,
    h("div", { class: `status-banner ${worst === "stale" || worst === "unknown" ? "degraded" : worst}` },
      h("div", {}, h("h1", {}, dot(worst), " ", headline),
        h("p", { class: "muted" }, `${summary.services} monitored systems · ${summary.open_incidents} open incident${summary.open_incidents === 1 ? "" : "s"} · refreshes every 10 s`)),
      h("a", { class: "button-link", href: "#incidents" }, "All incidents")),
    h("div", { class: "toolbar" }, h("div", { class: "chips" }, ...chips), q),
    shown.length ? h("div", { class: "svc-grid" }, ...shown.map(card)) :
      h("div", { class: "card" }, h("p", { class: "empty" }, summary.services ? "No service matches this filter." : "No systems yet. Point pagerlens-agent at your services, push telemetry (Connect tab), or load the demo fleet in the Lab.")),
    h("details", { class: "card help" }, h("summary", {}, "Send your own telemetry"),
      h("p", { class: "muted" }, "Create an ingest-only token under Settings (it can push data but read nothing), then post to the API. Logs are scrubbed of emails, IPs, cards and secrets before they are stored."),
      h("pre", { class: "code" }, h("code", {}, `export PAGERLENS_TOKEN=<ingest token>

curl -X POST ${location.origin}/api/ingest/metrics \\
  -H "Authorization: Bearer $PAGERLENS_TOKEN" -H "Content-Type: application/json" \\
  -d '{"service":"checkout-api","points":[{"name":"error_rate","value":0.4},{"name":"up","value":1}]}'

curl -X POST ${location.origin}/api/ingest/alerts \\
  -H "Authorization: Bearer $PAGERLENS_TOKEN" -H "Content-Type: application/json" \\
  -d '{"service":"checkout-api","name":"HighErrorRate","summary":"5xx above 5%","severity":"sev2"}'`))));
}

async function load(box) {
  try { state.data = await api("/api/dashboard"); } catch (err) {
    if (!state.data) fill(box, h("p", { class: "error" }, err.message));
    return;
  }
  draw(box);
}

export async function initDashboard() {
  const box = $("view-dashboard");
  clearInterval(timer);
  await load(box);
  timer = setInterval(() => { if (document.hidden) return; if (!location.hash || location.hash === "#dashboard") load(box); else clearInterval(timer); }, 10000);
}
export function stopDashboard() { clearInterval(timer); }
