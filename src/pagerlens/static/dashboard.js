import { api } from "/kit/api.js";
import { metricLabel, sparkline } from "/static/charts.js";
import { can } from "/kit/session.js";
import { retirePanel } from "/static/retire.js";
import { $, errorState, fill, h, loading, scrollRegion } from "/kit/ui.js";

const STATUS_LABEL = { down: "Down", degraded: "Degraded", stale: "No data", unknown: "Unknown", healthy: "Healthy" };
const ORDER = ["down", "degraded", "stale", "unknown", "healthy"];
const state = { data: null, filter: "all", q: "", retiring: null };
let timer = null;

export const ago = (iso) => {
  if (!iso) return "never";
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  return s < 90 ? `${s}s ago` : s < 5400 ? `${Math.round(s / 60)} min ago` : s < 172800 ? `${Math.round(s / 3600)} h ago` : `${Math.round(s / 86400)} d ago`;
};
export const dot = (status) => h("span", { class: `dot ${status}`, role: "img", "aria-label": STATUS_LABEL[status] || status });
const num = (v) => (v == null ? "–" : Math.abs(v) >= 100 ? Math.round(v).toLocaleString() : String(Math.round(v * 10) / 10));

function card(s, shellRef) {
  const sparks = Object.entries(s.sparks).map(([name, pts]) => {
    const { title, unit } = metricLabel(name);
    return h("div", { class: "spark" }, h("div", { class: "spark-head" }, h("span", { class: "muted" }, title), h("b", {}, `${num(s.latest[name])}${unit}`)), sparkline(pts, { name }));
  });
  return h("a", { class: `svc-card ${s.status}`, href: `#service/${s.name}` },
    h("div", { class: "row" }, h("h3", { "aria-level": "2" }, dot(s.status), " ", s.name),
      h("span", { class: "badges" }, s.tier ? h("span", { class: "badge plain" }, s.tier) : null,
        s.stale ? h("span", { class: "badge stale", title: "no data for a long time" }, "stale") : null,
        s.open_incidents ? h("span", { class: `badge sev ${s.worst_severity || "sev3"}` }, `${s.open_incidents} open`) : null)),
    h("p", { class: `why ${s.status}` }, s.reasons.length ? s.reasons.join(" · ") : STATUS_LABEL[s.status]),
    sparks.length ? h("div", { class: "sparks" }, ...sparks) : h("p", { class: "muted small-text" }, s.description || "No metrics yet."),
    h("div", { class: "row foot" }, h("span", { class: "muted small-text" }, `last data ${ago(s.last_seen)}`),
      s.depends_on.length ? h("span", { class: "muted small-text" }, `depends on ${s.depends_on.join(", ")}`) : null),
    s.stale && can("services:retire") ? h("div", { class: "row foot" }, h("button", { class: "danger small", type: "button", onclick: (e) => {
      e.preventDefault(); e.stopPropagation(); openRetire(shellRef(), s.name);       // the card is a link: do not follow it
    } }, "Retire service")) : null);
}

// The confirmation lives in the shell, not in a card: the grid is redrawn every 10 s and would wipe the typed name.
function openRetire(s, name) {
  state.retiring = name;
  s.retire.replaceChildren(retirePanel(name, { onDone: () => { closeRetire(s); load(s.box); }, onCancel: () => closeRetire(s) }));
  const input = s.retire.querySelector("#retire-confirm");
  if (input) input.focus();
}
function closeRetire(s) { state.retiring = null; s.retire.replaceChildren(); }

// The page is built once: the filter box and the "send your own telemetry" help live in a shell that the 10 s refresh
// never touches (it would take the focus, the caret and the open <details> away). Only the banner, the chips and the
// grid are redrawn from the data.
let shell = null;

function buildShell(box) {
  const s = { box, banner: h("div", {}), retire: h("div", {}), chips: h("div", { class: "chips" }), grid: h("div", {}) };
  s.q = h("input", { id: "svc-q", type: "search", placeholder: "Filter services…", value: state.q, "aria-label": "Filter services",
    oninput: (e) => { state.q = e.target.value; drawData(s); } });
  s.root = h("div", {}, s.banner, s.retire, h("div", { class: "toolbar" }, s.chips, s.q), s.grid,
    h("details", { class: "card help" }, h("summary", {}, "Send your own telemetry"),
      h("p", { class: "muted" }, "Create an ingest-only token under Settings (it can push data but read nothing), then post to the API. Logs are scrubbed of emails, IPs, cards and secrets before they are stored."),
      scrollRegion(h("pre", { class: "code" }, h("code", {}, `export PAGERLENS_TOKEN=<ingest token>

curl -X POST ${location.origin}/api/ingest/metrics \\
  -H "Authorization: Bearer $PAGERLENS_TOKEN" -H "Content-Type: application/json" \\
  -d '{"service":"checkout-api","points":[{"name":"error_rate","value":0.4},{"name":"up","value":1}]}'

curl -X POST ${location.origin}/api/ingest/alerts \\
  -H "Authorization: Bearer $PAGERLENS_TOKEN" -H "Content-Type: application/json" \\
  -d '{"service":"checkout-api","name":"HighErrorRate","summary":"5xx above 5%","severity":"sev2"}'`)), "Example ingest commands")));
  fill(box, s.root);
  return s;
}

function drawData(s) {
  const { summary, services } = state.data;
  if (state.retiring && !services.some((x) => x.name === state.retiring)) closeRetire(s);      // it is gone (retired here or elsewhere)
  const chips = [["all", `All ${summary.services}`], ...ORDER.filter((k) => summary[k]).map((k) => [k, `${STATUS_LABEL[k]} ${summary[k]}`])].map(([k, t]) =>
    h("button", { type: "button", class: `chip ${state.filter === k ? "active" : ""} ${k}`, onclick: () => { state.filter = k; drawData(s); } }, t));
  const shown = services.filter((x) => (state.filter === "all" || x.status === state.filter) && x.name.includes(state.q.trim().toLowerCase()));
  const worst = ORDER.find((k) => summary[k]) || "healthy";
  const headline = summary.down ? `${summary.down} down` : summary.degraded ? `${summary.degraded} degraded` : summary.services ? "All systems healthy" : "Nothing monitored yet";
  fill(s.banner,
    h("div", { class: `status-banner ${worst === "stale" || worst === "unknown" ? "degraded" : worst}` },
      h("div", {}, h("h1", {}, dot(worst), " ", headline),
        h("p", { class: "muted" }, `${summary.services} monitored systems · ${summary.open_incidents} open incident${summary.open_incidents === 1 ? "" : "s"} · refreshes every 10 s`)),
      h("a", { class: "button-link", href: "#incidents" }, "All incidents")));
  fill(s.chips, ...chips);
  fill(s.grid, shown.length ? h("div", { class: "svc-grid" }, ...shown.map((x) => card(x, () => s))) :
    h("div", { class: "card" }, h("p", { class: "empty" }, summary.services ? "No service matches this filter." : "No systems yet. Point pagerlens-agent at your services, push telemetry (Connect tab), or load the demo fleet in the Lab.")));
}

function draw(box) {
  // Rebuild the shell only when the view was taken over (first visit, an error message, another page in the box).
  if (!shell || shell.box !== box || box.children[0] !== shell.root) shell = buildShell(box);
  else if (shell.q.value !== state.q) shell.q.value = state.q;
  drawData(shell);
}

async function load(box) {
  try { state.data = await api("/api/dashboard"); } catch (err) {
    if (!state.data) errorState(box, err.message, () => { loading(box); load(box); });
    return;
  }
  draw(box);
}

export async function initDashboard() {
  const box = $("view-dashboard");
  clearInterval(timer);
  if (!state.data) loading(box, "Loading services\u2026");
  await load(box);
  timer = setInterval(() => { if (document.hidden) return; if (!location.hash || location.hash === "#dashboard") load(box); else clearInterval(timer); }, 10000);
}
export function stopDashboard() { clearInterval(timer); }
