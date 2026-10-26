import { api } from "/kit/api.js";
import { metricLabel, seriesChart } from "/static/charts.js";
import { $, fill, h } from "/kit/ui.js";
import { ago, dot } from "/static/dashboard.js";
import { can } from "/kit/session.js";
import { retirePanel } from "/static/retire.js";
import { flush } from "/static/regions.js";

const RANGES = [[15, "15 min"], [60, "1 hour"], [360, "6 hours"], [1440, "24 hours"]];
const STATUS_LABEL = { down: "Down", degraded: "Degraded", stale: "No data", unknown: "Unknown", healthy: "Healthy" };
const range = { minutes: 60, chosen: false };
let timer = null;

const when = (s) => (s ? new Date(s).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "");

// The page is a shell plus a content area. The 10 s refresh redraws only the content; the "Retire service" confirmation sits
// in the shell, so what is typed in it (and its focus, and whether it is open) is never touched.
let shell = null;

function ensureShell(box, name) {
  if (shell && shell.box === box && shell.name === name && box.children[0] === shell.root) return shell;
  const content = h("div", {});
  const retire = can("services:retire") ? h("details", { class: "card help", id: "retire-details" }, h("summary", {}, "Retire service"),
    retirePanel(name, { onDone: () => { location.hash = "#dashboard"; } })) : null;
  const root = h("div", {}, content, retire);
  fill(box, root);
  shell = { box, name, root, content };
  return shell;
}

function render(box, name, d) {
  const { content } = ensureShell(box, name);
  const to = Date.now(), from = to - d.minutes * 60000;
  const markers = [
    ...d.deploys.map((x) => ({ ts: x.deployed_at, kind: "deploy", title: `deploy ${x.version}${x.author ? ` by ${x.author}` : ""}` })),
    ...d.incidents.map((x) => ({ ts: x.detected_at, kind: "incident", title: `incident #${x.id}: ${x.title}` })),
  ];
  const picker = h("div", { class: "chips", role: "group", "aria-label": "Time range" }, ...RANGES.map(([m, t]) =>
    h("button", { type: "button", class: `chip ${range.minutes === m ? "active" : ""}`, onclick: () => { range.minutes = m; range.chosen = true; load(box, name); } }, t)));
  const charts = Object.entries(d.metrics).map(([key, m]) => {
    const { title, unit } = metricLabel(key);
    return h("figure", { class: "card chartbox" }, h("figcaption", {}, title, h("code", { class: "muted" }, ` ${key}`)),
      seriesChart(m.points, { label: `${title}, last ${d.minutes} minutes`, unit, from, to, markers, name: key }));
  });
  const neighbours = d.neighbours.length ? h("div", { class: "chips" }, ...d.neighbours.map((n) =>
    h("a", { class: `chip link ${n.status}`, href: `#service/${n.name}`, title: n.reasons.join(", ") || STATUS_LABEL[n.status] }, dot(n.status), ` ${n.relation} ${n.name}`))) : null;
  fill(content,
    h("a", { href: "#dashboard" }, "← all systems"),
    h("div", { class: `status-banner ${d.status === "stale" || d.status === "unknown" ? "degraded" : d.status}` },
      h("div", {}, h("h1", {}, dot(d.status), " ", d.name, h("span", { class: "state-word" }, ` ${STATUS_LABEL[d.status]}`), d.stale ? h("span", { class: "badge stale" }, "stale") : null),
        d.description ? h("p", { class: "muted" }, d.description) : null,
        d.reasons.length ? h("ul", {}, ...d.reasons.map((r) => h("li", {}, r))) : h("p", { class: "muted" }, "Every signal is within its normal range.")),
      h("dl", { class: "facts" }, h("dt", {}, "Tier"), h("dd", {}, d.tier || "–"), h("dt", {}, "Owner"), h("dd", {}, d.owner || "–"),
        h("dt", {}, "Errors in logs"), h("dd", {}, `${d.log_counts.errors} of ${d.log_counts.total} (last ${d.minutes} min)`))),
    neighbours,
    h("div", { class: "toolbar" }, h("h2", { class: "section-title" }, "Metrics"), picker),
    charts.length ? h("div", { class: "charts-wide" }, ...charts) : h("div", { class: "card" }, h("p", { class: "empty" }, "This service has not reported any metric yet.")),
    h("p", { class: "hint" }, "Dashed lines mark incidents (orange) and deploys (dotted). Hover a line for details."),
    h("h2", { class: "section-title" }, "Incidents"),
    d.incidents.length ? flush("Incidents of this service", h("table", {}, h("thead", {}, h("tr", {}, ...["#", "Incident", "Severity", "Status", "Detected", "Cause"].map((t) => h("th", {}, t)))),
      h("tbody", {}, ...d.incidents.map((i) => h("tr", { class: "clickable", onclick: () => { location.hash = `#incidents/${i.id}`; } },
        h("td", {}, i.id), h("td", { class: "title" }, i.title), h("td", {}, h("span", { class: `badge sev ${i.severity}` }, i.severity)),
        h("td", {}, h("span", { class: `badge status ${i.status}` }, i.status)), h("td", {}, when(i.detected_at)),
        h("td", { class: "muted" }, (i.root_cause_category || "").replace(/_/g, " "))))))) :
      h("div", { class: "card" }, h("p", { class: "empty" }, "No incidents for this service.")),
    h("div", { class: "panel-grid" },
      h("div", {}, h("h2", { class: "section-title" }, "Recent deploys"),
        d.deploys.length ? flush("Recent deploys", h("table", {}, h("tbody", {}, ...d.deploys.map((x) => h("tr", {},
          h("td", { class: "title" }, x.version), h("td", { class: "muted" }, x.summary || x.author || ""), h("td", {}, when(x.deployed_at))))))) :
          h("div", { class: "card" }, h("p", { class: "empty" }, "No deploys recorded."))),
      h("div", {}, h("h2", { class: "section-title" }, "Top errors and warnings"),
        d.signatures.length ? flush("Top errors and warnings", h("table", {}, h("tbody", {}, ...d.signatures.map((x) => h("tr", {},
          h("td", { class: "wrap-cell" }, h("code", {}, x.signature.slice(0, 110))), h("td", { class: "num" }, `${x.n}×`), h("td", { class: "muted" }, ago(x.last_seen))))))) :
          h("div", { class: "card" }, h("p", { class: "empty" }, "No warnings or errors in the recent logs.")))));
}

async function load(box, name) {
  try {
    let d = await api(`/api/services/${encodeURIComponent(name)}?minutes=${range.minutes}`);
    if (!range.chosen && d.data_since) {   // until the user picks one, show the smallest window that holds all the data
      const age = (Date.now() - new Date(d.data_since).getTime()) / 60000;
      const fit = (RANGES.find(([m]) => m >= age) || RANGES[RANGES.length - 1])[0];
      if (fit !== range.minutes) { range.minutes = fit; d = await api(`/api/services/${encodeURIComponent(name)}?minutes=${fit}`); }
    }
    render(box, name, d);
  } catch (err) {
    if (err.status === 404) fill(box, h("a", { href: "#dashboard" }, "← all systems"), h("div", { class: "card" }, h("p", { class: "empty" }, `No service called "${name}".`)));
    else if (!box.firstChild) fill(box, h("p", { class: "error" }, err.message));
  }
}

export async function initService(name) {
  const box = $("view-service");
  clearInterval(timer);
  range.chosen = false;
  if (!name) { location.hash = "#dashboard"; return; }
  await load(box, name);
  timer = setInterval(() => { if (document.hidden) return; if (location.hash === `#service/${name}`) load(box, name); else clearInterval(timer); }, 10000);
}
export function stopService() { clearInterval(timer); }
