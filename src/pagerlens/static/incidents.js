import { api } from "/kit/api.js";
import { LABELS, lineChart } from "/static/charts.js";
import { renderMarkdown } from "/static/markdown.js";
import { can } from "/kit/session.js";
import { watch } from "/static/live.js";
import { flush } from "/static/regions.js";
import { $, field, fill, h, scrollRegion, setBusy, toast } from "/kit/ui.js";

const CATEGORY_NAMES = {
  bad_deploy: "Bad deploy", db_saturation: "Database saturation", resource_exhaustion: "Resource exhaustion",
  dependency_outage: "Dependency outage", traffic_spike: "Traffic spike", expired_certificate: "Expired certificate",
  service_down: "Service down", sandbox_paused: "Sandbox paused", database_unreachable: "Database unreachable",
  ingest_overload: "Ingest overload", sensor_fleet_outage: "Sensor fleet outage", data_quality: "Bad sensor data", slow_query: "Slow query",
};
const when = (s) => (s ? new Date(s).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "");
const SOURCE_NAMES = { rules: "rules", llm: "AI", both: "rules + AI" };
const sevClass = (s) => `badge sev ${s}`;

let pendingAccount = null;
let watcher = null;
let investigating = false;     // an investigation request is in flight: its own reload comes when it ends, so live events wait

export function stopIncidents() { if (watcher) watcher.stop(); watcher = null; }

// Live: the server tells us (tcn -> server-sent events) when an incident or alert changed; we then re-read what is on screen. Without
// events the same call runs on a timer. A soft reload keeps what is being typed (see grabDrafts).
function startWatching(box, id) {
  stopIncidents();
  watcher = watch(() => {
    if (investigating || !location.hash.startsWith("#incidents")) return;
    if (id) renderDetail(box, id, true); else if (list.shell) loadList();
  });
}

export async function initIncidents(id) {
  const box = $("view-incidents");
  startWatching(box, id);
  if (id) return renderDetail(box, id);
  return renderList(box);
}

// A reload of the detail page (after an investigation that took a minute, after a note or a resolution) must not
// throw away what the person has meanwhile typed into the page: the note, the real cause, the method they picked.
// It is read from the live page just before the new one replaces it, and put back with the focus and the caret.
const DRAFTS = ["note-body", "rc-note", "rc-cat", "use-memory", "inv-mode", "inv-account"];
let chartPick = { id: null, name: null };

function grabDrafts(box) {
  const out = {};
  for (const key of DRAFTS) {
    const el = box.querySelector("#" + key);
    if (el) out[key] = { value: el.value, checked: el.checked, focused: document.activeElement === el, from: el.selectionStart, to: el.selectionEnd };
  }
  return out;
}

function putDrafts(box, drafts) {
  for (const [key, d] of Object.entries(drafts)) {
    const el = box.querySelector("#" + key);
    if (!el) continue;
    if (key === "use-memory") el.checked = d.checked; else if (key !== "inv-account") el.value = d.value;   // the account options arrive later
    if (d.focused) { el.focus(); if (d.from != null && el.setSelectionRange) try { el.setSelectionRange(d.from, d.to); } catch { /* not a text field */ } }
  }
}

// The list is a shell (filters and the bulk-resolve form) plus a results area. Loading a filter redraws only the results, so
// the reason being typed and the filter fields are never wiped.
const list = { status: "", service: "", picked: new Set(), rows: [], total: 0, shell: null };

async function renderList(box) {
  if (!list.shell || list.shell.box !== box || box.children[0] !== list.shell.root) list.shell = buildListShell(box);
  await loadList();
}

function buildListShell(box) {
  const results = h("div", {});
  const status = h("select", { id: "inc-status", "aria-label": "Status", onchange: (e) => { list.status = e.target.value; list.picked.clear(); loadList(); } },
    ...[["", "All statuses"], ["open", "Open"], ["investigating", "Investigating"], ["resolved", "Resolved"]].map(([v, t]) => h("option", { value: v }, t)));
  status.value = list.status;
  const service = h("input", { id: "inc-service", type: "search", placeholder: "Service name…", value: list.service, "aria-label": "Service",
    onchange: (e) => { list.service = e.target.value.trim(); list.picked.clear(); loadList(); } });
  const reason = h("input", { id: "bulk-reason", maxlength: "500", placeholder: "e.g. alert storm after the city was removed", "aria-label": "Reason" });
  const confirmBox = h("input", { id: "bulk-confirm", type: "checkbox" });
  const err = h("p", { class: "error", role: "alert" });
  const bulk = async (body, label) => {
    err.textContent = "";
    if (!reason.value.trim()) { err.textContent = "Write the reason first."; return; }
    if (!confirmBox.checked) { err.textContent = "Tick the confirmation: these incidents will be closed."; return; }
    try {
      const r = await api("/api/incidents/bulk-resolve", { method: "POST", json: { ...body, reason: reason.value.trim(), confirm: true } });
      toast(`${r.resolved} incident${r.resolved === 1 ? "" : "s"} resolved (${label})`);
      reason.value = ""; confirmBox.checked = false; list.picked.clear();
      loadList();
    } catch (ex) { err.textContent = ex.message; }
  };
  const selected = h("button", { class: "secondary", type: "button", id: "bulk-selected", onclick: () => bulk({ ids: [...list.picked] }, "selected") }, "Resolve selected");
  const matching = h("button", { class: "danger", type: "button", id: "bulk-matching", onclick: () => bulk({ all_matching: true, status: list.status === "open" || list.status === "investigating" ? list.status : null, service: list.service || null }, "all matching") }, "Resolve all matching");
  const panel = can("incidents:write") ? h("details", { class: "card help bulk", id: "bulk-details" }, h("summary", {}, "Resolve many incidents"),
    h("p", { class: "muted" }, "Closes the selected incidents, or every unresolved incident that matches the filters above, with your reason. A bulk resolution is recorded as a note on each incident and teaches the memory nothing."),
    field("Reason", reason),
    h("label", { class: "check inline", for: "bulk-confirm" }, confirmBox, " I understand these incidents will be closed"),
    h("div", { class: "btns" }, selected, matching), err) : null;
  const root = h("div", {},
    h("div", { class: "row" }, h("h1", {}, "Incidents"), h("a", { class: "button-link", href: "#lab" }, "Break something in the Lab")),
    h("div", { class: "toolbar" }, status, service), panel, results);
  fill(box, root);
  return { box, root, results, matching, selected };
}

async function loadList() {
  const { results, matching, selected } = list.shell;
  const q = new URLSearchParams({ ...(list.status ? { status: list.status } : {}), ...(list.service ? { service: list.service } : {}) });
  let data;
  try { data = await api(`/api/incidents${q.toString() ? "?" + q : ""}`); } catch (err) { fill(results, h("p", { class: "error" }, err.message)); return; }
  list.rows = data.incidents; list.total = data.total ?? data.incidents.length;
  const unresolved = list.status === "resolved" ? 0 : list.total;
  matching.textContent = `Resolve all matching${list.status === "resolved" ? "" : ` (up to ${unresolved})`}`;
  matching.disabled = list.status === "resolved";
  const syncPicked = () => { selected.textContent = `Resolve selected (${list.picked.size})`; selected.disabled = !list.picked.size; };
  syncPicked();
  const rows = list.rows;
  const cause = (r) => (r.root_cause_category ? `Resolved: ${CATEGORY_NAMES[r.root_cause_category] || r.root_cause_category}`
    : r.status === "resolved" && r.root_cause_note ? `Resolved: ${r.root_cause_note}` : (r.top_hypothesis || h("span", { class: "muted" }, "not investigated")));
  fill(results,
    rows.length ? flush("Incidents", h("table", {},
      h("thead", {}, h("tr", {}, ...[["", "Select"], ["", "Severity"], ["Incident"], ["Service"], ["Status"], ["Likely cause"], ["Detected"]].map(([t, name]) => h("th", {}, name ? h("span", { class: "sr" }, name) : t)))),
      h("tbody", {}, ...rows.map((r) => h("tr", { class: "clickable", tabindex: "0", onclick: () => { location.hash = `#incidents/${r.id}`; },
        onkeydown: (e) => { if (e.key === "Enter") location.hash = `#incidents/${r.id}`; } },
        h("td", { class: "pick", onclick: (e) => e.stopPropagation() }, r.status === "resolved" ? null : h("input", { type: "checkbox", "aria-label": `Select incident ${r.id}`, checked: list.picked.has(r.id),
          onchange: (e) => { if (e.target.checked) list.picked.add(r.id); else list.picked.delete(r.id); syncPicked(); } })),
        h("td", {}, h("span", { class: sevClass(r.severity) }, r.severity)),
        h("td", { class: "title" }, h("a", { href: `#incidents/${r.id}` }, r.title)),
        h("td", {}, r.service),
        h("td", {}, h("span", { class: `badge status ${r.status}` }, r.status)),
        h("td", {}, cause(r)),
        h("td", {}, when(r.detected_at))))))) :
      h("div", { class: "card empty" }, h("p", {}, list.status || list.service ? "No incident matches these filters." : "No incidents yet."),
        h("p", { class: "muted" }, "Open the Lab to break the demo shop, or send an alert to the webhook (see Fleet)."),
        h("a", { class: "button-link", href: "#lab" }, "Go to the Lab")),
    list.total > rows.length ? h("p", { class: "hint" }, `Showing the latest ${rows.length} of ${list.total}.`) : null);
}

async function renderDetail(box, id, soft = false) {
  if (!soft) fill(box, h("p", { class: "loading" }, "Loading…"));   // a soft reload keeps the page (and what is typed in it) until the new one is ready
  let inc;
  try { inc = await api(`/api/incidents/${id}`); } catch (err) {
    if (soft) toast(err.message, true); else fill(box, h("a", { href: "#incidents" }, "← Incidents"), h("p", { class: "error" }, err.message));
    return;
  }
  const reload = () => renderDetail(box, id, true);
  const memory = h("input", { id: "use-memory", type: "checkbox", checked: true });
  const mode = h("select", { id: "inv-mode", "aria-label": "Method" },
    h("option", { value: "rules" }, "Rules (no AI, free)"),
    h("option", { value: "hybrid" }, "Rules + AI (recommended)"),
    h("option", { value: "llm" }, "AI only"));
  try { const saved = localStorage.getItem("pagerlens.mode"); if (["rules", "hybrid", "llm"].includes(saved)) mode.value = saved; } catch { /* storage unavailable */ }
  const acct = h("select", { id: "inv-account", "aria-label": "AI account", hidden: true });
  const acctNote = h("p", { class: "hint", hidden: true }, "");
  const syncMode = () => {
    const ai = mode.value !== "rules";
    acct.hidden = !ai;
    acctNote.hidden = !ai;
    acctNote.textContent = !ai ? "" : (acct.dataset.count === "0"
      ? "No chat account yet. Add one under Settings (the key is stored encrypted)."
      : "The AI uses read-only tools, cites evidence and is checked before it counts. It sends log excerpts to the provider and spends its credit.");
  };
  if (can("incidents:investigate")) {
    api("/api/chat-accounts").then((a) => {
      for (const x of a.accounts) acct.append(h("option", { value: String(x.id) }, `${x.name} · ${x.chat_model}`));
      acct.dataset.count = String(a.accounts.length);
      if (pendingAccount && a.accounts.some((x) => String(x.id) === pendingAccount)) acct.value = pendingAccount;
      pendingAccount = null;
    }).catch(() => {}).finally(() => syncMode());
  }
  mode.addEventListener("change", () => { syncMode(); try { localStorage.setItem("pagerlens.mode", mode.value); } catch { /* ignore */ } });
  const go = h("button", { class: "primary", type: "button", onclick: async () => {
    if (mode.value !== "rules" && !acct.value) { toast("Choose an AI account first (Settings > Add account).", true); return; }
    setBusy(go, true, mode.value === "rules" ? "Investigating…" : "Investigating (the AI takes 10-60 s)…");
    investigating = true;
    try {
      const r = await api(`/api/incidents/${id}/investigate`, { method: "POST", json: { mode: mode.value, use_memory: memory.checked, account: mode.value === "rules" ? null : acct.value } });
      const warn = r.runs[0] && r.runs[0].warning;
      toast(warn ? `Finished with a warning: ${warn}` : "Investigation finished", Boolean(warn));
      investigating = false;
      reload();
    } catch (err) { investigating = false; toast(err.message, true); setBusy(go, false); }
  } }, inc.runs.length ? "Investigate again" : "Investigate");

  const header = h("div", { class: "detail-head" },
    h("a", { href: "#incidents" }, "← Incidents"),
    h("div", { class: "row" }, h("h1", {}, inc.title),
      h("span", { class: "badges" }, h("span", { class: sevClass(inc.severity) }, inc.severity), h("span", { class: `badge status ${inc.status}` }, inc.status))),
    h("p", { class: "muted" }, `${inc.service} · detected ${when(inc.detected_at)} · ${inc.symptom}`),
    inc.status === "resolved" ? h("div", { class: "banner ok" }, (inc.root_cause_category ? `Resolved as ${CATEGORY_NAMES[inc.root_cause_category] || inc.root_cause_category}${inc.root_cause_note ? ": " + inc.root_cause_note : ""}. This incident is now memory for future investigations.` : `Resolved: ${inc.root_cause_note || "no reason recorded"}. It was closed without a confirmed cause, so it is not memory.`)) : null,
    can("incidents:investigate") ? h("div", { class: "btns wrap" }, h("label", { class: "sr", for: "inv-mode" }, "Method"), mode, acct, go,
      h("label", { class: "check inline", for: "use-memory" }, memory, " Use memory of resolved incidents")) : null,
    can("incidents:investigate") ? acctNote : null,
    inc.runs[0] && inc.runs[0].warning ? h("div", { class: "banner" }, `Last run: ${inc.runs[0].warning}`) : null);

  const sections = [header, hypothesesSection(inc), h("div", { id: "charts-host" }), reportSection(inc), runSection(inc), resolveSection(inc, reload), notesSection(inc, reload)];
  const drafts = soft ? grabDrafts(box) : {};
  fill(box, ...sections);
  putDrafts(box, drafts);
  if (drafts["inv-account"]) pendingAccount = drafts["inv-account"].value;
  loadCharts(id, inc.service);
}

function hypothesesSection(inc) {
  if (!inc.hypotheses.length) {
    return h("section", { class: "card" }, h("h2", {}, "Hypotheses"), h("p", { class: "muted" }, can("incidents:investigate") ? "Press Investigate: PagerLens will gather read-only evidence, rank the possible causes and write a report. Nothing in your systems is changed." : "No investigation has run yet. A responder or administrator can run one."));
  }
  const obsHost = h("div", { class: "obs-host" });
  const cards = inc.hypotheses.map((hy) => h("article", { class: "hyp" },
    h("div", { class: "row" },
      h("h3", {}, `${hy.rank}. ${hy.title}`),
      h("span", { class: "badges" }, h("span", { class: `badge src ${hy.source}` }, SOURCE_NAMES[hy.source] || hy.source),
        h("span", { class: "badge alt" }, CATEGORY_NAMES[hy.category] || hy.category), h("span", { class: "badge plain" }, `${Math.round(hy.score * 100)}%`))),
    hy.source === "both" || hy.rules_score != null && hy.llm_score != null ? h("p", { class: "hint" }, `Rules ${Math.round(hy.rules_score * 100)}% · AI ${Math.round(hy.llm_score * 100)}% (agreement adds confidence)`) : null,
    hy.source === "llm" && hy.grounded === false ? h("p", { class: "warn-text" }, "Ungrounded: the AI cited no evidence that exists, so this is heavily discounted.") : null,
    h("progress", { max: "1", value: String(hy.score), "aria-label": "confidence" }),
    h("ul", { class: "evidence" }, ...hy.evidence.map((e) => h("li", { class: e.stance },
      h("span", { class: `stance ${e.stance}` }, e.stance === "supports" ? "supports" : "refutes"), " ", e.note, " ",
      h("button", { class: "linklike", type: "button", onclick: () => showObservation(obsHost, e.observation_id) }, `evidence #${e.observation_id}`))))));
  return h("section", { class: "card" }, h("h2", {}, "Hypotheses"),
    h("p", { class: "muted" }, "Each hypothesis cites observations that support or refute it. Click an evidence link to see the raw data behind it."), ...cards, obsHost);
}

async function showObservation(host, id) {
  try {
    const o = await api(`/api/observations/${id}`);
    fill(host, h("div", { class: "obs" }, h("div", { class: "row" }, h("strong", {}, `Observation #${o.id}: ${o.source}`),
      h("button", { class: "ghost small", type: "button", onclick: () => fill(host) }, "Close")),
      h("p", { class: "muted" }, `${o.summary} · digest ${o.digest}`),
      h("p", { class: "hint" }, "Log text below is untrusted data collected from your services."),
      scrollRegion(h("pre", { class: "code" }, h("code", {}, JSON.stringify(o.payload, null, 2))), `Raw evidence of observation #${o.id}`)));
    host.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (err) { toast(err.message, true); }
}

function reportSection(inc) {
  if (!inc.report) return null;
  return h("section", { class: "card" }, h("div", { class: "row" }, h("h2", {}, "Report"),
    h("button", { class: "secondary small", type: "button", onclick: async () => { try { await navigator.clipboard.writeText(inc.report.markdown); toast("Report copied as Markdown"); } catch { toast("Copy failed", true); } } }, "Copy Markdown")),
    renderMarkdown(inc.report.markdown.replace(/^# .*\n+/, "")));
}

function runSection(inc) {
  if (!inc.runs.length) return null;
  const host = h("div", {});
  const load = async (runId) => {
    const run = await api(`/api/runs/${runId}`);
    fill(host, flush("Investigation steps", h("table", {},
      h("thead", {}, h("tr", {}, ...["#", "Step", "What it found", "Rows", "ms"].map((t) => h("th", {}, t)))),
      h("tbody", {}, ...run.steps.map((s) => h("tr", {}, h("td", {}, s.ord), h("td", {}, h("code", {}, s.tool || (s.kind === "llm" ? "AI turn" : s.kind)), s.args && s.args.service ? ` ${s.args.service}` : ""),
        h("td", {}, s.summary), h("td", { class: "num" }, s.row_count ?? ""), h("td", { class: "num" }, s.ms ?? "")))))));
  };
  const select = h("select", { "aria-label": "Run", onchange: (e) => load(e.target.value) },
    ...inc.runs.map((r) => h("option", { value: String(r.id) }, `Run #${r.id} · ${r.mode}${r.use_memory ? " + memory" : ""} · ${r.status} · ${when(r.started_at)}${r.usage && r.usage.tool_calls ? ` · ${r.usage.tool_calls} tool calls` : ""}${r.usage && r.usage.llm_calls ? ` · ${r.usage.llm_calls} AI calls, ${(r.usage.prompt_tokens || 0) + (r.usage.completion_tokens || 0)} tokens` : ""}`)));
  load(inc.runs[0].id).catch((err) => toast(err.message, true));
  return h("section", { class: "card" }, h("h2", {}, "Run viewer"),
    h("p", { class: "muted" }, "Every step the investigator took, in order. Tools are read-only and capped; a run has a fixed tool-call budget."), select, host);
}

function resolveSection(inc, reload) {
  if (inc.status === "resolved") {
    const truth = h("div", {});
    return h("section", { class: "card" }, h("h2", {}, "Learning check"),
      h("p", { class: "muted" }, "Simulated incidents have a known answer. Reveal it to see whether the investigation got it right."),
      h("button", { class: "secondary small", type: "button", onclick: async () => {
        const r = await api(`/api/incidents/${inc.id}/truth`);
        fill(truth, r.truth ? h("p", {}, `Simulated scenario: `, h("strong", {}, r.truth.scenario), ` (true cause: ${CATEGORY_NAMES[r.truth.category] || r.truth.category}). Top hypothesis was ${inc.hypotheses[0] ? CATEGORY_NAMES[inc.hypotheses[0].category] || inc.hypotheses[0].category : "none"}.`) : h("p", { class: "muted" }, "This is not a simulated incident, so there is no recorded answer."));
      } }, "Reveal simulated answer"), truth);
  }
  if (!can("incidents:write")) return h("section", { class: "card" }, h("h2", {}, "Close the loop"), h("p", { class: "muted" }, "Your role can read incidents but not resolve them."));
  const cat = h("select", { id: "rc-cat" }, ...Object.entries(CATEGORY_NAMES).map(([k, v]) => h("option", { value: k }, v)));
  const note = h("input", { id: "rc-note", maxlength: "1000", placeholder: "What actually happened? (optional)" });
  const top = inc.hypotheses[0];
  if (top && CATEGORY_NAMES[top.category]) cat.value = top.category;
  return h("section", { class: "card" }, h("h2", {}, "Close the loop"),
    h("p", { class: "muted" }, "Record the real cause. The resolved incident is embedded and recalled when similar incidents happen, so investigations improve."),
    h("div", { class: "grid-inline" },
      h("div", { class: "field" }, h("label", { for: "rc-cat" }, "Real cause"), cat),
      h("div", { class: "field" }, h("label", { for: "rc-note" }, "Note"), note),
      h("button", { class: "primary", type: "button", onclick: async () => {
        try { await api(`/api/incidents/${inc.id}/resolve`, { method: "POST", json: { category: cat.value, note: note.value || null } }); toast("Incident resolved and remembered"); reload(); }
        catch (err) { toast(err.message, true); }
      } }, "Mark resolved")));
}

function notesSection(inc, reload) {
  const box = h("textarea", { id: "note-body", rows: "2", maxlength: "4000", placeholder: "Add a note for the team…" });
  return h("section", { class: "card" }, h("h2", {}, "Notes"),
    ...inc.notes.map((n) => h("p", { class: "note" }, h("strong", {}, `${n.author} `), h("span", { class: "muted" }, when(n.created_at)), h("br"), n.body)),
    ...(can("incidents:write") ? [h("div", { class: "field" }, box),
      h("button", { class: "secondary", type: "button", onclick: async () => {
        if (!box.value.trim()) return;
        try { await api(`/api/incidents/${inc.id}/notes`, { method: "POST", json: { body: box.value } }); box.value = ""; reload(); } catch (err) { toast(err.message, true); }
      } }, "Add note")] : []));
}

async function loadCharts(id, service) {
  const host = $("charts-host");
  if (!host) return;
  let t;
  try { t = await api(`/api/incidents/${id}/telemetry`); } catch { return; }
  const names = Object.keys(t.services);
  const grid = h("div", { class: "charts" });
  const first = chartPick.id === id && names.includes(chartPick.name) ? chartPick.name : service;
  const select = h("select", { "aria-label": "Service", onchange: (e) => { chartPick = { id, name: e.target.value }; draw(e.target.value); } }, ...names.map((n) => h("option", { value: n }, n === service ? `${n} (alerting)` : `${n} (dependency)`)));
  select.value = first;
  function draw(name) {
    const s = t.services[name];
    fill(grid, ...Object.entries(s.metrics).map(([m, pts]) => h("figure", { class: "chartbox" }, h("figcaption", {}, LABELS[m] || m), lineChart(pts, { anchor: t.anchor, deploys: s.deploys, label: `${LABELS[m] || m} for ${name}` }))));
  }
  fill(host, h("section", { class: "card" }, h("div", { class: "row" }, h("h2", {}, "Telemetry"), select),
    h("p", { class: "muted" }, "Last 90 minutes. Dashed line: alert fired. Dotted lines: deploys."), grid));
  draw(first);
}
