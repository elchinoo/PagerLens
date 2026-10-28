// The Tuning tab (administrators): PagerLens proposes improvements to ITS OWN database from EDB's query advisor and from slow-query
// findings; a person approves or rejects; applying is off unless the server allows it. For monitored apps there is only advice.
import { api } from "/kit/api.js";
import { $, confirmDialog, errorState, fill, fmtDateTime, h, loading, promptDialog, scrollRegion, setBusy, toast } from "/kit/ui.js";

const FILTERS = [["", "All"], ["proposed", "Proposed"], ["approved", "Approved"], ["applied", "Applied"], ["rejected", "Rejected"], ["failed", "Failed"]];
const BADGE = { proposed: "warn", approved: "alt", applied: "ok", rejected: "plain", failed: "bad" };
const SOURCE = { advisor: "query advisor", tuner: "edb_pg_tuner", slow_query: "slow query" };
const view = { status: "" };

function beforeAfter(p) {
  const b = p.before_timing, a = p.after_timing;
  if (!b && !a) return null;
  const cell = (t) => (t && t.available ? `${Number(t.total_cost).toLocaleString(undefined, { maximumFractionDigits: 1 })}` : "not available");
  const plans = (t) => (t && t.available ? (t.scans || []).join("; ") || "no scan node" : (t && t.reason) || "");
  const faster = b && a && b.available && a.available && a.total_cost > 0 ? b.total_cost / a.total_cost : null;
  return h("div", { class: "compare" },
    h("h4", {}, "Before and after (EXPLAIN)"),
    h("table", {},
      h("caption", { class: "sr-only" }, "Estimated plan cost of the query that motivated this change, before and after"),
      h("thead", {}, h("tr", {}, h("th", { scope: "col" }, ""), h("th", { scope: "col", class: "num" }, "Estimated cost"), h("th", { scope: "col" }, "Plan"))),
      h("tbody", {},
        h("tr", {}, h("th", { scope: "row" }, "Before"), h("td", { class: "num" }, cell(b)), h("td", { class: "wrap-cell" }, plans(b))),
        h("tr", {}, h("th", { scope: "row" }, "After"), h("td", { class: "num" }, cell(a)), h("td", { class: "wrap-cell" }, plans(a))))),
    faster ? h("p", { class: "ok-line" }, `The estimated cost fell ${faster >= 10 ? Math.round(faster) : faster.toFixed(1)} times.`) : null,
    h("p", { class: "hint" }, "Estimated cost units from EXPLAIN (a generic plan, nothing is executed), not measured milliseconds. The query is the one that motivated the proposal" +
      (p.motivating_query ? ": " + p.motivating_query : ".")));
}

async function decide(p, decision, reload) {
  const verb = decision === "approve" ? "Approve" : "Reject";
  const note = await promptDialog(`${verb} this proposal. A note is optional; it is kept with your name in the history.`,
    { title: `${verb} proposal #${p.id}`, label: "Note (optional)", confirmLabel: verb, multiline: true });
  if (note === null) return;
  try { await api(`/api/tuning/${p.id}/decide`, { method: "POST", json: { decision, note: note.trim() || null } }); toast(decision === "approve" ? "Approved" : "Rejected"); }
  catch (err) { toast(err.message, true); }
  reload();
}

async function applyIt(p, btn, reload) {
  const ok = await confirmDialog(`PagerLens will run this on its OWN database, one statement, with a timeout:\n\n${p.statement}\n\nIt records an EXPLAIN before and after.`,
    { title: `Apply proposal #${p.id}`, confirmLabel: "Apply", danger: true });
  if (!ok) return;
  setBusy(btn, true, "Applying…");
  try {
    const r = await api(`/api/tuning/${p.id}/apply`, { method: "POST" });
    toast(r.status === "applied" ? "Applied" : "The change failed: " + (r.error || ""), r.status !== "applied");
  } catch (err) { toast(err.message, true); }
  reload();
}

function historyBlock(p) {
  const out = h("div", { class: "history" });
  let open = false;
  const btn = h("button", { class: "linklike", type: "button", "aria-expanded": "false", onclick: async () => {
    if (open) { open = false; btn.setAttribute("aria-expanded", "false"); fill(out); return; }
    try {
      const full = await api(`/api/tuning/${p.id}`);
      open = true;
      btn.setAttribute("aria-expanded", "true");
      fill(out, h("ul", { class: "evidence", "aria-label": `History of proposal ${p.id}` }, ...full.audit.map((a) =>
        h("li", {}, h("strong", {}, a.action), ` by ${a.actor}, ${fmtDateTime(a.at)}`, a.detail ? `: ${a.detail}` : ""))));
    } catch (err) { toast(err.message, true); }
  } }, "History");
  return h("div", {}, btn, out);
}

function card(p, applyEnabled, reload) {
  const advice = !p.applicable;
  const btns = [];
  if (p.status === "proposed") {
    btns.push(h("button", { class: "primary", type: "button", onclick: () => decide(p, "approve", reload) }, "Approve"),
      h("button", { class: "secondary", type: "button", onclick: () => decide(p, "reject", reload) }, "Reject"));
  }
  let applyHint = null;
  if (p.status === "approved" && !advice) {
    const b = h("button", { class: "danger", type: "button", disabled: !applyEnabled, onclick: () => applyIt(p, b, reload) }, "Apply to PagerLens' database");
    btns.push(b);
    if (!applyEnabled) applyHint = h("p", { class: "hint" }, "Applying is switched off on this server (PAGERLENS_ALLOW_TUNING_APPLY is not true). Approving records the decision only.");
  }
  const decided = p.decided_by ? h("p", { class: "hint" }, `${p.status === "rejected" ? "Rejected" : "Approved"} by ${p.decided_by}, ${fmtDateTime(p.decided_at)}` + (p.decision_note ? `: ${p.decision_note}` : "")) : null;
  return h("article", { class: "card acct", id: `proposal-${p.id}` },
    h("div", { class: "row" }, h("h3", { "aria-level": "2" }, `#${p.id} ${advice ? "Advice" : "Proposal"}`),
      h("div", { class: "badges" }, h("span", { class: `badge ${BADGE[p.status] || "plain"}` }, p.status), h("span", { class: "badge plain" }, SOURCE[p.source] || p.source),
        h("span", { class: "badge plain" }, p.target === "self" ? "this database" : p.target), advice ? h("span", { class: "badge warn" }, "advice only") : null)),
    scrollRegion(h("pre", { class: "code" }, h("code", {}, p.statement)), `Statement of proposal ${p.id}`),
    p.rationale ? h("p", {}, p.rationale) : null,
    p.estimated_benefit ? h("p", { class: "muted" }, "Expected benefit: " + p.estimated_benefit) : null,
    advice && p.target !== "self" ? h("p", { class: "hint" }, `PagerLens never changes a monitored system. This is for the people who run ${p.target}.`) : null,
    decided, p.error ? h("p", { class: "error", role: "alert" }, "The change failed: " + p.error) : null,
    p.applied_at ? h("p", { class: "hint" }, `Applied by ${p.applied_by}, ${fmtDateTime(p.applied_at)}`) : null,
    beforeAfter(p), applyHint,
    h("div", { class: "btns" }, ...btns), historyBlock(p));
}

export async function initTuning() {
  const box = $("view-tuning");
  loading(box);
  const reload = () => initTuning();
  let data;
  try { data = await api("/api/tuning" + (view.status ? `?status=${view.status}` : "")); } catch (err) { errorState(box, err.message, reload); return; }
  const scan = h("button", { class: "primary", type: "button", id: "tuning-scan", onclick: async () => {
    setBusy(scan, true, "Looking…");
    try {
      const r = await api("/api/tuning/scan", { method: "POST" });
      toast(r.created.length ? `${r.created.length} new proposal(s)` : "Nothing new to propose");
      (r.notes || []).forEach((n) => toast(n));
    } catch (err) { toast(err.message, true); }
    reload();
  } }, "Look for improvements");
  const chips = h("div", { class: "chips", role: "group", "aria-label": "Filter by status" }, ...FILTERS.map(([v, label]) =>
    h("button", { class: "chip" + (view.status === v ? " active" : ""), type: "button", "aria-pressed": view.status === v ? "true" : "false",
      onclick: () => { view.status = v; reload(); } }, label)));
  fill(box,
    h("h1", {}, "Tuning"),
    h("p", { class: "muted" }, "PagerLens proposes changes to its own database from EDB's query advisor and from slow-query findings. Nothing happens until a person approves it, and applying is a separate step."),
    h("div", { class: data.apply_enabled ? "banner" : "banner ok", role: "note" },
      data.apply_enabled
        ? `Applying is ON for this server: an approved CREATE INDEX or CREATE STATISTICS on a public table of PagerLens' own database can be run (one at a time, ${data.statement_timeout_seconds} s timeout). PagerLens never changes a monitored system: for those it only writes advice.`
        : "Applying is OFF (the default): approving records a decision and changes nothing. PagerLens never changes a monitored system: for those it only writes advice."),
    h("div", { class: "toolbar" }, chips, h("div", { class: "btns" }, scan)),
    data.proposals.length ? h("div", {}, ...data.proposals.map((p) => card(p, data.apply_enabled, reload)))
      : h("div", { class: "card empty" }, h("p", {}, "No proposals" + (view.status ? ` with status ${view.status}` : "") + ". Press Look for improvements; on a database without EDB's advisor there may be nothing to suggest.")));
}
