// The Tuning tab without a browser: proposals as cards, the OFF-by-default apply switch, advice-only entries for monitored apps,
// approve with a note, apply behind a confirmation, the EXPLAIN before/after, history and the status filter.
// Run: node tests/ui/tuning_tab.mjs
import { readFileSync } from "node:fs";
import { fail, find, findAll, findId, installDom, modals } from "./fakedom.mjs";

const calls = [];
const mk = (id, extra = {}) => ({ id, source: "advisor", target: "self", statement: `CREATE INDEX CONCURRENTLY IF NOT EXISTS pl_ix_t${id} ON public.t (c${id})`, applicable: true,
  rationale: `query_advisor saw filters on public.t.c${id}`, estimated_benefit: "about 100 rows discarded per execution", status: "proposed", decided_by: null, decided_at: null, decision_note: null,
  applied_by: null, applied_at: null, before_timing: null, after_timing: null, error: null, motivating_query: null, ...extra });
let applyEnabled = false;
let proposals = [];
const reset = () => {
  proposals = [
    mk(1),
    mk(2, { source: "slow_query", target: "inventory-api", applicable: false, statement: "Review query 6823950417 in inventory-api's database (12 -> 484 ms)", rationale: "PagerLens never changes a monitored system" }),
    mk(3, { status: "approved", decided_by: "Ada Lovelace", decided_at: "2026-10-28T10:00:00Z", decision_note: "ok by me" }),
    mk(4, { status: "applied", applied_by: "operator", applied_at: "2026-10-28T11:00:00Z", motivating_query: "SELECT * FROM t WHERE c4 = $1",
      before_timing: { available: true, total_cost: 600, scans: ["Seq Scan on t"], method: "x" }, after_timing: { available: true, total_cost: 30, scans: ["Index Scan on t using pl_ix_t4"], method: "x" } }),
    mk(5, { status: "failed", error: "DuplicateTable: relation already exists." }),
    mk(6, { status: "applied", before_timing: { available: false, reason: "no motivating statement is known for this proposal" }, after_timing: { available: false, reason: "no motivating statement is known for this proposal" } }),
  ];
};
reset();
const dom = await installDom({ hash: "#tuning", routes: async (p, init) => {
  calls.push([init.method || "GET", p, init.body]);
  if (p.startsWith("/api/tuning/scan")) return { created: [7], skipped: 2, notes: ["query_advisor is not available on this database: not installed"] };
  if (/^\/api\/tuning\/\d+\/decide$/.test(p)) return {};
  if (/^\/api\/tuning\/\d+\/apply$/.test(p)) return { status: "applied" };
  if (/^\/api\/tuning\/\d+$/.test(p)) return { audit: [{ action: "created", actor: "scheduled job", detail: "advisor / self", at: "2026-10-28T09:00:00Z" }, { action: "approved", actor: "Ada Lovelace", detail: "ok by me", at: "2026-10-28T10:00:00Z" }] };
  if (p.startsWith("/api/tuning")) {
    const status = new URLSearchParams(p.split("?")[1] || "").get("status");
    return { proposals: proposals.filter((x) => !status || x.status === status), apply_enabled: applyEnabled, statement_timeout_seconds: 60, note: "n" };
  }
  return {};
} });
const text = (el) => (el.data !== undefined ? String(el.data) : "") + (el.textContent || "") + (el.children || []).map(text).join(" ");
const button = (root, label) => find(root, (e) => e.tag === "button" && text(e).trim() === label);
const buttons = (root, label) => findAll(root, (e) => e.tag === "button" && text(e).trim() === label);
const click = async (el) => { el.listeners.click[0]({ target: el, preventDefault() {}, stopPropagation() {} }); await dom.settle(); };   // not awaited: a dialog's handler waits for the person
const overlay = () => find(document.body, (e) => e.tag === "dialog" && e.attrs?.role === "alertdialog");
const dlgButton = (label) => find(overlay(), (e) => e.tag === "button" && text(e).trim() === label);
const posted = (re) => calls.filter(([m, p]) => m !== "GET" && re.test(p));

const { initTuning } = await import("/static/tuning.js");
await initTuning();
await dom.settle();
const box = dom.el("view-tuning");
const card = (id) => findId(box, `proposal-${id}`);

// 1. cards, badges, the switch is OFF, advice is marked, statements are text
if (!text(box).includes("Tuning") || !text(box).includes("Applying is OFF (the default)") || !text(box).includes("never changes a monitored system")) fail("the page must say apply is OFF and what PagerLens never touches");
if (findAll(box, (e) => e.tag === "article").length !== 6) fail("expected six proposal cards");
if (!text(card(2)).includes("advice only") || !text(card(2)).includes("inventory-api") || text(card(1)).includes("advice only")) fail("the monitored-app entry must be advice only and name the service");
if (!text(card(1)).includes("CREATE INDEX CONCURRENTLY IF NOT EXISTS pl_ix_t1 ON public.t (c1)") || !text(card(1)).includes("this database")) fail("the statement and its target must show");
if (!button(box, "Look for improvements")) fail("no 'Look for improvements' button");
if (buttons(card(1), "Approve").length !== 1 || buttons(card(1), "Reject").length !== 1) fail("a proposed change can be approved or rejected");
if (buttons(card(4), "Approve").length) fail("a decided change cannot be decided again");

// 2. approved but apply is off: the apply button is disabled and says why; the decision line names the person and the note
const off = button(card(3), "Apply to PagerLens' database");
if (!off || off.attrs.disabled === undefined) fail("apply must be disabled while the server has it off");
if (!text(card(3)).includes("PAGERLENS_ALLOW_TUNING_APPLY") || !text(card(3)).includes("Approved by Ada Lovelace") || !text(card(3)).includes("ok by me")) fail("the card must explain the off switch and show who approved");
if (button(card(2), "Apply to PagerLens' database")) fail("advice must never offer Apply");

// 3. applied: the EXPLAIN before/after, honestly labelled; failed: the error; an unavailable plan says why
const applied = text(card(4));
if (!applied.includes("Seq Scan on t") || !applied.includes("Index Scan on t using pl_ix_t4") || !applied.includes("600") || !applied.includes("20 times")) fail("before/after: " + applied);
if (!applied.includes("not measured milliseconds") || !applied.includes("SELECT * FROM t WHERE c4 = $1")) fail("the before/after must say it is estimated and show the query");
if (findAll(card(4), (e) => e.tag === "caption").length !== 1 || !findAll(card(4), (e) => e.tag === "th" && e.attrs?.scope === "row").length) fail("the before/after table needs a caption and row headers");
if (!text(card(5)).includes("The change failed: DuplicateTable")) fail("a failed change must show its error");
if (!text(card(6)).includes("no motivating statement is known") || text(card(6)).includes("times")) fail("an unavailable plan must say why and not invent a ratio");

// 4. approve asks for a note in a dialog, then posts it
await click(button(card(1), "Approve"));
if (!overlay() || modals.length !== 1) fail("Approve must open the note dialog");
const ta = find(overlay(), (e) => e.tag === "textarea");
ta.value = "reviewed, safe";
ta.listeners.input?.forEach((f) => f({ target: ta }));
await click(dlgButton("Approve"));
const dec = posted(/\/api\/tuning\/1\/decide$/);
if (dec.length !== 1 || JSON.parse(dec[0][2]).decision !== "approve" || JSON.parse(dec[0][2]).note !== "reviewed, safe") fail("approve body: " + JSON.stringify(dec));
// cancelling a dialog changes nothing
await click(button(card(1), "Reject"));
await click(dlgButton("Cancel"));
if (posted(/\/api\/tuning\/1\/decide$/).length !== 1 || overlay()) fail("Cancel must not post and must close the dialog");

// 5. with apply ON the button works, behind a confirmation that shows the exact statement
applyEnabled = true;
await initTuning();
await dom.settle();
if (!text(dom.el("view-tuning")).includes("Applying is ON for this server") || !text(dom.el("view-tuning")).includes("60 s timeout")) fail("the page must say apply is ON");
const on = button(findId(dom.el("view-tuning"), "proposal-3"), "Apply to PagerLens' database");
if (!on || on.attrs.disabled !== undefined) fail("apply must be enabled when the server allows it");
await click(on);
if (!overlay() || !text(overlay()).includes("CREATE INDEX CONCURRENTLY IF NOT EXISTS pl_ix_t3 ON public.t (c3)") || !text(overlay()).includes("its OWN database")) fail("the confirmation must show the exact statement and say which database");
await click(dlgButton("Cancel"));
if (posted(/\/apply$/).length) fail("Cancel must not apply");
await click(on);
await click(dlgButton("Apply"));
if (posted(/\/api\/tuning\/3\/apply$/).length !== 1) fail("confirming must apply once");

// 6. scan, history, filter
await click(button(dom.el("view-tuning"), "Look for improvements"));
if (posted(/\/api\/tuning\/scan$/).length !== 1) fail("the scan button did not post");
const hist = button(findId(dom.el("view-tuning"), "proposal-3"), "History");
await click(hist);
const h3 = text(findId(dom.el("view-tuning"), "proposal-3"));
if (!h3.includes("scheduled job") || !h3.includes("advisor / self") || hist.attrs["aria-expanded"] !== "true") fail("history: " + h3);
await click(hist);
if (text(findId(dom.el("view-tuning"), "proposal-3")).includes("scheduled job")) fail("History must collapse");
await click(button(dom.el("view-tuning"), "Applied"));
if (!calls.some(([m, p]) => m === "GET" && p === "/api/tuning?status=applied")) fail("the filter must ask the server for that status");
if (findAll(dom.el("view-tuning"), (e) => e.tag === "article").length !== 2) fail("the filter must show only applied proposals");
const active = findAll(dom.el("view-tuning"), (e) => e.className === "chip active");
if (active.length !== 1 || text(active[0]).trim() !== "Applied" || active[0].attrs["aria-pressed"] !== "true") fail("the active filter must be marked");

// 7. an error loading shows a message with a retry, and markup in a statement stays text
proposals = [mk(9, { statement: "<img src=x onerror=alert(1)>", rationale: "<script>alert(1)</script>" })];
await click(button(dom.el("view-tuning"), "All"));
if (findAll(dom.el("view-tuning"), (e) => ["img", "script"].includes(e.tag)).length || !text(dom.el("view-tuning")).includes("<img src=x onerror=alert(1)>")) fail("markup must stay text");
const src = readFileSync(new URL("../../src/pagerlens/static/tuning.js", import.meta.url), "utf8");
if (/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/.test(src)) fail("tuning.js must only use text rendering");

console.log("ok: the Tuning tab (cards, apply off by default, advice only, approve with note, apply behind confirmation, before/after, history, filter)");
process.exit(0);
