// Regression: "Investigate" can take a minute and then reloads the incident page. A note being written meanwhile,
// the real cause being filled in, and the method that was chosen must all still be there afterwards.
// Run:  node tests/ui/incident_typing.mjs        (no browser, no server: a tiny fake DOM and a stubbed fetch)
import { fail, find, findId, installDom } from "./fakedom.mjs";

const incident = { id: 7, title: "Checkout 5xx", severity: "sev2", status: "open", service: "checkout-api", detected_at: "2026-01-02T10:00:00Z", symptom: "errors",
  runs: [], hypotheses: [], notes: [], report: null, root_cause_category: null, root_cause_note: null };
let release;
const gate = new Promise((r) => { release = r; });
const dom = await installDom({ hash: "#incidents/7", routes: async (p) => {
  if (p === "/api/incidents/7") return incident;
  if (p === "/api/chat-accounts") return { accounts: [{ id: 3, name: "Work", chat_model: "m" }] };
  if (p === "/api/incidents/7/telemetry") return { anchor: 0, services: { "checkout-api": { metrics: {}, deploys: [] } } };
  if (p === "/api/incidents/7/investigate") { await gate; return { runs: [{}] }; }   // the long wait
  return {};
} });
const { initIncidents } = await import("/static/incidents.js");
await initIncidents(7);
await dom.settle();

const box = dom.el("view-incidents");
const go = find(box, (e) => e.tag === "button" && e.children.some((c) => c.data === "Investigate"));
if (!go) fail("the Investigate button was not rendered");
findId(box, "inv-mode").value = "hybrid";
findId(box, "use-memory").checked = false;
findId(box, "inv-account").value = "3";
const pending = go.listeners.click[0]();              // the investigation starts and takes its time

const note = findId(box, "note-body");
note.focus(); note.value = "rolled back at 10:12"; note.setSelectionRange(6, 6);
findId(box, "rc-note").value = "bad deploy";
release();                                            // the investigation ends and the page reloads
await pending;
await dom.settle();

const n = findId(box, "note-body");
if (!n || n.value !== "rolled back at 10:12") fail("the reload wiped the note being written");
if (document.activeElement !== n || n.selectionStart !== 6) fail("the reload took the focus or the caret away from the note");
const rc = findId(box, "rc-note");
if (!rc || rc.value !== "bad deploy") fail("the reload wiped the real cause note");
if (findId(box, "inv-mode").value !== "hybrid" || findId(box, "use-memory").checked !== false) fail("the reload reset the chosen method");
if (findId(box, "inv-account").value !== "3") fail("the reload reset the chosen AI account");
console.log("ok: the typed note, the focus and the chosen method survive the investigation reload");
process.exit(0);
