// Regression: the dashboard refreshes itself every 10 s. The "Filter services" box must keep what is typed, the focus and
// the caret, and the "Send your own telemetry" help must stay open.
// Run:  node tests/ui/dashboard_typing.mjs        (no browser, no server: a tiny fake DOM and a stubbed fetch)
import { fail, find, findId, installDom } from "./fakedom.mjs";

const service = { name: "checkout-api", status: "healthy", sparks: {}, latest: {}, reasons: [], depends_on: [], description: "", tier: "", open_incidents: 0, last_seen: null };
const dom = await installDom({ hash: "#dashboard", routes: async (p) => {
  if (p === "/api/dashboard") return { summary: { services: 1, open_incidents: 0, healthy: 1 }, services: [service] };
  return {};
} });
const { initDashboard } = await import("/static/dashboard.js");
await initDashboard();

const box = dom.el("view-dashboard");
const typed = findId(box, "svc-q");
if (!typed) fail("the filter box was not rendered");
typed.focus();
typed.value = "chec";
typed.setSelectionRange(2, 2);                        // the person types and the caret sits in the middle
typed.listeners.input[0]({ target: typed });
const input = findId(box, "svc-q");                   // whatever the typing itself left on the page
const help = find(box, (e) => e.tag === "details");
help.attrs.open = "";                                 // and opens the help
if (document.activeElement !== input || input.selectionStart !== 2) fail("typing itself lost the focus or caret");

await dom.tick();                                     // the 10 s refresh fires
await dom.tick();

const after = findId(box, "svc-q");
if (after !== input || after.value !== "chec") fail("the refresh replaced the filter box and lost what was typed");
if (document.activeElement !== after) fail("the refresh took the focus away from the filter box");
if (after.selectionStart !== 2) fail("the refresh moved the caret");
if (find(box, (e) => e.tag === "details") !== help || help.attrs.open !== "") fail("the refresh closed the help");
console.log("ok: the filter text, focus, caret and open help survive the refresh");
process.exit(0);
