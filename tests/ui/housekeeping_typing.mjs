// Regression: the dashboard and the service page refresh every 10 s. The "Retire service" confirmation (typed name, focus, caret,
// open panel) must survive, and so must what is typed in the two housekeeping settings and in the bulk-resolve reason.
// Run:  node tests/ui/housekeeping_typing.mjs        (no browser, no server: a tiny fake DOM and a stubbed fetch)
import { fail, find, findAll, findId, installDom } from "./fakedom.mjs";

const base = { status: "healthy", sparks: {}, latest: {}, reasons: [], depends_on: [], description: "", tier: "", open_incidents: 0, last_seen: null, stale: false };
const services = [
  { ...base, name: "checkout-api" },
  { ...base, name: "citypulse-fleet-default", status: "stale", stale: true, reasons: ["no data for 4320 min", "open incident: SensorFleetDegraded"], open_incidents: 1, worst_severity: "sev2", last_seen: "2026-01-01T00:00:00Z" },
];
const calls = [];
let refreshes = 0;
const dom = await installDom({ hash: "#dashboard", routes: async (p, init) => {
  calls.push([init.method || "GET", p, init.body]);
  if (p === "/api/dashboard") { refreshes++; return { summary: { services: 2, open_incidents: 1, healthy: 1, stale: 1, degraded: 0 }, services }; }
  if (p.startsWith("/api/services/") && p.endsWith("/retire")) return { retired: "x", metric_points: 60, log_events: 2, deploys: 1, incidents_resolved: [5], dependency_edges: 0 };
  if (p.startsWith("/api/services/")) return { name: "checkout-api", status: "healthy", stale: false, reasons: [], minutes: 60, data_since: null, metrics: {}, incidents: [], deploys: [], signatures: [], log_counts: { errors: 0, total: 0 }, neighbours: [], tier: "", owner: "" };
  if (p === "/api/settings/housekeeping") return { auto_resolve_minutes: 30, stale_after_minutes: 60, limits: { auto_resolve_minutes: [0, 1440], stale_after_minutes: [0, 43200] }, min_stale: 5 };
  if (p === "/api/accounts") return { accounts: [], env: null, vault: { initialized: true, unlocked: true } };
  if (p === "/api/providers" || p === "/api/tokens") return [];
  if (p === "/api/session") return { has_admin_password: true };
  if (p.startsWith("/api/incidents")) return { incidents: [{ id: 3, title: "HighErrorRate", severity: "sev2", status: "open", service: "checkout-api", detected_at: "2026-01-02T10:00:00Z", root_cause_category: null, root_cause_note: null, top_hypothesis: null }], total: 1 };
  return {};
} });
const click = (el) => el.listeners.click[0]({ preventDefault() {}, stopPropagation() {} });
const btn = (root, text) => find(root, (e) => e.tag === "button" && e.children.some((c) => c.data === text));

// ---- dashboard: the card of a stale service ------------------------------------------------------------------
const { initDashboard, stopDashboard } = await import("/static/dashboard.js");
await initDashboard();
const box = dom.el("view-dashboard");
const retireButtons = findAll(box, (e) => e.tag === "button" && e.children.some((c) => c.data === "Retire service"));
if (retireButtons.length !== 1) fail(`expected a Retire button on the stale card only, found ${retireButtons.length}`);
if (!findAll(box, (e) => e.className === "badge stale").length) fail("the stale card has no stale badge");
click(retireButtons[0]);
const typed = findId(box, "retire-confirm");
if (!typed) fail("the confirmation field did not open");
const go = find(box, (e) => e.tag === "button" && e.children.some((c) => c.data === "Retire service") && e.attrs?.type === "submit");
if (go.attrs.disabled === undefined) fail("the retire button is live before the name is typed");
typed.value = "citypulse-fl";
typed.setSelectionRange(4, 4);
typed.listeners.input[0]({ target: typed });
if (document.activeElement !== typed) fail("opening the confirmation did not focus it");
await dom.tick();                                     // the 10 s refresh fires
await dom.tick();
const after = findId(box, "retire-confirm");
if (after !== typed || after.value !== "citypulse-fl") fail("the dashboard refresh replaced the confirmation field or wiped the typed name");
if (document.activeElement !== typed || typed.selectionStart !== 4) fail("the dashboard refresh took the focus or caret from the confirmation");
if (refreshes < 3) fail("the refresh did not run, so this test proved nothing");
typed.value = "citypulse-fleet-default";
typed.listeners.input[0]({ target: typed });
if (go.disabled) fail("the retire button stayed disabled after the exact name was typed");
const form = findId(box, "retire-panel");
await form.listeners.submit[0]({ preventDefault() {} });
const post = calls.find((c) => c[0] === "POST" && c[1] === "/api/services/citypulse-fleet-default/retire");
if (!post || JSON.parse(post[2]).confirm !== "citypulse-fleet-default") fail("the retire request was not sent with the typed name");
stopDashboard();

// ---- the service page ----------------------------------------------------------------------------------------
location.hash = "#service/checkout-api";
const { initService } = await import("/static/service.js");
await initService("checkout-api");
const sbox = dom.el("view-service");
const details = findId(sbox, "retire-details");
if (!details) fail("the service page has no Retire service section");
details.attrs.open = "";
const st = findId(sbox, "retire-confirm");
st.focus(); st.value = "checkout"; st.setSelectionRange(3, 3);
st.listeners.input[0]({ target: st });
await dom.tick();
await dom.tick();
const st2 = findId(sbox, "retire-confirm");
if (st2 !== st || st2.value !== "checkout") fail("the service page refresh wiped the typed name");
if (document.activeElement !== st || st.selectionStart !== 3) fail("the service page refresh took the focus or caret");
if (findId(sbox, "retire-details") !== details || details.attrs.open !== "") fail("the service page refresh closed the retire section");

// ---- settings --------------------------------------------------------------------------------------------------
location.hash = "#settings";
const { initSettings } = await import("/static/settings.js");
await initSettings();
const hk = dom.el("settings-housekeeping");
const auto = findId(hk, "hk-auto");
auto.focus(); auto.value = "4"; auto.setSelectionRange(1, 1);
auto.listeners.input[0]({ target: auto });
await initSettings();                                 // Settings is redrawn after an account change
const auto2 = findId(hk, "hk-auto");
if (auto2 !== auto || auto2.value !== "4") fail("redrawing Settings wiped the number being typed");
if (document.activeElement !== auto || auto.selectionStart !== 1) fail("redrawing Settings took the focus from the number");
if (findId(hk, "hk-stale").value !== "60") fail("the untouched setting lost its value");

// ---- incidents list: bulk resolve ------------------------------------------------------------------------------
location.hash = "#incidents";
const { initIncidents } = await import("/static/incidents.js");
await initIncidents();
const ibox = dom.el("view-incidents");
const reason = findId(ibox, "bulk-reason");
if (!reason) fail("the bulk resolve form was not rendered");
reason.focus(); reason.value = "alert storm"; reason.setSelectionRange(5, 5);
const status = findId(ibox, "inc-status");
status.value = "open";
await status.listeners.change[0]({ target: status });  // changing the filter reloads the results
await dom.settle();
if (findId(ibox, "bulk-reason") !== reason || reason.value !== "alert storm") fail("changing the filter wiped the reason being typed");
if (document.activeElement !== reason || reason.selectionStart !== 5) fail("changing the filter took the focus from the reason");
await initIncidents();                                 // opening the page again (the same route) reloads the results only
if (findId(ibox, "bulk-reason") !== reason || reason.value !== "alert storm") fail("reloading the list wiped the reason being typed");
if (!calls.some((c) => c[1] === "/api/incidents?status=open")) fail("the filter was not sent to the server");
await click(findId(ibox, "bulk-matching"));            // without the confirmation tick it must refuse
if (calls.some((c) => c[1] === "/api/incidents/bulk-resolve")) fail("bulk resolve was sent without the confirmation");
findId(ibox, "bulk-confirm").checked = true;
await click(findId(ibox, "bulk-matching"));
const bulk = calls.find((c) => c[1] === "/api/incidents/bulk-resolve");
const sent = bulk && JSON.parse(bulk[2]);
if (!sent || sent.confirm !== true || sent.all_matching !== true || sent.status !== "open" || sent.reason !== "alert storm") fail("bulk resolve did not send the filter, the reason and the confirmation");
console.log("ok: the retire confirmation, the settings numbers and the bulk reason survive every refresh and redraw");
process.exit(0);
