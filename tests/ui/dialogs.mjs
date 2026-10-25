// Regression: destructive actions ask through the kit's confirmDialog (never a native confirm(), which freezes a browser test),
// a refresh timer cannot wipe an open dialog, and the dashboard shows loading, then data, or an error with a retry.
// Run:  node tests/ui/dialogs.mjs        (no browser, no server: a tiny fake DOM and a stubbed fetch)
import { fail, find, findAll, installDom } from "./fakedom.mjs";

const calls = [];
let dashboardFails = true, releaseDash;
const dashGate = new Promise((r) => { releaseDash = r; });
const dom = await installDom({ hash: "#lab", routes: async (p, init) => {
  calls.push([init.method || "GET", p]);
  if (p === "/api/simulator/scenarios") return { scenarios: [{ key: "bad-deploy", title: "Bad deploy", severity: "sev2", blurb: "b", service: "checkout-api" }] };
  if (p === "/api/simulator/trigger") return { incident_id: 5 };
  if (p === "/api/tokens") return [{ id: 9, name: "ci", prefix: "pl_ab", scope: "read", created_at: null, last_used_at: null, revoked_at: null }];
  if (p === "/api/settings/housekeeping") return { auto_resolve_minutes: 30, stale_after_minutes: 60, limits: { auto_resolve_minutes: [0, 1440], stale_after_minutes: [1, 1440] } };
  if (p === "/api/accounts") return { vault: { initialized: true, unlocked: true }, accounts: [{ id: 2, name: "Work", provider: "openai", base_url: "http://x", has_key: true, chat_model: "m", read_only: false }] };
  if (p === "/api/providers") return [{ id: "openai", name: "OpenAI", base_url: "http://x", chat_model: "m", note: "" }];
  if (p === "/api/session") return { has_admin_password: true };
  if (p === "/api/dashboard") {
    await dashGate;
    if (dashboardFails) throw new Error("boom");
    return { summary: { services: 0, open_incidents: 0 }, services: [] };
  }
  return {};
} });
const button = (root, label) => find(root, (e) => e.tag === "button" && (e.children || []).some((c) => c.data === label));
const overlay = () => find(document.body, (e) => e.className === "confirm-overlay");
const dlgButton = (label) => find(overlay(), (e) => e.tag === "button" && (e.children || []).some((c) => c.data === label));
const posted = (path) => calls.some(([m, p]) => m !== "GET" && p === path);

// Lab: "Break it" asks first; Cancel does nothing; a timer cannot wipe the dialog; Continue goes ahead.
const { initLab } = await import("/static/lab.js");
await initLab();
const lab = dom.el("view-lab");
const click = async (el) => { await el.listeners.click[0]({ target: el, preventDefault() {} }); await dom.settle(); };
click(button(lab, "Break it"));
await dom.settle();
if (!overlay()) fail("Break it did not open a confirmation dialog");
if (!find(overlay(), (e) => e.attrs?.role === "alertdialog")) fail("the confirmation is not an alertdialog");
if (posted("/api/simulator/trigger")) fail("the scenario ran before it was confirmed");
await dom.tick();
if (!overlay()) fail("a timer wiped the open dialog");
await click(dlgButton("Cancel"));
if (overlay() || posted("/api/simulator/trigger")) fail("Cancel closed wrongly or still ran the scenario");
click(button(lab, "Break it"));
await dom.settle();
await click(dlgButton("Continue"));
await dom.settle();
if (!posted("/api/simulator/trigger")) fail("Continue did not run the scenario");

// Settings: revoking a token asks first, in danger style.
const { initSettings } = await import("/static/settings.js");
await initSettings();
await dom.settle();
const revoke = button(dom.el("settings-security"), "Revoke");
if (!revoke) fail("no Revoke button was rendered");
click(revoke);
await dom.settle();
if (!overlay() || !dlgButton("Revoke") || dlgButton("Revoke").className !== "danger-solid") fail("Revoke did not open a danger confirmation");
if (posted("/api/tokens/9")) fail("the token was revoked before it was confirmed");
await click(dlgButton("Cancel"));
if (posted("/api/tokens/9")) fail("Cancel still revoked the token");
click(revoke);
await dom.settle();
await click(dlgButton("Revoke"));
if (!posted("/api/tokens/9")) fail("confirming did not revoke the token");

// Settings: deleting an account asks first.
const del = button(dom.el("settings-accounts"), "Delete");
if (!del) fail("no Delete button was rendered");
click(del);
await dom.settle();
if (!overlay() || posted("/api/accounts/2")) fail("Delete did not wait for a confirmation");
await click(dlgButton("Cancel"));
if (posted("/api/accounts/2")) fail("Cancel still deleted the account");

// Dashboard: loading while the first data is on its way, an error with a retry if it fails, then the page.
const { initDashboard, stopDashboard } = await import("/static/dashboard.js");
const start = initDashboard();
await dom.settle();
const box = dom.el("view-dashboard");
if (!find(box, (e) => e.className === "loading")) fail("the dashboard was blank while its first data loaded");
releaseDash();
await start;
if (!find(box, (e) => e.className === "error-state")) fail("a failed first load did not show an error state");
const retry = button(box, "Try again");
if (!retry) fail("the error state has no retry button");
dashboardFails = false;
await click(retry);
if (findAll(box, (e) => e.className === "error-state").length || !find(box, (e) => e.tag === "h1")) fail("retry did not render the dashboard");
stopDashboard();
console.log("ok");
process.exit(0);
