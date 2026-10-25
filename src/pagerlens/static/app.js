import { api } from "/kit/api.js";
import { initConnect } from "/static/connect.js";
import { initDashboard, stopDashboard } from "/static/dashboard.js";
import { initIncidents } from "/static/incidents.js";
import { initLab } from "/static/lab.js";
import { initRunbooks } from "/static/runbooks.js";
import { initService, stopService } from "/static/service.js";
import { initSettings } from "/static/settings.js";
import { bootSession, can, refreshSession, renderLogin, renderSetup, renderVaultBanner, state } from "/kit/session.js";
import { $, h } from "/kit/ui.js";

const TABS = ["dashboard", "service", "incidents", "runbooks", "lab", "settings", "connect"];
const INIT = { dashboard: initDashboard, service: initService, incidents: initIncidents, lab: initLab, runbooks: initRunbooks, settings: initSettings, connect: initConnect };
const SECTIONS = ["auth-card", "vault-banner", "nav", "signout", ...TABS.map((t) => "view-" + t)];

function hideAll() { for (const id of SECTIONS) $(id).hidden = true; }

const UNAVAILABLE_HINT = "If this server runs on a platform that pauses idle apps, resume it first (for AgentPG: agentpg sandbox resume <sandbox-id>), then retry.";

async function boot(notice = "") {
  hideAll();
  // The card shows a loading state, then an error with "Try again", instead of staying blank while the session loads after sign-in.
  const card = $("auth-card");
  card.hidden = false;
  const onReady = (s) => {
    if (s.state === "setup_required") renderSetup(() => boot(), "PagerLens");
    else if (s.state === "logged_out") renderLogin(() => boot(), notice, "PagerLens");
    else showApp();
  };
  const s = await bootSession(card, { text: "Loading PagerLens\u2026", onReady });
  if (!s) card.append(h("p", { class: "hint" }, UNAVAILABLE_HINT));
}

// What each tab needs; the server enforces it, this only hides what a role would be refused.
const NEEDS = { dashboard: "dashboard:read", service: "dashboard:read", incidents: "incidents:read", runbooks: "runbooks:read", lab: "simulator:run", settings: "settings:manage", connect: "mcp:use" };

function showApp() {
  $("auth-card").hidden = true;
  for (const a of document.querySelectorAll("#nav a")) a.hidden = !can(NEEDS[a.dataset.tab]);
  $("nav").hidden = false;
  $("signout").hidden = false;
  renderVaultBanner();
  route();
}

function route() {
  if (!state.session || state.session.state !== "logged_in") return;
  const [rawName, arg] = location.hash.slice(1).split("/");
  const name = rawName === "fleet" ? "dashboard" : rawName;      // the old Fleet tab became the dashboard
  const allowed = TABS.filter((t) => can(NEEDS[t]));
  const tab = allowed.includes(name) ? name : (allowed[0] || "dashboard");
  if (tab !== "dashboard") stopDashboard();
  if (tab !== "service") stopService();
  for (const t of TABS) $("view-" + t).hidden = t !== tab;
  const navTab = tab === "service" ? "dashboard" : tab;           // a service page belongs to the Dashboard tab
  for (const a of document.querySelectorAll("#nav a")) a.classList.toggle("active", a.dataset.tab === navTab);
  INIT[tab](tab === "incidents" && /^\d+$/.test(arg || "") ? Number(arg) : tab === "service" ? decodeURIComponent(arg || "") : undefined);
}

$("signout").addEventListener("click", async () => {
  let out = {};
  try { out = await api("/api/logout", { method: "POST" }); } catch { /* the cookie is cleared server-side regardless */ }
  if (out.logout_url) { location.assign(out.logout_url); return; }   // also end the single sign-on session
  boot();
});

let lostTimer;
window.addEventListener("apg-auth-lost", () => {
  clearTimeout(lostTimer);
  lostTimer = setTimeout(() => boot("Your session ended. Please sign in again."), 50);
});
window.addEventListener("apg-vault-locked", async () => {
  try { await refreshSession(); renderVaultBanner(); } catch { /* ignore */ }
});
window.addEventListener("apg-unlocked", route);
window.addEventListener("hashchange", route);

boot();
