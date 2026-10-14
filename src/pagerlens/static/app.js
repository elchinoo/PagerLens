import { api } from "/static/api.js";
import { initConnect } from "/static/connect.js";
import { initFleet } from "/static/fleet.js";
import { initIncidents } from "/static/incidents.js";
import { initLab } from "/static/lab.js";
import { initRunbooks } from "/static/runbooks.js";
import { initSettings } from "/static/settings.js";
import { refreshSession, renderLogin, renderSetup, renderVaultBanner, state } from "/static/session.js";
import { $, h } from "/static/ui.js";

const TABS = ["incidents", "fleet", "lab", "runbooks", "settings", "connect"];
const INIT = { incidents: initIncidents, fleet: initFleet, lab: initLab, runbooks: initRunbooks, settings: initSettings, connect: initConnect };
const SECTIONS = ["auth-card", "vault-banner", "nav", "signout", ...TABS.map((t) => "view-" + t)];

function hideAll() { for (const id of SECTIONS) $(id).hidden = true; }

function showUnavailable(err) {
  hideAll();
  $("auth-card").replaceChildren(
    h("img", { class: "hero-logo", src: "/static/logo.svg", alt: "", width: "72", height: "72" }),
    h("h1", {}, "PagerLens can't be reached"),
    h("p", { class: "muted" }, err.message),
    h("p", { class: "hint" }, "If this server runs on a platform that pauses idle apps, resume it first (for AgentPG: agentpg sandbox resume <sandbox-id>), then retry."),
    h("button", { class: "primary", type: "button", onclick: () => boot() }, "Retry"));
  $("auth-card").hidden = false;
}

async function boot(notice = "") {
  hideAll();
  let s;
  try { s = await refreshSession(); } catch (err) { showUnavailable(err); return; }
  if (s.state === "setup_required") renderSetup(() => boot());
  else if (s.state === "logged_out") renderLogin(() => boot(), notice);
  else showApp();
}

function showApp() {
  $("auth-card").hidden = true;
  $("nav").hidden = false;
  $("signout").hidden = false;
  renderVaultBanner();
  route();
}

function route() {
  if (!state.session || state.session.state !== "logged_in") return;
  const [name, arg] = location.hash.slice(1).split("/");
  const tab = TABS.includes(name) ? name : "incidents";
  for (const t of TABS) $("view-" + t).hidden = t !== tab;
  for (const a of document.querySelectorAll("#nav a")) a.classList.toggle("active", a.dataset.tab === tab);
  INIT[tab](tab === "incidents" && /^\d+$/.test(arg || "") ? Number(arg) : undefined);
}

$("signout").addEventListener("click", async () => {
  try { await api("/api/logout", { method: "POST" }); } catch { /* the cookie is cleared server-side regardless */ }
  boot();
});

let lostTimer;
window.addEventListener("pl-auth-lost", () => {
  clearTimeout(lostTimer);
  lostTimer = setTimeout(() => boot("Your session ended. Please sign in again."), 50);
});
window.addEventListener("pl-vault-locked", async () => {
  try { await refreshSession(); renderVaultBanner(); } catch { /* ignore */ }
});
window.addEventListener("pl-unlocked", route);
window.addEventListener("hashchange", route);

boot();
