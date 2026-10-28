import { api } from "/kit/api.js";
import { flush } from "/static/regions.js";
import { $, confirmDialog, copy, field, fill, fmtDate, h, toast } from "/kit/ui.js";

export async function initSettings() {
  await Promise.all([renderAccounts(), renderSecurity(), renderHousekeeping()]);
}

// ---- stale and auto-resolve ---------------------------------------------------------------------
// Built once. Settings is redrawn after an account is saved or deleted; this card is not, so a number being typed is never
// wiped. A later visit only refreshes the fields that were not touched and do not have the focus.
async function renderHousekeeping() {
  const box = $("settings-housekeeping");
  let cur;
  try { cur = await api("/api/settings/housekeeping"); } catch (err) { if (!box.children.length) box.replaceChildren(h("p", { class: "error" }, err.message)); return; }
  const fields = box.hk;
  if (fields) {
    for (const [key, el] of Object.entries(fields)) if (!el.dirty && document.activeElement !== el) el.value = String(cur[key]);
    return;
  }
  const auto = h("input", { id: "hk-auto", type: "number", min: "0", max: String(cur.limits.auto_resolve_minutes[1]), step: "1", value: String(cur.auto_resolve_minutes) });
  const stale = h("input", { id: "hk-stale", type: "number", min: "0", max: String(cur.limits.stale_after_minutes[1]), step: "1", value: String(cur.stale_after_minutes) });
  for (const el of [auto, stale]) el.addEventListener("input", () => { el.dirty = true; });
  const err = h("p", { class: "error", role: "alert" });
  box.hk = { auto_resolve_minutes: auto, stale_after_minutes: stale };
  fill(box,
    h("h2", {}, "Stale services and recovered incidents"),
    h("p", { class: "muted" }, "Keeps the dashboard from looking like an alert storm. Both settings apply at once and need no restart."),
    h("form", { class: "card", onsubmit: async (e) => {
      e.preventDefault();
      err.textContent = "";
      try {
        const saved = await api("/api/settings/housekeeping", { method: "PUT", json: { auto_resolve_minutes: Number(auto.value), stale_after_minutes: Number(stale.value) } });
        auto.value = String(saved.auto_resolve_minutes); stale.value = String(saved.stale_after_minutes);
        auto.dirty = stale.dirty = false;
        toast("Settings saved");
      } catch (ex) { err.textContent = ex.message; }
    } },
    h("div", { class: "grid2" },
      field("Auto-resolve after (minutes)", auto, "An open incident nobody has touched is resolved when its alert has been quiet and the service healthy for this long. 0 turns it off."),
      field("Mark stale after (minutes)", stale, `A service with no data for this long gets a stale badge and leaves the degraded count. 0 turns it off, otherwise at least ${cur.min_stale}.`)),
    h("div", { class: "btns" }, h("button", { class: "primary", type: "submit" }, "Save")), err));
}

// ---- provider accounts --------------------------------------------------------------------------
async function renderAccounts() {
  const box = $("settings-accounts");
  let data, presets;
  try { [data, presets] = await Promise.all([api("/api/accounts"), api("/api/providers")]); } catch (err) { box.replaceChildren(h("p", { class: "error" }, err.message)); return; }
  const v = data.vault;
  const notice = !v.initialized
    ? h("div", { class: "banner" }, "To store provider API keys, first set an admin password under Security below. Keys are encrypted with a random data key that your password protects; the database alone reveals nothing.")
    : (!v.unlocked ? h("div", { class: "banner" }, "Provider keys are locked. Unlock them with your password (banner at the top) to test or use accounts.") : null);
  const formHost = h("div", {});
  const cards = [...data.accounts, ...(data.env ? [data.env] : [])].map((a) => accountCard(a, data, () => renderAll(), (acct) => showForm(acct)));

  function showForm(existing) {
    formHost.replaceChildren(accountForm(existing, presets, () => { formHost.replaceChildren(); renderAll(); }, () => formHost.replaceChildren()));
    formHost.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
  fill(box,
    h("div", { class: "row" }, h("h2", {}, "Provider accounts"), h("button", { class: "primary", type: "button", onclick: () => showForm(null) }, "Add account")),
    h("p", { class: "muted" }, "Add as many OpenAI-compatible accounts as you like (OpenAI, OpenRouter, GLM, Kimi, Claude and others). They power the AI and Rules + AI investigations (choose one per investigation); the rules investigator needs none."),
    notice, formHost,
    cards.length ? h("div", { class: "acct-grid" }, ...cards) : h("p", { class: "empty" }, "No accounts yet."));
}

function renderAll() { initSettings(); }

function accountCard(a, data, reload, edit) {
  const active = data.active_embedding === a.id || (data.active_embedding === "env" && a.id === "env");
  const result = h("p", { class: "test-result", role: "status" });
  const test = (target) => async (e) => {
    e.target.disabled = true;
    result.className = "test-result";
    result.textContent = `Testing ${target}…`;
    try {
      const r = await api(`/api/accounts/${a.id}/test`, { method: "POST", json: { target } });
      result.className = "test-result ok";
      result.textContent = target === "chat" ? `Chat works (${r.ms} ms). Reply: "${r.reply}"`
        : `Embeddings work (${r.ms} ms): ${r.dimensions} dimensions from ${r.model}.`;
    } catch (err) { result.className = "test-result bad"; result.textContent = err.message; } finally { e.target.disabled = false; }
  };
  return h("article", { class: "card acct" },
    h("div", { class: "row" }, h("h3", {}, a.name),
      h("span", { class: "badges" },
        active ? h("span", { class: "badge plain" }, "embeddings") : null,
        a.read_only ? h("span", { class: "badge plain" }, "server setting") : h("span", { class: "badge plain" }, a.provider))),
    h("dl", { class: "facts" },
      h("dt", {}, "Base URL"), h("dd", {}, a.base_url),
      h("dt", {}, "API key"), h("dd", {}, a.has_key ? (a.api_key_last4 ? `stored, ends in ${a.api_key_last4}` : "set by the server") : "none"),
      h("dt", {}, "Chat model"), h("dd", {}, a.chat_model || "not set"),
      h("dt", {}, "Embedding model"), h("dd", {}, a.embedding_model ? `${a.embedding_model} (${a.embedding_dim} dimensions)${active ? ", used by search and memory" : ""}` : "not set")),
    h("div", { class: "btns wrap" },
      a.chat_model ? h("button", { class: "secondary small", type: "button", onclick: test("chat") }, "Test chat") : null,
      a.embedding_model ? h("button", { class: "secondary small", type: "button", onclick: test("embeddings") }, "Test embeddings") : null,
      a.embedding_model && !active ? h("button", { class: "secondary small", type: "button", onclick: async (e) => {
        e.target.disabled = true;
        try {
          const r = await api("/api/embeddings/active", { method: "PUT", json: { account: String(a.id) } });
          toast(r.needs_reembedding ? "Embeddings switched. Re-embed (pagerlens reembed or POST /api/embeddings/reembed) to use the new size." : "Embeddings switched");
          reload();
        } catch (err) { result.className = "test-result bad"; result.textContent = err.message; e.target.disabled = false; }
      } }, "Use for embeddings") : null,
      a.read_only ? null : h("button", { class: "secondary small", type: "button", onclick: () => edit(a) }, "Edit"),
      a.read_only ? null : h("button", { class: "danger small", type: "button", onclick: async () => {
        if (!(await confirmDialog(`Delete the account "${a.name}"? Its stored key is erased.`, { title: "Delete account", confirmLabel: "Delete", danger: true }))) return;
        try { await api(`/api/accounts/${a.id}`, { method: "DELETE" }); toast("Account deleted"); reload(); } catch (err) { toast(err.message, true); }
      } }, "Delete")),
    result);
}

function accountForm(existing, presets, saved, cancel) {
  const e = existing;
  const provider = h("select", { id: "af-provider" }, ...presets.map((p) => h("option", { value: p.id }, p.name)));
  provider.value = e?.provider && presets.some((p) => p.id === e.provider) ? e.provider : "openai";
  const name = h("input", { id: "af-name", value: e?.name || "", maxlength: "60", required: true, placeholder: "e.g. OpenAI work" });
  const base = h("input", { id: "af-base", value: e?.base_url || "", maxlength: "300", required: true, placeholder: "https://api.example.com/v1" });
  const key = h("input", { id: "af-key", type: "password", autocomplete: "off", spellcheck: "false", placeholder: e?.has_key ? "leave blank to keep the stored key" : "sk-…" });
  const chat = h("input", { id: "af-chat", value: e?.chat_model || "", maxlength: "120", placeholder: "model name, e.g. from the provider's docs" });
  const embed = h("input", { id: "af-embed", value: e?.embedding_model || "", maxlength: "120", placeholder: "optional, e.g. text-embedding-3-small" });
  const dim = h("input", { id: "af-dim", type: "number", min: "8", max: "2000", step: "1", value: e?.embedding_dim ? String(e.embedding_dim) : "", placeholder: "e.g. 768" });
  const clear = h("input", { id: "af-clear", type: "checkbox" });
  const note = h("p", { class: "hint" });
  const err = h("p", { class: "error", role: "alert" });
  const applyPreset = () => {
    const p = presets.find((x) => x.id === provider.value);
    note.textContent = p?.note || "";
    if (e || !p) return;
    base.value = p.base_url;
    chat.value = p.chat_model;
    embed.value = p.embedding_model || "";
    dim.value = p.embedding_dim ? String(p.embedding_dim) : "";
    if (!name.value) name.value = p.id === "custom" ? "" : p.name;
  };
  provider.addEventListener("change", applyPreset);
  applyPreset();
  return h("form", {
    class: "card acct-form",
    onsubmit: async (ev) => {
      ev.preventDefault();
      err.textContent = "";
      const json = { name: name.value, provider: provider.value, base_url: base.value, api_key: key.value || null, clear_key: clear.checked,
        chat_model: chat.value || null, embedding_model: embed.value || null, embedding_dim: embed.value && dim.value ? Number(dim.value) : null };
      try {
        await api(e ? `/api/accounts/${e.id}` : "/api/accounts", { method: e ? "PUT" : "POST", json });
        key.value = "";
        toast(e ? "Account updated" : "Account added");
        saved();
      } catch (ex) { err.textContent = ex.message; }
    },
  },
  h("h3", {}, e ? `Edit ${e.name}` : "Add an account"),
  field("Provider", provider, null), note,
  h("div", { class: "grid2" }, field("Name", name), field("Base URL", base, "Must be https. Requests go from this server to this address.")),
  field("API key", key, "Stored encrypted. It is never shown again, only its last 4 characters."),
  e?.has_key ? h("label", { class: "check", for: "af-clear" }, clear, " Remove the stored key") : null,
  field("Chat model", chat),
  h("div", { class: "grid2" }, field("Embedding model", embed, "Used for runbook search and incident memory once you press \"Use for embeddings\" on the saved account."),
    field("Embedding size", dim, "Must match the stored vectors, or run a re-embed after switching (the vector size follows the active account).")),
  h("div", { class: "btns" }, h("button", { class: "primary", type: "submit" }, e ? "Save changes" : "Add account"),
    h("button", { class: "secondary", type: "button", onclick: cancel }, "Cancel")),
  err);
}

// ---- security -----------------------------------------------------------------------------------
async function renderSecurity() {
  const box = $("settings-security");
  let tokens, session;
  try { [tokens, session] = await Promise.all([api("/api/tokens"), api("/api/session")]); } catch (err) { box.replaceChildren(h("p", { class: "error" }, err.message)); return; }
  const reveal = h("div", { hidden: true });
  const tName = h("input", { id: "tk-name", maxlength: "60", required: true, placeholder: "e.g. Claude Code on my laptop" });
  const tScope = h("select", { id: "tk-scope" }, h("option", { value: "read" }, "Read-only (list and read incidents; recommended for MCP)"), h("option", { value: "ingest" }, "Ingest only (push logs, metrics, deploys and alerts; reads nothing)"), h("option", { value: "metrics" }, "Metrics only (scrape /metrics; reads nothing else)"), h("option", { value: "full" }, "Full access"));
  const tErr = h("p", { class: "error", role: "alert" });
  const tokenForm = h("form", { class: "grid-inline", onsubmit: async (e) => {
    e.preventDefault();
    tErr.textContent = "";
    try {
      const t = await api("/api/tokens", { method: "POST", json: { name: tName.value, scope: tScope.value } });
      tName.value = "";
      reveal.replaceChildren(
        h("p", { class: "warn-text" }, "Copy this token now. It is shown only once and cannot be recovered; only a hash is stored."),
        h("div", { class: "codewrap" }, h("pre", { class: "code" }, h("code", {}, t.token)), h("button", { class: "secondary small", type: "button", onclick: () => copy(t.token, "Token copied") }, "Copy")));
      reveal.hidden = false;
      renderTokenTable();
    } catch (ex) { tErr.textContent = ex.message; }
  } }, field("Name", tName), field("Access", tScope), h("button", { class: "primary", type: "submit" }, "Create token"));

  const table = h("div", {});
  async function renderTokenTable() {
    const list = await api("/api/tokens");
    table.replaceChildren(list.length ? flush("API tokens", h("table", {},
      h("thead", {}, h("tr", {}, ...[["Name"], ["Token"], ["Access"], ["Created"], ["Last used"], ["", "Actions"]].map(([t, name]) => h("th", {}, name ? h("span", { class: "sr" }, name) : t)))),
      h("tbody", {}, ...list.map((t) => h("tr", {},
        h("td", { class: "title" }, t.name), h("td", {}, h("code", {}, `${t.prefix}…`)), h("td", {}, t.scope),
        h("td", {}, fmtDate(t.created_at)), h("td", {}, fmtDate(t.last_used_at)),
        h("td", { class: "actions" }, t.revoked_at ? h("span", { class: "muted" }, "revoked") : h("button", { class: "danger small", type: "button", onclick: async () => {
          if (!(await confirmDialog(`Revoke "${t.name}"? Clients using it stop working immediately.`, { title: "Revoke token", confirmLabel: "Revoke", danger: true }))) return;
          try { await api(`/api/tokens/${t.id}`, { method: "DELETE" }); toast("Token revoked"); renderTokenTable(); } catch (err) { toast(err.message, true); }
        } }, "Revoke"))))))) : h("p", { class: "hint" }, "No tokens yet."));
  }

  const has = session.has_admin_password;
  const cur = h("input", { id: "pw-cur", type: "password", autocomplete: "current-password" });
  const nw = h("input", { id: "pw-new", type: "password", autocomplete: "new-password", minlength: "12", required: true });
  const nw2 = h("input", { id: "pw-new2", type: "password", autocomplete: "new-password", minlength: "12", required: true });
  const pErr = h("p", { class: "error", role: "alert" });
  const pwForm = h("form", { onsubmit: async (e) => {
    e.preventDefault();
    pErr.textContent = "";
    if (nw.value !== nw2.value) { pErr.textContent = "The new passwords do not match."; return; }
    try {
      await api("/api/admin-password", { method: "POST", json: { current: has ? cur.value : null, new: nw.value } });
      cur.value = nw.value = nw2.value = "";
      toast("Password saved. You were signed out everywhere.");
      window.dispatchEvent(new CustomEvent("apg-auth-lost"));
    } catch (ex) { pErr.textContent = ex.message; }
  } },
  has ? field("Current password", cur) : null,
  field(has ? "New password (12+ characters)" : "Admin password (12+ characters)", nw),
  field("Repeat", nw2),
  h("button", { class: "primary", type: "submit" }, has ? "Change password" : "Set admin password"), pErr);

  box.replaceChildren(
    h("h2", {}, "Security"),
    h("h3", {}, "Admin password"),
    h("p", { class: "muted" }, has ? "Changing it signs every browser out and re-protects the stored provider keys." : "No admin password is set (you signed in with the server's API key). Set one to store provider keys and to sign in without that key."),
    h("div", { class: "card" }, pwForm),
    h("h3", {}, "API tokens"),
    h("p", { class: "muted" }, "For MCP clients and scripts. Prefer the narrowest token: read-only for assistants, ingest-only for the services that push telemetry."),
    h("div", { class: "card" }, tokenForm, tErr), reveal, table);
  renderTokenTable();
}
