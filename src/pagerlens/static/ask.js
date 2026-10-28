// The Ask tab: a conversation with PagerLens in plain English. The server runs a model over read-only tools and VERIFIES every
// [incident #N] / [evidence #N] / [runbook #N] citation: only verified sources come back as chips, the rest is marked in the answer.
// Everything from the server goes in through text nodes (the h() helper), never parsed as HTML; links are only ever built from a strict pattern.
import { api } from "/kit/api.js";
import { $, fill, h } from "/kit/ui.js";

const MAX_CHARS = 1000;
const LINK = /^#(incidents\/\d{1,15}|runbooks)$/;
const FALLBACK_SUGGESTIONS = ["Why is checkout-api failing?", "Have we seen this before?", "What is slow in the database?"];

// The conversation lives in the module, not in the DOM: leaving the tab and coming back (the router re-runs initAsk) keeps it,
// and so does a half-typed question. Nothing is stored in the browser beyond this page's lifetime.
const convo = { id: null, turns: [], pending: false, error: null, draft: "", ready: true, reason: "", suggestions: FALLBACK_SUGGESTIONS };
const ui = { log: null, input: null, send: null };

function turnText(t) { return String(t.text || "").slice(0, MAX_CHARS); }

function sourceChip(s) {
  const ok = LINK.test(String(s.link || ""));
  const kids = [h("span", { class: "chip-ref" }, s.ref), " ", h("span", { class: "muted" }, String(s.label || "").slice(0, 70))];
  return h("li", {}, ok ? h("a", { class: "chip link", href: s.link, title: `${s.ref}: ${s.label || ""}` }, ...kids) : h("span", { class: "chip" }, ...kids));
}

const WHY = { not_found: "no such record", not_read: "never read in this conversation" };

function assistantTurn(t) {
  const kids = [h("p", { class: "who" }, "PagerLens"), h("p", { class: "text" }, t.text)];
  if (t.sources && t.sources.length) {
    kids.push(h("p", { class: "hint", id: `src-${t.n}` }, "Verified sources (checked against the database):"),
      h("ul", { class: "sources", "aria-labelledby": `src-${t.n}` }, ...t.sources.map(sourceChip)));
  }
  if (t.unverified && t.unverified.length) {
    kids.push(h("p", { class: "unverified", role: "note" },
      "Could not verify: " + t.unverified.map((u) => `${u.ref} (${WHY[u.reason] || u.reason})`).join(", ") +
      ". They are marked in the answer and are not shown as sources."));
  }
  const others = (t.warnings || []).filter((w) => !/could not be verified/.test(w));
  for (const w of others) kids.push(h("p", { class: "hint" }, w));
  if (t.steps && t.steps.length) kids.push(h("p", { class: "hint" }, "Looked at: " + t.steps.filter((s) => !s.error).map((s) => s.tool).join(", ")));
  return h("article", { class: "msg assistant" }, ...kids);
}

function render() {
  const log = ui.log;
  if (!log) return;
  const kids = [];
  if (!convo.turns.length && !convo.pending && !convo.error) {
    kids.push(h("p", { class: "muted empty-ask" }, "Ask a question below, or pick one of the suggestions."));
  }
  convo.turns.forEach((t, i) => {
    t.n = i;
    kids.push(t.role === "user"
      ? h("article", { class: "msg user" }, h("p", { class: "who" }, "You"), h("p", { class: "text" }, t.text))
      : assistantTurn(t));
  });
  if (convo.pending) {
    kids.push(h("div", { class: "typing loading", role: "status" }, h("span", { class: "spinner", "aria-hidden": "true" }),
      h("span", { class: "loading-text" }, "PagerLens is looking things up…")));
  }
  let retry = null;
  if (convo.error) {
    retry = h("button", { class: "secondary", type: "button", id: "ask-retry", onclick: () => run() }, "Try again");
    kids.push(h("div", { class: "error-state", role: "alert" }, h("p", { class: "error" }, convo.error), retry));
  }
  fill(log, ...kids);
  log.setAttribute("aria-busy", convo.pending ? "true" : "false");
  if (ui.send) ui.send.disabled = convo.pending;
  const last = log.children[log.children.length - 1];
  if (last && last.scrollIntoView) last.scrollIntoView({ block: "nearest" });
  if (retry) retry.focus();
}

async function run() {
  if (convo.pending) return;
  convo.pending = true;
  convo.error = null;
  render();
  try {
    const messages = convo.turns.slice(-6).map((t) => ({ role: t.role, content: turnText(t) }));
    const out = await api("/api/ask", { method: "POST", json: { messages, ...(convo.id ? { conversation_id: convo.id } : {}) } });
    convo.id = out.conversation_id;
    convo.turns.push({ role: "assistant", text: out.answer, sources: out.sources, unverified: out.unverified, warnings: out.warnings, steps: out.steps });
  } catch (err) {
    convo.error = err && err.message ? err.message : "Something went wrong. Try again.";
  }
  convo.pending = false;
  render();
  if (!convo.error && ui.input) ui.input.focus();
}

function ask(text) {
  const q = String(text || "").trim().slice(0, MAX_CHARS);
  if (!q || convo.pending) return;
  convo.turns.push({ role: "user", text: q });
  convo.draft = "";
  if (ui.input) ui.input.value = "";
  return run();
}

function reset() {
  if (convo.pending) return;
  Object.assign(convo, { id: null, turns: [], error: null, draft: "" });
  if (ui.input) { ui.input.value = ""; ui.input.focus(); }
  render();
}

export async function initAsk() {
  const box = $("view-ask");
  const input = h("textarea", { id: "ask-input", rows: "2", maxlength: String(MAX_CHARS), autocomplete: "off", spellcheck: "true",
    "aria-describedby": "ask-hint", placeholder: "Ask about a service, an incident or the database…", value: convo.draft });
  input.addEventListener("input", () => { convo.draft = input.value; });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); ask(input.value); }
  });
  const send = h("button", { class: "primary", type: "button", id: "ask-send", onclick: () => ask(input.value) }, "Ask");
  const log = h("div", { id: "ask-log", class: "ask-log card", role: "log", "aria-live": "polite", "aria-label": "Conversation with PagerLens", "aria-busy": "false" });
  Object.assign(ui, { log, input, send });
  const chips = h("div", { class: "chips", role: "group", "aria-label": "Suggested questions" });
  const drawChips = () => fill(chips, ...convo.suggestions.map((q) => h("button", { class: "chip", type: "button", onclick: () => ask(q) }, q)));
  const notice = h("div", { id: "ask-notice" });
  fill(box,
    h("h1", {}, "Ask PagerLens"),
    h("p", { class: "muted" }, "Ask in plain English. PagerLens looks things up with read-only tools and cites what it found. Every citation is checked against the database: a source it cannot verify is marked, and only verified sources are shown as chips. It can read; it cannot change anything."),
    notice, chips, log,
    h("div", { class: "ask-form", role: "group", "aria-label": "Ask a question" },
      h("label", { class: "sr-only", for: "ask-input" }, "Your question"), input,
      h("p", { class: "hint", id: "ask-hint" }, "Enter sends, Shift+Enter adds a line. Answers come from a model: check the sources."),
      h("div", { class: "btns" }, send, h("button", { class: "ghost", type: "button", onclick: reset }, "New conversation"))));
  drawChips();
  render();
  try {
    const s = await api("/api/ask");
    Object.assign(convo, { ready: s.ready, reason: s.reason || "", suggestions: s.suggestions && s.suggestions.length ? s.suggestions : FALLBACK_SUGGESTIONS });
  } catch { /* the first question will show the real error */ }
  drawChips();
  fill(notice, convo.ready ? null : h("div", { class: "banner", role: "status" }, convo.reason || "No chat account is configured, so PagerLens cannot answer yet."));
}
