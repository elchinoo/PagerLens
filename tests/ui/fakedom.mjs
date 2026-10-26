// A tiny fake DOM for the browser modules (no browser, no server). Shared by the *_typing.mjs checks.
// It models what matters for "a redraw wiped what the person was typing": element identity, value, focus and caret,
// and (as a real browser does) it drops the focus when the focused element is removed from the page.
import { pathToFileURL } from "node:url";
import { register } from "node:module";
import path from "node:path";

const here = path.dirname(new URL(import.meta.url).pathname);
const STATIC = path.resolve(here, "../../src/pagerlens/static");
const KIT = path.resolve(here, "../../../agentpg-kit/src/apgkit/static");
const loader = `export async function resolve(s, c, n) {
  if (s.startsWith("/kit/")) return { url: ${JSON.stringify(pathToFileURL(KIT).href)} + "/" + s.slice(5), shortCircuit: true };
  if (s.startsWith("/static/")) return { url: ${JSON.stringify(pathToFileURL(STATIC).href)} + "/" + s.slice(8), shortCircuit: true };
  return n(s, c);
}`;
register("data:text/javascript," + encodeURIComponent(loader));

export const modals = [];   // open modal dialogs, last = topmost
export const isInert = (el) => { const top = modals[modals.length - 1]; return !!top && !contains(top, el); };
const contains = (root, el) => root === el || (root.children || []).some((c) => contains(c, el));

class El {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.dataset = {}; this.value = ""; this.listeners = {}; this.classes = new Set(); this.classList = { toggle() {}, add: (c) => this.classes.add(c), remove: (c) => this.classes.delete(c), contains: (c) => this.classes.has(c) }; this.style = {}; this.textContent = ""; this.className = ""; this.disabled = false; this.parent = null; this.open = false; this.selectionStart = null; this.selectionEnd = null; }
  append(...k) { for (const x of k) if (x.parent !== undefined) x.parent = this; this.children.push(...k); }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter((c) => c !== this); this.parent = null; if (document.activeElement && !contains(document.body, document.activeElement)) document.activeElement = null; }
  prepend(...k) { this.children.unshift(...k); }
  replaceChildren(...k) {
    const old = this.children;
    this.children = k;
    const a = document.activeElement;
    if (a && old.some((c) => contains(c, a)) && !k.some((c) => contains(c, a))) document.activeElement = null;   // a removed element loses focus
  }
  setAttribute(k, v) { this.attrs[k] = v; if (k === "checked") this.checked = true; }
  addEventListener(t, f) { (this.listeners[t] ||= []).push(f); }
  focus() { document.activeElement = this; }
  setSelectionRange(a, b) { this.selectionStart = a; this.selectionEnd = b; }
  // <dialog>: showModal() makes it the topmost modal (everything outside it is inert), close() pops it; a native Escape is a
  // cancelable 'cancel' event, which the page must handle itself (the kit calls preventDefault and closes the dialog).
  showModal() { this.open = true; modals.push(this); this.attrs.open = ""; }
  close() { this.open = false; const i = modals.indexOf(this); if (i >= 0) modals.splice(i, 1); }
  dispatch(type, ev = {}) {
    const e = { target: this, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, ...ev };
    for (const f of this.listeners[type] || []) f(e);
    return e;
  }
  scrollIntoView() {}
  get nodeType() { return 1; }
  querySelector(sel) { return sel.startsWith("#") ? find(this, (e) => e !== this && e.attrs?.id === sel.slice(1)) || null : null; }
  querySelectorAll() { return []; } matches() { return false; }
}

export const find = (el, pred) => (pred(el) ? el : (el.children || []).map((c) => find(c, pred)).find(Boolean));
export const findId = (el, id) => find(el, (e) => e.attrs?.id === id);
export const findAll = (el, pred) => [...(pred(el) ? [el] : []), ...(el.children || []).flatMap((c) => findAll(c, pred))];

// Installs the globals and returns helpers. `routes(path, init)` answers every fetch with a JSON body.
export async function installDom({ hash, routes, perms = ["*"] }) {
  const els = {};
  globalThis.document = { body: new El("body"), activeElement: null, hidden: false, documentElement: { dataset: { csrf: "X-PagerLens-CSRF" } }, getElementById: (id) => Object.values(els).map((r) => find(r, (e) => e.attrs?.id === id)).find(Boolean) || (els[id] ||= new El("#" + id)),   // like a page: a created element is found once it is attached
    createElement: (t) => new El(t), createElementNS: (_, t) => new El(t), createTextNode: (d) => ({ nodeType: 3, data: d }), querySelectorAll: () => [] };
  modals.length = 0;
  globalThis.window = { dispatchEvent() {}, addEventListener() {} };
  globalThis.CustomEvent = class {};
  for (const n of ["confirm", "alert", "prompt"]) globalThis[n] = () => { throw new Error(`native ${n}() called`); };   // a native dialog freezes a real browser
  globalThis.location = { origin: "http://x", hash, search: "", pathname: "/" };
  globalThis.fetch = async (p, init) => {
    const body = await routes(p, init || {});
    return { ok: true, status: 200, headers: { get: () => "application/json" }, json: async () => body, text: async () => JSON.stringify(body) };
  };
  const { state } = await import("/kit/session.js");
  state.session = { state: "logged_in", user: { permissions: perms } };
  // Timers: nothing fires by itself. A test runs the pending ones by hand, in order.
  const realSetTimeout = globalThis.setTimeout, realSetInterval = globalThis.setInterval;
  const timers = [];
  globalThis.setTimeout = (f) => { const t = { f, kind: "timeout", live: true }; timers.push(t); return t; };
  globalThis.clearTimeout = (t) => { if (t) t.live = false; };
  globalThis.setInterval = (f) => { const t = { f, kind: "interval", live: true }; timers.push(t); return t; };
  globalThis.clearInterval = (t) => { if (t) t.live = false; };
  const settle = () => new Promise((r) => realSetTimeout(r, 30));
  // Fire every live timer once (a timeout is then spent), then let the async refresh it started finish.
  const tick = async () => {
    for (const t of timers.filter((x) => x.live)) { if (t.kind === "timeout") t.live = false; await t.f(); }
    await settle();
  };
  return { el: (id) => document.getElementById(id), timers, tick, settle, realSetTimeout, realSetInterval };
}

export function fail(msg) { console.error("FAIL: " + msg); process.exit(1); }
