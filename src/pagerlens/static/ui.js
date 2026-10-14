// Tiny DOM helpers. Text always goes through textContent, never innerHTML.

export const $ = (id) => document.getElementById(id);

export function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === false || v == null) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "value") el.value = v;
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

let toastTimer;
export function toast(msg, bad = false) {
  const t = $("toast");
  t.textContent = msg;
  t.className = "toast" + (bad ? " bad" : "");
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, bad ? 8000 : 3500);
}

export async function copy(text, okMsg = "Copied") {
  try { await navigator.clipboard.writeText(text); toast(okMsg); } catch { toast("Copy failed", true); }
}

export const fmtDate = (s) => (s ? new Date(s).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : "never");

export function setBusy(button, busy, label) {
  button.disabled = busy;
  if (label !== undefined) button.dataset.label = button.dataset.label || button.textContent;
  button.textContent = busy ? label : (button.dataset.label || button.textContent);
}

export function field(label, input, hint) {
  const id = input.id || `f_${Math.random().toString(36).slice(2, 8)}`;
  input.id = id;
  return h("div", { class: "field" }, h("label", { for: id }, label), input, hint ? h("p", { class: "hint" }, hint) : null);
}

// Element.replaceChildren renders null/undefined/false as the text "null"; this drops them instead.
export function fill(el, ...kids) {
  el.replaceChildren(...kids.flat().filter((k) => k != null && k !== false));
}
