import { api } from "/kit/api.js";
import { field, h, toast } from "/kit/ui.js";

// The "Retire service" confirmation, shared by the service page and the dashboard card. It is built once and placed
// OUTSIDE anything the 10 s refresh redraws, so the typed name, the focus and the caret survive (a redraw would wipe it).
export function retirePanel(name, { onDone, onCancel } = {}) {
  const typed = h("input", { id: "retire-confirm", autocomplete: "off", spellcheck: "false", placeholder: name, "aria-label": `Type ${name} to confirm` });
  const go = h("button", { class: "danger", type: "submit", disabled: true }, "Retire service");
  const err = h("p", { class: "error", role: "alert" });
  typed.addEventListener("input", () => { go.disabled = typed.value !== name; });      // only the button changes; nothing is redrawn
  return h("form", { class: "card danger-zone", id: "retire-panel", onsubmit: async (e) => {
    e.preventDefault();
    if (typed.value !== name) return;
    err.textContent = "";
    go.disabled = true;
    try {
      const r = await api(`/api/services/${encodeURIComponent(name)}/retire`, { method: "POST", json: { confirm: typed.value } });
      toast(`${name} retired: ${r.metric_points} metric points, ${r.log_events} log lines and ${r.deploys} deploys deleted, ${r.incidents_resolved.length} incident${r.incidents_resolved.length === 1 ? "" : "s"} resolved`);
      if (onDone) onDone(r);
    } catch (ex) { err.textContent = ex.message; go.disabled = typed.value !== name; }
  } },
  h("h3", {}, `Retire ${name}`),
  h("p", { class: "muted" }, "Removes the service from the dashboard and deletes its metric points, log events, deploys and dependency edges. Its open incidents are resolved as \"service retired\" and kept as history; nothing is learned from them. If it sends telemetry again later, it reappears as a new service."),
  field(`Type the service name (${name}) to confirm`, typed),
  h("div", { class: "btns" }, go, onCancel ? h("button", { class: "secondary", type: "button", onclick: onCancel }, "Cancel") : null),
  err);
}
