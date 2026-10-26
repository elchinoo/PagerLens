import { api } from "/kit/api.js";
import { $, confirmDialog, fill, h, setBusy, toast } from "/kit/ui.js";

export async function initLab() {
  const box = $("view-lab");
  fill(box, h("p", { class: "loading" }, "Loading…"));
  let data;
  try { data = await api("/api/simulator/scenarios"); } catch (err) { fill(box, h("p", { class: "error" }, err.message)); return; }
  const cards = data.scenarios.map((s) => {
    const btn = h("button", { class: "primary", type: "button", onclick: async () => {
      if (!(await confirmDialog("This replaces the demo telemetry (logs, metrics, deploys) with a fresh window that contains this failure. Incidents and reports are kept. Continue?", { title: "Replace demo telemetry", confirmLabel: "Continue", danger: true }))) return;
      setBusy(btn, true, "Breaking the shop…");
      try { const r = await api("/api/simulator/trigger", { method: "POST", json: { scenario: s.key } }); toast("Alert fired"); location.hash = `#incidents/${r.incident_id}`; }
      catch (err) { toast(err.message, true); setBusy(btn, false); }
    } }, "Break it");
    return h("article", { class: "card acct" },
      h("div", { class: "row" }, h("h3", { "aria-level": "2" }, s.title), h("span", { class: `badge sev ${s.severity}` }, s.severity)),
      h("p", { class: "muted" }, s.blurb), h("p", { class: "hint" }, `Alert fires on ${s.service}.`), h("div", { class: "btns" }, btn));
  });
  const reset = h("button", { class: "secondary", type: "button", onclick: async () => {
    setBusy(reset, true, "Resetting…");
    try { await api("/api/simulator/baseline", { method: "POST" }); toast("Healthy baseline loaded"); } catch (err) { toast(err.message, true); }
    setBusy(reset, false);
  } }, "Load healthy baseline");
  fill(box,
    h("h1", {}, "Lab"),
    h("p", { class: "muted" }, "A fictional online shop of five services. Pick a failure: the simulator writes realistic logs, metrics and deploys through the same ingest path real services use, fires an alert, and opens an incident. The true cause is hidden until you reveal it."),
    h("div", { class: "banner" }, "The Lab regenerates the demo telemetry each time, so only the newest scenario has live telemetry. Past incidents keep their reports and evidence."),
    h("div", { class: "btns" }, reset),
    h("div", { class: "acct-grid" }, ...cards),
    h("p", { class: "muted" }, "Measure how well it does: run ", h("code", {}, "pagerlens eval"), " (CLI) for a cold vs. warm top-1 / top-3 comparison against the hidden answers."));
}
