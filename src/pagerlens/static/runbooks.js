import { api } from "/kit/api.js";
import { $, fill, h } from "/kit/ui.js";

export async function initRunbooks() {
  const box = $("view-runbooks");
  fill(box, h("p", { class: "loading" }, "Loading…"));
  let data;
  try { data = await api("/api/runbooks"); } catch (err) { fill(box, h("p", { class: "error" }, err.message)); return; }
  fill(box, h("h1", {}, "Runbooks"),
    h("p", { class: "muted" }, "The knowledge the investigator retrieves (hybrid vector + full-text search in Postgres) to suggest manual next steps."),
    data.runbooks.length ? h("div", {}, ...data.runbooks.map((r) => h("article", { class: "card" },
      h("div", { class: "row" }, h("h3", {}, r.title), h("span", { class: "badge alt" }, r.category)), h("p", {}, r.body)))) :
      h("div", { class: "card empty" }, h("p", {}, "No runbooks yet. Loading the demo fleet in the Lab adds some.")));
}
