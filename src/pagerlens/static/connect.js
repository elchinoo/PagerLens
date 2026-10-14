import { CLIENTS } from "/static/clients.js";
import { $, copy, h } from "/static/ui.js";

let ready = false;

function render() {
  const c = CLIENTS.find((x) => x.id === $("client").value) || CLIENTS[0];
  const url = location.origin + "/mcp";
  $("client-where").textContent = c.where;
  $("client-snippet").textContent = c.snippet(url);
  $("mcp-url").textContent = url;
}

export function initConnect() {
  if (!ready) {
    ready = true;
    for (const c of CLIENTS) $("client").append(h("option", { value: c.id }, c.name));
    $("client").addEventListener("change", render);
    $("copy-snippet").addEventListener("click", () => copy($("client-snippet").textContent));
  }
  render();
}
