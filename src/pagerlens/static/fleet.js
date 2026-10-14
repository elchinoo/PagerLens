import { api } from "/static/api.js";
import { $, fill, h } from "/static/ui.js";

const when = (s) => (s ? new Date(s).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "never");
const fmt = (v) => (v == null ? "–" : Math.round(v * 10) / 10);

export async function initFleet() {
  const box = $("view-fleet");
  fill(box, h("p", { class: "loading" }, "Loading fleet…"));
  let data;
  try { data = await api("/api/fleet"); } catch (err) { fill(box, h("p", { class: "error" }, err.message)); return; }
  const origin = location.origin;
  fill(box,
    h("h1", {}, "Fleet"),
    h("p", { class: "muted" }, "The services PagerLens watches. The demo fleet is simulated; real services push the same data through the ingest API."),
    data.services.length ? h("div", { class: "acct-grid" }, ...data.services.map((s) => h("article", { class: "card acct" },
      h("div", { class: "row" }, h("h3", {}, s.name), h("span", { class: "badges" }, s.tier ? h("span", { class: "badge plain" }, s.tier) : null,
        s.open_incidents ? h("span", { class: "badge sev sev2" }, `${s.open_incidents} open`) : h("span", { class: "badge status resolved" }, "healthy"))),
      h("p", { class: "muted" }, s.description || ""),
      h("dl", { class: "facts" },
        h("dt", {}, "Owner"), h("dd", {}, s.owner || "–"),
        h("dt", {}, "Depends on"), h("dd", {}, s.depends_on.length ? s.depends_on.join(", ") : "nothing"),
        h("dt", {}, "Last deploy"), h("dd", {}, s.last_deploy ? `${s.last_deploy.version} · ${when(s.last_deploy.deployed_at)}` : "none"),
        h("dt", {}, "Right now"), h("dd", {}, `${fmt(s.latest.request_rate)} req/s · ${fmt(s.latest.error_rate)}% errors · p95 ${fmt(s.latest.latency_p95_ms)} ms · CPU ${fmt(s.latest.cpu_pct)}% · mem ${fmt(s.latest.mem_pct)}%`))))) :
      h("div", { class: "card empty" }, h("p", {}, "No services yet."), h("a", { class: "button-link", href: "#lab" }, "Load the demo fleet in the Lab")),
    h("section", { class: "settings-block" },
      h("h2", {}, "Send your own telemetry"),
      h("p", { class: "muted" }, "Create an Ingest-only token under Settings (it can push data but read nothing), then post to the API. Logs are scrubbed of emails, IPs, cards and secrets before they are stored."),
      h("pre", { class: "code" }, h("code", {}, `export PAGERLENS_TOKEN=<ingest token>

curl -X POST ${origin}/api/ingest/logs \\
  -H "Authorization: Bearer $PAGERLENS_TOKEN" -H "Content-Type: application/json" \\
  -d '{"service":"checkout-api","events":[{"level":"error","message":"payment failed: timeout"}]}'

curl -X POST ${origin}/api/ingest/alerts \\
  -H "Authorization: Bearer $PAGERLENS_TOKEN" -H "Content-Type: application/json" \\
  -d '{"service":"checkout-api","name":"HighErrorRate","summary":"5xx above 5%","severity":"sev2"}'`))));
}
