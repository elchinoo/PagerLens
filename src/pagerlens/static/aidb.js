// The AIDB governance panel (Settings, administrators). Shown only when AIDB mode exists on this database: what the agent's purpose may
// read, whether the operator's seals still verify, and the tool calls the purpose denied (aidb.decisions). Plain Postgres shows nothing.
import { api } from "/kit/api.js";
import { fill, fmtDateTime, h } from "/kit/ui.js";

const STATES = { ready: "ok", unverified: "warn", "not-set-up": "plain", tampered: "bad", error: "bad", unavailable: "plain" };

export async function renderAidb(box) {
  if (!box) return;
  let st;
  try { st = await api("/api/aidb/status"); } catch { return; }
  if (!st || !st.state || st.state === "off") { fill(box); return; }
  let gov = null;
  try { gov = await api("/api/aidb/governance"); } catch { /* shown without the table */ }
  const rows = (gov && gov.denials) || [];
  fill(box,
    h("h2", {}, "AIDB mode"),
    h("p", { class: "muted" }, "Retrieval and the AIDB agent run inside the database. The agent can read only the evidence views its purpose names; Postgres refuses anything else, and every refusal is recorded."),
    h("div", { class: "card" },
      h("p", {}, h("span", { class: `badge ${STATES[st.state] || "plain"}` }, st.state), ` retrieval backend asked for: ${st.requested_backend}`
        + (st.retrieval ? `, in effect: ${Object.entries(st.retrieval).map(([k, v]) => `${k} ${v}`).join(", ")}` : "")),
      st.tampered && st.tampered.length ? h("div", { class: "banner" }, "Changed outside the app: " + st.tampered.join("; ")) : null,
      gov && gov.grants && gov.grants.length ? h("p", { class: "hint" }, `Purpose role ${gov.role} may: ${gov.grants.join(", ")}.`) : null,
      gov && gov.state === "ready" ? h("h3", {}, `Denied tool calls (${gov.window})`) : null,
      gov && gov.denials_error ? h("p", { class: "hint" }, `Denials are not readable here: ${gov.denials_error}.`) : null,
      rows.length ? h("table", {},
        h("caption", { class: "sr-only" }, "Tool calls refused by the agent's purpose"),
        h("thead", {}, h("tr", {}, ["When", "Agent", "Role", "Reason", "Statement"].map((c) => h("th", { scope: "col" }, c)))),
        h("tbody", {}, rows.map((d) => h("tr", {}, h("td", {}, fmtDateTime(d.at)), h("td", {}, d.agent || ""), h("td", {}, d.role || ""),
          h("td", {}, d.reason || ""), h("td", { class: "wrap-cell" }, d.statement || ""))))) :
        (gov && gov.state === "ready" && !gov.denials_error ? h("p", { class: "muted" }, "No tool call was denied in this window.") : null)));
}
