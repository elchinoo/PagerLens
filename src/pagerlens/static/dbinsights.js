// The Database tab: the kit's query-insights panel (edb_stat_monitor, edb_pg_tuner, query_advisor) for this app's own database.
// Administrators only (GET /api/insights needs settings:manage). On a plain Postgres every part says "Not available".
import { initInsights } from "/kit/insights.js";
import { api } from "/kit/api.js";
import { $ } from "/kit/ui.js";

export function initDatabase() {
  return initInsights($("view-insights"), api);
}
