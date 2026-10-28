// Live updates and the Database tab, without a browser: live.js (EventSource, debounce, polling fallback), the incident list reloading on a
// server event, and the kit's insights panel mounted in its tab. Run: node tests/ui/live_insights.mjs
import { fail, find, findAll, installDom } from "./fakedom.mjs";

const sources = [];
globalThis.EventSource = class {
  constructor(url) { this.url = url; this.readyState = 1; this.listeners = {}; this.closed = false; sources.push(this); }
  addEventListener(t, f) { (this.listeners[t] ||= []).push(f); }
  close() { this.closed = true; this.readyState = 2; }
  emit(t, data) { for (const f of this.listeners[t] || []) f({ data: JSON.stringify(data) }); }
};

let listCalls = 0, insightsCalls = 0;
const dom = await installDom({ hash: "#incidents", routes: async (p) => {
  if (p.startsWith("/api/incidents")) { listCalls++; return { incidents: [], total: 0 }; }
  if (p.startsWith("/api/insights")) {
    insightsCalls++;
    const na = { available: false, reason: "extension edb_stat_monitor is not installed" };
    return { sources: {}, top_queries: { available: true, source: "pg_stat_statements", queries: [
      { queryid: "6823950417", query: "SELECT qty FROM stock WHERE sku = $1", calls: 10, total_ms: 4800, mean_ms: 480, max_ms: 900, rows: 10 }] }, tuner: na, advisor: na };
  }
  return {};
} });
const text = (el) => (el.data !== undefined ? String(el.data) : "") + (el.textContent || "") + (el.children || []).map(text).join(" ");

// 1. live.js: a burst of change events is one reload; hello without live falls back to polling; stop closes the stream
const { watch } = await import("/static/live.js");
let calls = 0;
const w = watch(() => { calls++; }, { fallbackMs: 5000 });
const es = sources.at(-1);
if (es.url !== "/api/events") fail("the stream URL is " + es.url);
es.emit("hello", { live: true });
for (let i = 0; i < 5; i++) es.emit("change", { table: "incident", op: "update", id: i });
await dom.tick();
if (calls !== 1) fail(`five events in a burst must trigger one reload, got ${calls}`);
if (w.mode() !== "live") fail("mode should be live, is " + w.mode());
w.stop();
if (!es.closed || w.mode() !== "stopped") fail("stop() must close the stream");

let polled = 0;
const p = watch(() => { polled++; }, { fallbackMs: 5000 });
const es2 = sources.at(-1);
es2.emit("hello", { live: false });                    // the database cannot send changes (no tcn)
if (!es2.closed || p.mode() !== "polling") fail("without live changes it must fall back to polling");
await dom.tick();
if (polled !== 1) fail("the polling fallback must reload on its timer, got " + polled);
p.stop();

const es3 = (watch(() => {}), sources.at(-1));         // a refused stream (signed out, no permission): readyState CLOSED
es3.readyState = 2; es3.onerror();
if (!es3.closed) fail("a refused stream must fall back, not retry forever");

// 2. the incident list reloads when the server says something changed, and stops listening when the tab is left
const { initIncidents, stopIncidents } = await import("/static/incidents.js");
await initIncidents();
await dom.settle();
const before = listCalls, listEs = sources.at(-1);
listEs.emit("hello", { live: true });
listEs.emit("change", { table: "incident", op: "insert", id: 9 });
await dom.tick();
if (listCalls !== before + 1) fail(`the list must re-read once after a change event (before ${before}, after ${listCalls})`);
stopIncidents();
if (!listEs.closed) fail("leaving the Incidents tab must close the event stream");

// 3. the Database tab mounts the kit's insights panel and renders it
const { initDatabase } = await import("/static/dbinsights.js");
await initDatabase();
await dom.settle();
const box = dom.el("view-insights");
const all = text(box);
if (!all.includes("Query insights")) fail("the kit panel did not render its heading");
if (!all.includes("6823950417") && !all.includes("SELECT qty FROM stock")) fail("the top query is missing: " + all.slice(0, 200));
if (!all.includes("Not available on this database") || !all.includes("edb_stat_monitor is not installed")) fail("an unavailable part must say so with the server's reason");
if (insightsCalls !== 1) fail("the panel should call /api/insights once, called " + insightsCalls);
console.log("ok: live updates (events, debounce, polling fallback, stop) and the Database tab");
process.exit(0);
