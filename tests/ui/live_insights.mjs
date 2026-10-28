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

// 1b. watchdog: a proxy that buffers the stream leaves EventSource CONNECTING with no error and no hello. After 6 s the page closes
// the stream, polls, and tries the stream once more after 60 s. The fake timers record their delays so the numbers are checked too.
{
  const fakeSet = globalThis.setTimeout, delays = new Map();
  globalThis.setTimeout = (f, ms) => { const t = fakeSet(f, ms); delays.set(t, ms); return t; };
  const mine = (from) => dom.timers.slice(from).filter((t) => t.live && t.kind === "timeout");
  let n = dom.timers.length, wd = 0;
  const w1 = watch(() => { wd++; }, { fallbackMs: 5000 });
  const s1 = sources.at(-1);
  const [dog] = mine(n);
  if (!dog || delays.get(dog) !== 6000) fail("the watchdog must wait 6000 ms for hello, got " + (dog && delays.get(dog)));
  await dog.f();                                         // 6 s pass with no hello
  if (!s1.closed || w1.mode() !== "polling") fail("no hello in 6 s must close the stream and poll, mode " + w1.mode());
  const [retry] = mine(n).filter((t) => t !== dog);
  if (!retry || delays.get(retry) !== 60000) fail("the stream must be retried once after 60000 ms, got " + (retry && delays.get(retry)));
  const before = sources.length;
  await retry.f();                                       // 60 s later: the second try comes up
  if (sources.length !== before + 1) fail("the retry must open a new stream");
  const s2 = sources.at(-1);
  s2.emit("hello", { live: true });
  if (w1.mode() !== "live") fail("a hello on the retried stream must make the page live again, mode " + w1.mode());
  w1.stop();
  if (!s2.closed) fail("stop() must close the retried stream");

  // a stream that never says hello twice is not retried a second time
  n = dom.timers.length;
  const w2 = watch(() => {}, { fallbackMs: 5000 });
  const [dog2] = mine(n);
  await dog2.f();
  const [retry2] = mine(n).filter((t) => t !== dog2);
  await retry2.f();
  const [dog3] = mine(n).filter((t) => t !== dog2 && t !== retry2);
  if (!dog3) fail("the retried stream needs its own watchdog");
  const count = sources.length;
  await dog3.f();
  if (w2.mode() !== "polling" || mine(n).filter((t) => ![dog2, retry2, dog3].includes(t)).length) fail("after the retry also fails it must stay on polling, with no third attempt");
  if (sources.length !== count) fail("no third stream");
  w2.stop();

  // hello in time cancels the watchdog
  n = dom.timers.length;
  const w3 = watch(() => {}, { fallbackMs: 5000 });
  const [dog4] = mine(n);
  sources.at(-1).emit("hello", { live: true });
  if (dog4.live) fail("hello must cancel the watchdog");
  w3.stop();
  globalThis.setTimeout = fakeSet;
}

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
