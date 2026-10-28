// Live updates: server-sent events (Postgres tcn on the server) with a timer as the fallback.
// watch(onChange) opens GET /api/events. A `change` event (an incident or alert row changed; it carries no content) calls onChange
// once, debounced, so the page re-reads through the normal API. If the browser has no EventSource, the server says the database
// cannot send changes (`hello` with live:false) or the stream is refused, it polls every `fallbackMs` instead. Nothing runs while the
// tab is hidden. Returns { stop(), mode() } where mode() is "live", "polling" or "stopped".
export function watch(onChange, { fallbackMs = 20000, debounceMs = 300, url = "/api/events" } = {}) {
  let es = null, poll = null, wait = null, stopped = false;
  const fire = () => { clearTimeout(wait); wait = setTimeout(() => { if (!stopped && !document.hidden) onChange(); }, debounceMs); };
  const fallBack = () => {
    if (es) { es.close(); es = null; }
    if (!poll && !stopped) poll = setInterval(() => { if (!document.hidden) onChange(); }, fallbackMs);
  };
  if (typeof EventSource === "undefined") fallBack();
  else {
    es = new EventSource(url);
    es.addEventListener("hello", (e) => {
      let live = false;
      try { live = JSON.parse(e.data).live === true; } catch { /* not JSON: treat as not live */ }
      if (!live) fallBack();
    });
    es.addEventListener("change", fire);
    es.onerror = () => { if (es && es.readyState === 2) fallBack(); };   // CLOSED: refused (signed out, no permission) or the server is gone
  }
  return {
    stop() { stopped = true; clearTimeout(wait); clearInterval(poll); poll = null; if (es) { es.close(); es = null; } },
    mode() { return stopped ? "stopped" : poll ? "polling" : es ? "live" : "stopped"; },
  };
}
