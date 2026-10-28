// Live updates: server-sent events (Postgres tcn on the server) with a timer as the fallback.
// watch(onChange) opens GET /api/events. A `change` event (an incident or alert row changed; it carries no content) calls onChange
// once, debounced, so the page re-reads through the normal API. If the browser has no EventSource, the server says the database
// cannot send changes (`hello` with live:false) or the stream is refused, it polls every `fallbackMs` instead. Nothing runs while the
// tab is hidden. Returns { stop(), mode() } where mode() is "live", "polling" or "stopped".
//
// Watchdog: a proxy that buffers the stream leaves EventSource in CONNECTING with no `error` event, so the page would never poll. If
// no `hello` arrives within `helloMs` the stream is closed, the page is marked not live and polls; the stream is tried once more
// after `retryMs` (a successful `hello` with live:true then stops the polling again).
export function watch(onChange, { fallbackMs = 20000, debounceMs = 300, url = "/api/events", helloMs = 6000, retryMs = 60000 } = {}) {
  let es = null, poll = null, wait = null, dog = null, again = null, stopped = false, retried = false;
  const fire = () => { clearTimeout(wait); wait = setTimeout(() => { if (!stopped && !document.hidden) onChange(); }, debounceMs); };
  const closeStream = () => { clearTimeout(dog); dog = null; if (es) { es.close(); es = null; } };
  const startPolling = () => {
    if (!poll && !stopped) poll = setInterval(() => { if (!document.hidden) onChange(); }, fallbackMs);
  };
  const fallBack = () => { closeStream(); startPolling(); };
  const open = (isRetry) => {
    const source = new EventSource(url);
    es = source;
    dog = setTimeout(() => {
      if (stopped || es !== source) return;
      fallBack();                                                  // no `hello` in time: not live, poll
      if (!isRetry && !retried) { retried = true; again = setTimeout(() => { if (!stopped) open(true); }, retryMs); }
    }, helloMs);
    source.addEventListener("hello", (e) => {
      if (es !== source) return;
      clearTimeout(dog); dog = null;
      let live = false;
      try { live = JSON.parse(e.data).live === true; } catch { /* not JSON: treat as not live */ }
      if (!live) fallBack();
      else if (poll) { clearInterval(poll); poll = null; }         // the retried stream came up: live again
    });
    source.addEventListener("change", fire);
    source.onerror = () => { if (es === source && source.readyState === 2) fallBack(); };   // CLOSED: refused (signed out, no permission) or the server is gone
  };
  if (typeof EventSource === "undefined") startPolling();
  else open(false);
  return {
    stop() { stopped = true; clearTimeout(wait); clearTimeout(again); clearInterval(poll); poll = null; closeStream(); },
    mode() { return stopped ? "stopped" : poll ? "polling" : es ? "live" : "stopped"; },
  };
}
