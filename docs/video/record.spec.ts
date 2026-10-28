import { test, expect, Page, Locator, Browser } from '@playwright/test';
import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * Records the on-screen part of the PagerLens tutorial video (docs/VIDEO-SCRIPT.md, scenes 1 to 12) with Playwright video.
 *
 *   1920x1080, light theme, slow human pacing (moving cursor, smooth scrolling, typed text), visible callout
 *   highlights and the lower-thirds from the script's callout column. Output (git-ignored): docs/video/out/.
 *
 * It does NOT start anything. Start the stack first (VIDEO-SCRIPT.md section 1): a fresh PagerLens database, `pagerlens
 * seed`, and `pagerlens serve` with the demo stand-in model, which scene 8 needs:
 *
 *   python scripts/fake_llm.py --port 8099 &      # DEMO STAND-IN, not a real model
 *   LLM_BASE_URL=http://127.0.0.1:8099/v1 LLM_API_KEY=demo LLM_CHAT_MODEL=demo-chat EMBEDDING_MODEL=demo-embed \
 *     pagerlens serve 2> /tmp/pagerlens-recording.log
 *
 * Then, from docs/video (once: `npm install`; the Chrome channel needs Google Chrome installed):
 *
 *   ADMIN_PASSWORD='<throwaway, 12+ characters>' npx playwright test            # reads the setup code from the log
 *
 * Environment (nothing secret is stored in this file; secrets stay in the Playwright process):
 *   PAGERLENS_URL   default http://localhost:8000
 *   ADMIN_PASSWORD  required. Throwaway, chosen by you. Used off camera (first-run setup and sign-in happen before the
 *                   recording context exists, so no password or token is ever on screen).
 *   SETUP_CODE      the first-run code, or
 *   SETUP_LOG       path of the server's stderr log (default /tmp/pagerlens-recording.log), polled for the code.
 *                   Neither is needed when the app is already set up (the password is then used to sign in).
 *   PACE            pause multiplier, default 1 (slow). Use 0.2 for a quick rehearsal.
 *   HEADED=1        show the browser.
 *
 * The recorder also asserts what the narration claims: the top hypothesis of the Rules investigation is the bad deploy,
 * the AI investigation agrees with it, and the second report lists the first incident under "Similar past incidents".
 * Terminal scenes are drawn as an in-page terminal card: scene 10 performs a real POST /api/ingest/alerts, scene 11 real MCP
 * calls (initialize, tools/call) against /mcp with the read-only `editor` token; scene 12 shows the quick-start commands as text.
 */

const BASE = (process.env.PAGERLENS_URL || 'http://localhost:8000').replace(/\/$/, '');
const PACE = Number(process.env.PACE || '1');
const OUT = process.env.OUT_DIR || path.join(__dirname, 'out');
// Narration timing (narration.json, written by narrate.py via narration.py audio): the scene lengths and the beats inside a scene follow the spoken audio.
// NARRATION_TIMING=<timing.json>; without it every scene lasts the table's length. PACE_FILE=<json {scene: factor}> stretches
// (>1) or compresses (<1) the pauses of one scene so its actions end when its narration does (see docs/video/README.md).
const LEAD = 0.2;      // seconds after the scene start before the narration starts (narration.py LEAD_IN)
const TAIL = 1.0;      // seconds of picture after the narration ends (the scene lasts at least audio + 0.7 s)
const mouse = { x: SIZE_W() / 2, y: 600 };   // where the cursor is, so idle time can drift it a little (a still picture tires the eye)
function SIZE_W() { return 1920; }
const TIMING: Record<string, { voice: string; duration: number; cues: { text: string; start: number; end: number }[] }> =
  process.env.NARRATION_TIMING ? JSON.parse(fs.readFileSync(process.env.NARRATION_TIMING, 'utf8')) : {};
const PACE_FACTORS: Record<string, number> = process.env.PACE_FILE && fs.existsSync(process.env.PACE_FILE)
  ? JSON.parse(fs.readFileSync(process.env.PACE_FILE, 'utf8')) : {};
let curPace = PACE;   // PACE times the current scene's factor
const SETUP_LOG = process.env.SETUP_LOG || '/tmp/pagerlens-recording.log';
const CSRF = { 'X-PagerLens-CSRF': '1' };
const SIZE = { width: 1920, height: 1080 };

test.use({
  baseURL: BASE,
  viewport: SIZE,
  colorScheme: 'light',
  deviceScaleFactor: 1,
  permissions: ['clipboard-read', 'clipboard-write'],
  video: { mode: 'on', size: SIZE },
});

// ---------------------------------------------------------------------------------------------------------------------
// Overlay (injected into every page): visible cursor, click ripple, callouts, lower third, terminal card, end card.
// Everything is drawn with CSSOM style assignments, which the page's content-security-policy allows.
// ---------------------------------------------------------------------------------------------------------------------
function installOverlay() {
  const ID = '__rec_root';
  const root = () => {
    let r = document.getElementById(ID);
    if (!r) {
      r = document.createElement('div');
      r.id = ID;
      Object.assign(r.style, { position: 'fixed', inset: '0', zIndex: '2147483647', pointerEvents: 'none', fontFamily: 'system-ui, sans-serif' });
      (document.body || document.documentElement).appendChild(r);
    }
    return r;
  };
  const el = (tag: string, style: Record<string, string>, text?: string) => {
    const e = document.createElement(tag);
    Object.assign(e.style, style);
    if (text !== undefined) e.textContent = text;
    return e;
  };
  const w = window as any;
  let cursor: HTMLElement | null = null;
  const moveCursor = (x: number, y: number) => {
    if (!cursor || !cursor.isConnected) {
      cursor = el('div', { position: 'fixed', width: '26px', height: '26px', borderRadius: '50%', background: 'rgba(255,140,0,.35)',
        border: '3px solid #ff8c00', boxShadow: '0 0 0 2px #fff', transform: 'translate(-50%,-50%)', zIndex: '3', left: '-50px', top: '-50px' });
      root().appendChild(cursor);
    }
    cursor.style.left = x + 'px';
    cursor.style.top = y + 'px';
  };
  document.addEventListener('mousemove', (e) => moveCursor(e.clientX, e.clientY), true);
  document.addEventListener('mousedown', (e) => {
    const ring = el('div', { position: 'fixed', left: e.clientX + 'px', top: e.clientY + 'px', width: '16px', height: '16px', borderRadius: '50%',
      border: '4px solid #ff8c00', transform: 'translate(-50%,-50%)', transition: 'all .45s ease-out', opacity: '1' });
    root().appendChild(ring);
    requestAnimationFrame(() => { Object.assign(ring.style, { width: '70px', height: '70px', opacity: '0' }); });
    setTimeout(() => ring.remove(), 600);
  }, true);

  w.__rec = {
    callout(box: { x: number; y: number; width: number; height: number }, text: string, place: 'above' | 'below' | 'right') {
      const pad = 8;
      const frame = el('div', { position: 'fixed', left: box.x - pad + 'px', top: box.y - pad + 'px', width: box.width + 2 * pad + 'px',
        height: box.height + 2 * pad + 'px', border: '4px solid #e8590c', borderRadius: '10px', boxShadow: '0 0 0 4px rgba(255,255,255,.85), 0 0 24px rgba(232,89,12,.55)' });
      frame.className = '__rec_callout';
      const label = el('div', { position: 'fixed', background: '#e8590c', color: '#fff', font: '600 24px/1.25 system-ui, sans-serif', padding: '10px 16px',
        borderRadius: '8px', maxWidth: '640px', boxShadow: '0 4px 16px rgba(0,0,0,.35)' }, text);
      label.className = '__rec_callout';
      root().append(frame, label);
      const lw = label.offsetWidth, lh = label.offsetHeight;
      let left = box.x, top = box.y - lh - 22;
      if (place === 'below') top = box.y + box.height + 22;
      if (place === 'right') { left = box.x + box.width + 24; top = box.y + box.height / 2 - lh / 2; }
      if (top < 8) top = box.y + box.height + 22;
      left = Math.max(12, Math.min(left, window.innerWidth - lw - 12));
      top = Math.max(8, Math.min(top, window.innerHeight - lh - 8));
      Object.assign(label.style, { left: left + 'px', top: top + 'px' });
    },
    clearCallouts() { root().querySelectorAll('.__rec_callout').forEach((n) => n.remove()); },
    lower(text: string | null) {
      root().querySelectorAll('.__rec_lower').forEach((n) => n.remove());
      if (!text) return;
      const bar = el('div', { position: 'fixed', left: '48px', bottom: '56px', background: 'rgba(16,24,40,.92)', color: '#fff',
        font: '600 34px/1.2 system-ui, sans-serif', padding: '16px 28px', borderLeft: '10px solid #2f81f7', borderRadius: '6px', maxWidth: '1500px' }, text);
      bar.className = '__rec_lower';
      root().appendChild(bar);
    },
    term(open: boolean, label = 'Terminal', note = 'the request below is real: it runs against this local server') {
      root().querySelectorAll('.__rec_term').forEach((n) => n.remove());
      if (!open) return;
      const box = el('div', { position: 'fixed', left: '160px', right: '160px', top: '170px', bottom: '170px', background: '#0d1117', color: '#e6edf3',
        borderRadius: '14px', boxShadow: '0 20px 60px rgba(0,0,0,.55)', border: '1px solid #30363d', display: 'flex', flexDirection: 'column' });
      box.className = '__rec_term';
      const bar = el('div', { padding: '12px 18px', background: '#161b22', color: '#8b949e', font: '600 20px system-ui, sans-serif',
        borderRadius: '14px 14px 0 0' }, label + '  (' + note + ')');
      const pre = el('pre', { margin: '0', padding: '26px 30px', font: '26px/1.5 ui-monospace, Menlo, monospace', whiteSpace: 'pre-wrap',
        wordBreak: 'break-all', overflow: 'hidden', flex: '1' });
      pre.id = '__rec_term_pre';
      box.append(bar, pre);
      root().appendChild(box);
    },
    termText(text: string) { const p = document.getElementById('__rec_term_pre'); if (p) p.textContent = text; },
    title(lines: string[]) {
      const card = el('div', { position: 'fixed', inset: '0', background: 'linear-gradient(135deg,#0b1220,#16335f)', color: '#fff', display: 'flex',
        flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: '30px', textAlign: 'center', padding: '0 160px' });
      card.className = '__rec_title';
      lines.forEach((l, i) => card.appendChild(el('div', { font: i === 0 ? '700 96px system-ui, sans-serif' : '500 44px/1.3 system-ui, sans-serif' }, l)));
      root().appendChild(card);
    },
    clearTitle() { root().querySelectorAll('.__rec_title').forEach((n) => n.remove()); },
    endcard(lines: string[]) {
      const card = el('div', { position: 'fixed', inset: '0', background: 'rgba(11,18,32,.94)', color: '#fff', display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center', gap: '28px', textAlign: 'center' });
      card.className = '__rec_end';
      lines.forEach((l, i) => card.appendChild(el('div', { font: i === 0 ? '700 64px system-ui, sans-serif' : '500 40px system-ui, sans-serif' }, l)));
      root().appendChild(card);
    },
  };
}

// ---------------------------------------------------------------------------------------------------------------------
// Human pacing helpers
// ---------------------------------------------------------------------------------------------------------------------
const pause = (page: Page, ms: number) => page.waitForTimeout(Math.max(0, Math.round(ms * curPace)));

/** Smoothly wheel-scroll until the locator's centre sits in the comfortable band of the viewport. */
async function reveal(page: Page, loc: Locator, band: [number, number] = [260, 760]) {
  await loc.first().waitFor({ state: 'attached' });
  await mmove(page, SIZE.width / 2, 600);
  let lastY = -1;
  for (let i = 0; i < 60; i++) {
    const box = await loc.first().boundingBox();
    if (!box) return;
    const c = box.y + box.height / 2;
    if (c >= band[0] && c <= band[1]) return;
    await page.mouse.wheel(0, c < band[0] ? -140 : 140);
    await pause(page, 70);
    const y = await page.evaluate(() => window.scrollY);
    if (y === lastY) return;   // already at the top or bottom of the page: the element cannot get any closer to the band
    lastY = y;
  }
}

async function mmove(page: Page, x: number, y: number, steps = 1) {
  mouse.x = x; mouse.y = y;
  await page.mouse.move(x, y, { steps });
}

/** Wait `ms`, drifting the cursor slowly (small circles) so the picture never sits perfectly still. */
async function idle(page: Page, ms: number) {
  const end = Date.now() + ms;
  let i = 0;
  while (end - Date.now() > 300) {
    const slice = Math.min(700, end - Date.now());
    i++;
    await page.mouse.move(mouse.x + 38 * Math.cos(i), mouse.y + 24 * Math.sin(i), { steps: 14 });
    await page.waitForTimeout(Math.max(0, slice - 250));
  }
  if (end - Date.now() > 0) await page.waitForTimeout(end - Date.now());
}

async function glide(page: Page, loc: Locator) {
  await reveal(page, loc);
  const box = await loc.first().boundingBox();
  if (!box) return;
  await mmove(page, box.x + box.width / 2, box.y + box.height / 2, Math.max(8, Math.round(30 * Math.min(1, curPace + 0.3))));
}

async function click(page: Page, loc: Locator, beforeMs = 450, afterMs = 900) {
  await glide(page, loc);
  await pause(page, beforeMs);
  await loc.first().click();
  await pause(page, afterMs);
}

async function type(page: Page, loc: Locator, text: string) {
  await glide(page, loc);
  await loc.first().click();
  await loc.first().pressSequentially(text, { delay: Math.round(85 * curPace) });
  await pause(page, 500);
}

/** Draw a callout on a locator for `ms`, then remove it. A missing element is reported, not fatal, unless `must`. */
async function callout(page: Page, loc: Locator, text: string, ms = 3200, place: 'above' | 'below' | 'right' = 'above', must = false) {
  if (!(await loc.count())) {
    if (must) throw new Error(`callout target missing for "${text}"`);
    console.warn(`[recorder] callout skipped (target not on screen): ${text}`);
    return;
  }
  await reveal(page, loc);
  const box = await loc.first().boundingBox();
  if (!box) return;
  await page.evaluate(([b, t, p]) => (window as any).__rec.callout(b, t, p), [box, text, place] as const);
  await page.waitForTimeout(Math.round(Math.max(ms * curPace, Math.min(ms, 2000) * PACE))); // a callout stays long enough to read
  await page.evaluate(() => (window as any).__rec.clearCallouts());
}

const lowerThird = (page: Page, text: string | null) => page.evaluate((t) => (window as any).__rec.lower(t), text);

/** What a scene body can wait for: the start of a spoken sentence (0-based) or the end of the narration. */
type Beats = { at: (cue: string) => Promise<void>; wander: (cue: string, ticks?: number) => Promise<void>; endOfNarration: () => Promise<void> };

const sceneLog: Record<string, { start: number; end: number; natural: number; hold: number; audio?: number; pace: number }> = {};

/**
 * Run a scene and pad it so it lasts at least the narration plus TAIL seconds (or the table's length when no narration timing
 * is given). Beats let the body line its actions up with what is being said; they only ever wait, never skip.
 */
async function scene(page: Page, n: number, name: string, seconds: number, body: (b: Beats) => Promise<void>) {
  curPace = PACE * (PACE_FACTORS[String(n)] ?? 1);
  const t0 = Date.now();
  console.log(`[recorder] scene ${n}: ${name}`);
  const timing = TIMING[String(n)];
  const waitUntil = async (secs: number, label = '') => {
    const wait = secs * 1000 * PACE - (Date.now() - t0);
    if (wait > 0) await idle(page, wait);
    else if (label && wait < -1500 * PACE) console.warn(`[recorder]   scene ${n}: ${label} is ${(-wait / 1000 / PACE).toFixed(1)} s late (lower this scene's factor in pace.json)`);
  };
  await body({
    // wait for the start of the spoken sentence that contains `cue` (text of narration.txt); a wrong anchor fails the run
    at: async (cue) => {
      if (!timing) return;
      const hit = timing.cues.find((c) => c.text.toLowerCase().includes(cue.toLowerCase()));
      if (!hit) throw new Error(`scene ${n}: no narrated sentence contains "${cue}" (narration.txt and record.spec.ts disagree)`);
      await waitUntil(LEAD + hit.start, `"${cue}"`);
    },
    // scroll the page gently down and up until the sentence that contains `cue` starts (so a long sentence is not read over a still picture)
    wander: async (cue, ticks = 120) => {
      if (!timing) return;
      const hit = timing.cues.find((c) => c.text.toLowerCase().includes(cue.toLowerCase()));
      if (!hit && cue !== 'END') throw new Error(`scene ${n}: no narrated sentence contains "${cue}"`);
      const target = (LEAD + (hit ? hit.start : timing.duration)) * 1000 * PACE;
      let dir = 1, k = 0;
      while (target - (Date.now() - t0) > 1400) {
        await page.mouse.wheel(0, dir * ticks);
        await page.waitForTimeout(600);
        if (++k % 3 === 0) dir = -dir;
      }
    },
    endOfNarration: async () => { if (timing) await waitUntil(LEAD + timing.duration); },
  });
  const natural = Date.now() - t0;
  const hold = timing ? timing.duration + LEAD + TAIL : seconds;
  await waitUntil(hold);
  sceneLog[String(n)] = { start: t0 / 1000, end: Date.now() / 1000, natural: natural / 1000 / PACE, hold, audio: timing?.duration, pace: curPace / PACE };
  console.log(`[recorder] scene ${n} done: body ${(natural / 1000).toFixed(1)} s, scene ${((Date.now() - t0) / 1000).toFixed(1)} s, narration ${timing ? timing.duration.toFixed(1) : '-'} s`);
}

async function toastText(page: Page, text: string | RegExp, timeout = 60_000) {
  await expect(page.locator('#toast')).toContainText(text, { timeout });
}

/** Type `text` into the terminal card (6 characters at a time) after what is already shown; returns the new full text. */
async function typeInTerm(page: Page, shown: string, text: string, delayMs = 110) {
  for (const chunk of text.match(/.{1,6}/gs) || []) {
    shown += chunk;
    await page.evaluate((t) => (window as any).__rec.termText(t), shown);
    await pause(page, delayMs);
  }
  return shown;
}
const showTerm = (page: Page, text: string) => page.evaluate((t) => (window as any).__rec.termText(t), text);

/** Real MCP calls (streamable HTTP, JSON-RPC) to /mcp with the given bearer token. */
async function mcpSession(playwright: any, token: string) {
  const api = await playwright.request.newContext();
  const base = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' };
  const parse = (text: string) => JSON.parse((text.split('\n').find((l) => l.startsWith('data:')) || 'data: {}').slice(5));
  const init = await api.post(BASE + '/mcp', { headers: base, data: { jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'tutorial-demo', version: '1' } } } });
  expect(init.ok(), 'MCP initialize').toBeTruthy();
  const headers = { ...base, 'mcp-session-id': init.headers()['mcp-session-id'] };
  await api.post(BASE + '/mcp', { headers, data: { jsonrpc: '2.0', method: 'notifications/initialized' } });
  let id = 1;
  return {
    async call(name: string, args: object) {
      const r = await api.post(BASE + '/mcp', { headers, data: { jsonrpc: '2.0', id: ++id, method: 'tools/call', params: { name, arguments: args } } });
      expect(r.ok(), `MCP ${name}`).toBeTruthy();
      return parse(await r.text()).result;
    },
    dispose: () => api.dispose(),
  };
}

// ---------------------------------------------------------------------------------------------------------------------
// Off-camera preparation: first-run setup, sign-in, tokens (secrets stay in this process)
// ---------------------------------------------------------------------------------------------------------------------
function readSetupCode(): string | undefined {
  if (process.env.SETUP_CODE) return process.env.SETUP_CODE;
  try {
    const log = fs.readFileSync(SETUP_LOG, 'utf8');
    const after = log.split('PagerLens first-run setup').pop() || '';
    return after.match(/\b[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}\b/)?.[0];
  } catch {
    return undefined;
  }
}

async function prepare(browser: Browser) {
  const password = process.env.ADMIN_PASSWORD;
  if (!password || password.length < 12) throw new Error('set ADMIN_PASSWORD to a throwaway of 12 or more characters');
  const ctx = await browser.newContext({ baseURL: BASE, viewport: SIZE });
  const api = ctx.request;
  const session = await (await api.get('/api/session')).json();
  if (session.state === 'setup_required') {
    const code = readSetupCode();
    if (!code) throw new Error(`no setup code: set SETUP_CODE or let SETUP_LOG (${SETUP_LOG}) hold the server's stderr`);
    const r = await api.post('/api/setup', { data: { code, password }, headers: CSRF });
    expect(r.ok(), 'first-run setup').toBeTruthy();
  }
  const login = await api.post('/api/login', { data: { password }, headers: CSRF });
  expect(login.ok(), 'sign in').toBeTruthy();
  const mk = async (name: string, scope: string) => {
    const r = await api.post('/api/tokens', { data: { name, scope }, headers: CSRF });
    expect(r.ok(), `create ${scope} token`).toBeTruthy();
    return (await r.json()).token as string;
  };
  const editorToken = await mk('editor', 'read');          // configured in the editor (scene 11), never shown
  const ingestToken = await mk('demo-sender', 'ingest');   // used by the ingest call of scene 10, never shown
  const state = await ctx.storageState();
  await ctx.close();
  return { state, ingestToken, editorToken };
}

const clip = (s: string, n = 94) => (s.length > n ? s.slice(0, n - 1) + '…' : s);

// ---------------------------------------------------------------------------------------------------------------------
// The recording
// ---------------------------------------------------------------------------------------------------------------------
test('record the PagerLens tutorial', async ({ browser, playwright, context }) => {
  fs.mkdirSync(OUT, { recursive: true });
  const { state, ingestToken, editorToken } = await prepare(browser);
  const up = await playwright.request.newContext();
  expect((await up.get(BASE + '/healthz')).ok(), `PagerLens answers at ${BASE}`).toBeTruthy();
  await up.dispose();

  await context.addCookies(state.cookies); // signed in before the camera rolls: the password is never on screen
  await context.addInitScript(installOverlay);
  const page = await context.newPage(); // the camera starts here, after setup, sign-in and token creation

  const nav = (tab: string) => page.locator(`#nav a[data-tab="${tab}"]`);
  const hypotheses = page.locator('section', { has: page.getByRole('heading', { name: 'Hypotheses' }) });

  // ---- 0  Title card (no narration) -------------------------------------------------------------------------------
  curPace = PACE;
  const tTitle = Date.now();
  await page.goto('/#dashboard');
  await expect(page.locator('.svc-card')).toHaveCount(5);
  await page.evaluate(() => (window as any).__rec.title(['PagerLens', 'From alert to confirmed cause: investigating incidents on Postgres with pgvector']));
  await page.waitForTimeout(3500 * PACE);
  await page.evaluate(() => (window as any).__rec.clearTitle());
  sceneLog['0'] = { start: tTitle / 1000, end: Date.now() / 1000, natural: 0, hold: 3.5, pace: 1 };

  // ---- 1  The dashboard ------------------------------------------------------------------------------------------
  await scene(page, 1, 'Dashboard', 30, async (b) => {
    for (const card of await page.locator('.svc-card').all()) {   // the cards while PagerLens is introduced
      const bx = await card.boundingBox();
      if (bx) await mmove(page, bx.x + bx.width / 2, bx.y + bx.height / 2, 25);
      await pause(page, 1500);
    }
    await b.at('It never changes your systems');
    await callout(page, page.locator('#nav'), 'Read-only by design', 2800, 'below');
    await b.at('It runs on plain Postgres');
    await lowerThird(page, 'PagerLens: Postgres + pgvector');
    await b.endOfNarration();
    await lowerThird(page, null);
  });

  // ---- 2  A service card -----------------------------------------------------------------------------------------
  await scene(page, 2, 'Service card', 30, async (b) => {
    const card = page.locator('.svc-card', { hasText: 'checkout-api' });
    await glide(page, card);
    await b.at('Look at checkout-api');
    await callout(page, card.getByText(/depends on/), 'Dependencies separate causes from victims', 3000, 'above');
    await b.at('That map matters later');
    await click(page, card, 400, 800);
    await expect(page).toHaveURL(/#service\/checkout-api/);
    for (let i = 0; i < 4; i++) { await page.mouse.wheel(0, 120); await pause(page, 500); }   // the charts
    await b.at('Everything here arrived');
    await page.goBack();
    await expect(page.locator('.svc-card')).toHaveCount(5);
    await b.at('The page refreshes');
    await callout(page, page.locator('#view-dashboard p', { hasText: /refreshes every 10 s/ }), 'Updates every 10 seconds', 2500, 'below');
  });

  // ---- 3  The Lab ------------------------------------------------------------------------------------------------
  await scene(page, 3, 'Lab: Break it', 40, async (b) => {
    await click(page, nav('lab'), 300, 400);
    await expect(page.getByRole('heading', { name: 'Lab', level: 1 })).toBeVisible();
    const bad = page.locator('article', { hasText: 'Bad release breaks checkout' });
    await b.wander('A bad release');
    await page.mouse.wheel(0, -2000);
    await b.at('A bad release');
    for (const art of (await page.locator('article', { has: page.getByRole('button', { name: 'Break it' }) }).all()).slice(0, 3)) {
      const bx = await art.boundingBox();
      if (bx) await mmove(page, bx.x + bx.width / 2, bx.y + bx.height / 2, 20);
      await pause(page, 900);
    }
    await b.at('The simulator writes');
    await page.mouse.wheel(0, 380);                              // the confusing mixes further down
    await pause(page, 1500);
    await b.at('It also keeps the true cause hidden');
    await callout(page, bad.locator('p.muted'), 'True cause is hidden', 3000, 'right');
    await b.at('I will pick the bad release');
    await click(page, bad.getByRole('button', { name: 'Break it' }), 400, 600);
    await b.at('It replaces the demo data');
    await callout(page, page.locator('dialog[open]'), 'Replaces the demo telemetry; incidents are kept', 3000, 'below');
    await b.at('Here is the new incident');
    await click(page, page.getByRole('button', { name: 'Continue' }), 300, 500);
    await expect(page).toHaveURL(/#incidents\/\d+/);
  });
  const firstIncidentUrl = page.url();

  // ---- 4  Investigate with Rules --------------------------------------------------------------------------------
  await scene(page, 4, 'Investigate (Rules)', 50, async (b) => {
    await expect(page.getByRole('button', { name: 'Investigate', exact: true })).toBeVisible();
    await glide(page, page.locator('.badge').first());           // the severity and status badges, the symptom
    await b.at('I will investigate it');
    await page.locator('#inv-mode').selectOption('rules');
    await expect(page.locator('#use-memory')).toBeChecked();
    await b.at('Rules means no model');
    await callout(page, page.locator('#inv-mode'), 'Rules: free and deterministic', 3000, 'below');
    await b.at("Let's run it");
    await click(page, page.getByRole('button', { name: 'Investigate', exact: true }), 300, 300);
    await toastText(page, 'Investigation finished');
    await b.at('That took seconds');
    await callout(page, page.getByRole('button', { name: /^Investigate/ }), 'Seconds, not minutes', 2000, 'below');
    await b.at('It asked read-only questions');
    await reveal(page, page.getByRole('heading', { name: 'Run viewer' }), [160, 300]);   // the steps table shows exactly those queries
    await b.at('Metrics, compared');
    for (let i = 0; i < 3; i++) { await page.mouse.wheel(0, 140); await pause(page, 700); }
    await b.at('The result is a ranked list');
    await reveal(page, hypotheses.locator('article.hyp').first(), [200, 600]);
    await callout(page, hypotheses.getByRole('heading', { name: 'Hypotheses' }), 'Ranked, each with a score', 3000, 'right');
  });
  // what the narration says: the release is the top hypothesis
  await expect(hypotheses.locator('article.hyp h3').first()).toContainText(/Release .* introduced the failure|deploy/i);
  await expect(hypotheses.locator('article.hyp h3').first()).toContainText('1.');

  // ---- 5  Evidence -----------------------------------------------------------------------------------------------
  await scene(page, 5, 'Evidence', 50, async (b) => {
    const top = hypotheses.locator('article.hyp').first();
    await reveal(page, top, [200, 560]);
    await b.at('Every line says');
    await callout(page, top.locator('.stance.supports').first(), 'Evidence for', 2500, 'right');
    await b.at('Open an evidence link');
    await click(page, top.getByRole('button', { name: /^evidence #\d+$/ }).first(), 400, 900);
    await expect(page.locator('.obs')).toBeVisible();
    await b.at('Here, a new error signature');
    await click(page, top.getByRole('button', { name: /^evidence #\d+$/ }).nth(1), 400, 700);   // the evidence for the new error signature
    await expect(page.locator('.obs')).toContainText(/error_signatures/);
    await b.at('The log text is untrusted');
    await callout(page, page.locator('.obs pre'), 'Log text is untrusted data, shown, never obeyed', 3500, 'above');
    await page.locator('.obs pre').first().hover();
    await b.at('It also checks the opposite');
    await click(page, page.locator('.obs').getByRole('button', { name: 'Close' }));
    const refutes = hypotheses.locator('.stance.refutes');
    if (await refutes.count()) await callout(page, refutes.first(), 'Evidence against', 3500, 'right');
    else console.warn('[recorder] no "refutes" line on this run; the narration sentence about refuting checks is generic');
  });

  // ---- 6  Report and run viewer --------------------------------------------------------------------------------
  await scene(page, 6, 'Report and Run viewer', 35, async (b) => {
    const reportHeading = page.getByRole('heading', { name: 'Report', level: 2 });
    await reveal(page, reportHeading, [200, 500]);
    await b.at('It holds the most likely cause');
    await callout(page, page.getByRole('heading', { name: /Most likely cause/ }), 'Most likely cause', 1800, 'right');
    await callout(page, page.getByRole('heading', { name: /Timeline/ }), 'Timeline (UTC)', 1800, 'right');
    await b.at('Copy it with one click');
    await click(page, page.getByRole('button', { name: 'Copy Markdown' }), 400, 500);
    await toastText(page, /copied|Copy failed/, 5000);
    await b.at('Below it, the run viewer');
    const runViewer = page.getByRole('heading', { name: 'Run viewer' });
    await reveal(page, runViewer, [200, 400]);
    await callout(page, runViewer, 'Every step is auditable', 3000, 'right');
    await b.at('The runbook steps');
    await callout(page, page.getByRole('heading', { name: /Suggested runbooks/ }), 'Manual steps only', 3000, 'right');
  });

  // ---- 7  The other methods and provider accounts ------------------------------------------------------------------
  await scene(page, 7, 'Methods and provider accounts', 35, async (b) => {
    const mode = page.locator('#inv-mode');
    await page.mouse.wheel(0, -4000);
    await pause(page, 800);
    await glide(page, mode);
    await b.at('The first is AI');
    await mode.selectOption('llm');
    await b.at('The second is Rules plus AI');
    await mode.selectOption('hybrid');
    await b.at('When they agree');
    await callout(page, mode, 'Agreement: confidence goes up', 2500, 'below');
    await b.at('When only the model believes');
    await callout(page, mode, 'Model alone: confidence is capped', 2500, 'below');
    await b.at('anything the model claims');
    await callout(page, page.locator('p.hint', { hasText: /checked before it counts/ }), 'Model claims are checked against real evidence', 2800, 'below');
    await b.at('To use a model');
    await callout(page, mode, 'AI and Rules + AI need a chat account', 2200, 'below');
    await click(page, nav('settings'), 300, 600);
    const accounts = page.locator('#settings-accounts');
    await reveal(page, accounts.getByRole('heading', { name: 'Provider accounts' }), [200, 400]);
    await b.at('Keys are stored encrypted');
    await click(page, accounts.getByRole('button', { name: 'Add account' }), 300, 500);
    const provider = page.locator('#af-provider');
    for (const label of ['OpenRouter', 'Custom']) {
      const value = await page.locator('#af-provider option', { hasText: label }).first().getAttribute('value');
      if (value) await provider.selectOption(value);
      await pause(page, 900);
    }
    await callout(page, page.locator('#af-key'), 'Stored encrypted, never shown again', 3000, 'below');
    await b.at('We have not measured');
    await lowerThird(page, 'AI accuracy on live models: not measured yet');
    await b.endOfNarration();
    await lowerThird(page, null);
    await click(page, page.locator('form.acct-form').getByRole('button', { name: 'Cancel' }), 300, 400);
    await page.goBack(); // the incident
    await expect(page).toHaveURL(firstIncidentUrl);
  });

  // ---- 8  AI investigation (stand-in model) ----------------------------------------------------------------------
  await scene(page, 8, 'AI investigation (Rules + AI) with the demo stand-in', 50, async (b) => {
    const mode = page.locator('#inv-mode');
    await mode.selectOption('hybrid');
    const account = page.locator('#inv-account');
    await expect(account).toBeVisible();
    await expect(account.locator('option')).not.toHaveCount(0);
    await b.at('I choose an account');
    await callout(page, account, 'The model uses the same read-only tools', 2800, 'below');
    await b.at('This one is a stand-in');
    await lowerThird(page, 'Demo stand-in model (scripts/fake_llm.py). With a real model the run reads the same');
    await b.at('It is not a real model');
    await b.wander('I press Investigate');
    await page.mouse.wheel(0, -2000);
    await b.at('I press Investigate');
    await click(page, page.getByRole('button', { name: /^Investigate/ }), 300, 300);
    await expect(page.getByRole('button', { name: /Investigating/ })).toBeVisible({ timeout: 5000 }).catch(() => {});
    await toastText(page, /Investigation finished|Finished with a warning/);
    await b.at("Each of the model");
    const runViewer = page.getByRole('heading', { name: 'Run viewer' });
    await reveal(page, runViewer, [160, 300]);
    await page.mouse.wheel(0, 300);
    await pause(page, 500);
    await callout(page, page.locator('code', { hasText: 'AI turn' }).first(), 'Every AI turn and tool call is recorded', 3000, 'right');
    await b.at('Then the two results');
    const top = hypotheses.locator('article.hyp').first();
    await reveal(page, top, [200, 560]);
    await b.at('The rules and the model both blame');
    await callout(page, top.locator('p.hint').first(), 'Rules and AI agree: confidence goes up', 3500, 'below');
    await b.endOfNarration();
    await lowerThird(page, null);
  });
  await expect(hypotheses.locator('article.hyp').first().locator('.badge.src')).toContainText(/Rules \+ AI|both/i);
  await expect(page.locator('code', { hasText: 'AI turn' }).first()).toBeVisible();

  // ---- 9  Close the loop, break it again, memory recalled --------------------------------------------------------
  await scene(page, 9, 'Close the loop and recall', 45, async (b) => {
    const closing = page.getByRole('heading', { name: 'Close the loop' });
    await reveal(page, closing, [200, 400]);
    await expect(page.locator('#rc-cat')).toHaveValue('bad_deploy');
    await b.at('I tell it the real cause');
    await type(page, page.locator('#rc-note'), 'rollback of v2.14.0 fixed it');
    await b.at('The incident is stored');
    await callout(page, page.getByRole('button', { name: 'Mark resolved' }), 'Only human-confirmed causes become memory', 2500, 'above');
    await click(page, page.getByRole('button', { name: 'Mark resolved' }), 300, 300);
    await toastText(page, 'Incident resolved and remembered', 15_000);
    await b.at('The simulator can reveal');
    await click(page, page.getByRole('button', { name: 'Reveal simulated answer' }), 300, 1200);
    await b.at('Now I break the same thing again');
    await click(page, nav('lab'), 300, 400);
    const bad = page.locator('article', { hasText: 'Bad release breaks checkout' });
    await click(page, bad.getByRole('button', { name: 'Break it' }), 300, 400);
    await click(page, page.getByRole('button', { name: 'Continue' }), 300, 400);
    await expect(page).toHaveURL(/#incidents\/\d+/);
    expect(page.url()).not.toBe(firstIncidentUrl);
    await expect(page.getByRole('button', { name: 'Investigate', exact: true })).toBeVisible();
    await page.locator('#inv-mode').selectOption('rules');
    await click(page, page.getByRole('button', { name: 'Investigate', exact: true }), 300, 300);
    await toastText(page, 'Investigation finished');
    const similar = page.getByRole('heading', { name: /Similar past incidents/ });
    await reveal(page, similar, [200, 450]);
    await b.at('The new report lists');
    await callout(page, similar, 'Recalled from pgvector', 3500, 'right');
  });
  // what the narration says: the earlier incident, and the cause it was resolved as, is in the second report
  const similarHeading = page.getByRole('heading', { name: /Similar past incidents/ });
  await expect(similarHeading).toBeVisible();
  await expect(page.locator('section.card', { has: similarHeading })).toContainText(/#\d+ HighErrorRate \(checkout-api\), resolved as bad_deploy/);

  // ---- 10  Send your own alert (terminal card) -----------------------------------------------------------------
  await scene(page, 10, 'Ingest an alert', 30, async (b) => {
    const cmd = `curl -sS -X POST ${BASE}/api/ingest/alerts \\\n  -H "Authorization: Bearer $PAGERLENS_TOKEN" -H "Content-Type: application/json" \\\n  -d '{"service":"demo-api","name":"HighErrorRate","summary":"5xx above 5%","severity":"sev2"}'`;
    await click(page, nav('dashboard'), 300, 500);               // the dashboard's "Send your own telemetry" help
    await b.at('Create an ingest token');
    const help = page.locator('details.help');
    await click(page, help.locator('summary'), 300, 700);
    await callout(page, help.locator('p.muted'), 'Ingest token: write-only', 3000, 'below');
    await b.at('Then post logs');
    await reveal(page, help.locator('pre'), [300, 700]);
    await b.at('Every log line is scrubbed');
    await callout(page, help.locator('p.muted'), 'Scrubbed before it is stored', 2800, 'below');
    await b.at('Here is one alert');
    await page.evaluate(() => (window as any).__rec.term(true, 'Terminal'));
    const shown = await typeInTerm(page, '$ ', cmd);
    await pause(page, 400);
    const api = await playwright.request.newContext();
    const res = await api.post(`${BASE}/api/ingest/alerts`, {
      headers: { Authorization: `Bearer ${ingestToken}`, 'Content-Type': 'application/json' },
      data: { service: 'demo-api', name: 'HighErrorRate', summary: '5xx above 5%', severity: 'sev2' },
    });
    const reply = await res.json();
    expect(reply.new_incident).toBe(true);
    await api.dispose();
    await b.at('The reply says');
    await showTerm(page, `${shown}\n\n${JSON.stringify(reply)}`);
    await lowerThird(page, 'Alert opened an incident');
    await b.at('And there it is');
    await page.evaluate(() => (window as any).__rec.term(false));
    await lowerThird(page, null);
    await click(page, nav('incidents'));
    const row = page.locator('tr', { hasText: 'demo-api' });
    await expect(row).toBeVisible();
    await callout(page, row, 'Alert opened an incident', 3000, 'above');
  });

  // ---- 11  Connect an editor over MCP --------------------------------------------------------------------------
  await scene(page, 11, 'Connect and MCP', 25, async (b) => {
    await click(page, nav('connect'), 300, 500);
    const client = page.locator('#client');
    const pick = async (label: string) => {
      const value = await page.locator('#client option', { hasText: label }).first().getAttribute('value');
      if (value) await client.selectOption(value);
    };
    await pick('Claude Code');
    await b.at('PagerLens speaks MCP');
    await callout(page, page.locator('#client-snippet'), 'Bearer token, read-only recommended', 2800, 'above');
    await b.at('Claude Code, VS Code and Cursor');
    await pick('VS Code'); await pause(page, 1200);
    await pick('Cursor'); await pause(page, 1200);
    await pick('Claude Code');
    await click(page, page.locator('#copy-snippet'), 300, 400);
    // The editor segment is drawn as a terminal card with REAL MCP calls (the read-only `editor` token against /mcp); the
    // assistant's own screen is not shown, and nothing below is invented: every line is built from the server's replies.
    await b.at('Here are real calls');
    const mcp = await mcpSession(playwright, editorToken);
    await page.evaluate(() => (window as any).__rec.term(true, 'MCP client', 'real MCP calls to this local server with the read-only editor token'));
    let shown = await typeInTerm(page, '$ ', `claude mcp add --transport http pagerlens ${BASE}/mcp \\\n    --header "Authorization: Bearer $PAGERLENS_TOKEN"\n\n`, 60);
    await b.at('It can list incidents');
    const listed = await mcp.call('list_incidents', { limit: 5 });
    const rows: any[] = (listed.content || []).map((c: any) => JSON.parse(c.text));
    expect(rows.length, 'MCP list_incidents returns the demo incidents').toBeGreaterThan(0);
    shown += `> list_incidents {"limit": 5}\n` + rows.map((r) => clip(`  #${r.id}  ${r.severity}  ${r.status}  ${r.service}  ${r.title}`)).join('\n') + '\n\n';
    await showTerm(page, shown);
    await pause(page, 1800);
    let target: any;
    for (const r of rows) {                                      // the newest incident that has been investigated
      const g = JSON.parse((await mcp.call('get_incident', { incident_id: r.id })).content[0].text);
      if (g?.hypotheses?.length) { target = g; break; }
    }
    expect(target, 'MCP get_incident finds an investigated incident').toBeTruthy();
    const h = target.hypotheses[0];
    const ev = (h.evidence || []).filter((e: any) => e.stance === 'supports').slice(0, 2);
    shown += `> get_incident {"incident_id": ${target.id}}\n  most likely cause: ${clip(h.title, 76)} (score ${Math.round(h.score * 100)}%)\n`
      + ev.map((e: any) => clip(`  supports: ${e.note}`)).join('\n') + '\n\n';
    await showTerm(page, shown);
    await b.at('But a read-only token');
    const refused = await mcp.call('add_note', { incident_id: target.id, note: 'tutorial: this write must be refused' });
    expect(refused.isError, 'a read token cannot write').toBeTruthy();
    shown += `> add_note {"incident_id": ${target.id}, "note": "..."}\n  ${clip(String(refused.content?.[0]?.text || '').replace(/^Error executing tool add_note: /, 'refused: '))}\n`;
    await showTerm(page, shown);
    await mcp.dispose();
    await b.at('In the wider ecosystem');
    await page.evaluate(() => (window as any).__rec.term(false));
    await lowerThird(page, 'Ecosystem: CityPulse and the simulator report in; the LLM gateway serves the models');
    await b.at('People sign in');
    await b.wander('END', 100);
    await b.endOfNarration();
    await lowerThird(page, null);
  });

  // ---- 12  Recap -------------------------------------------------------------------------------------------------
  await scene(page, 12, 'Recap', 25, async (b) => {
    await click(page, nav('dashboard'), 300, 500);
    await b.at('PagerLens collects telemetry');
    for (const card of await page.locator('.svc-card').all()) {   // the cards while the recap is spoken
      const bx = await card.boundingBox();
      if (bx) await mmove(page, bx.x + bx.width / 2, bx.y + bx.height / 2, 25);
      await pause(page, 1100);
    }
    await b.at('To try it');
    await page.evaluate(() => (window as any).__rec.term(true, 'Quick start', 'the commands from docs/GUIDE.md; shown, not run'));
    await typeInTerm(page, '', [
      '$ git clone <the PagerLens repository> && cd pagerlens',
      '$ docker compose up -d db',
      '$ pagerlens migrate',
      '$ pagerlens seed',
      '$ pagerlens serve          # then open the Lab and press Break it',
    ].join('\n'), 60);
    await b.at('The guide covers');
    await page.evaluate(() => (window as any).__rec.term(false));
    await page.evaluate(() => (window as any).__rec.endcard(['Guide: docs/GUIDE.md in the PagerLens repository', 'Break it. Investigate. Confirm the cause.']));
    await b.endOfNarration();
  });

  const video = page.video();
  await page.close(); // flushes the video
  const closedAt = Date.now() / 1000;
  fs.writeFileSync(path.join(OUT, 'scenes.json'), JSON.stringify({ closedAt, scenes: sceneLog }, null, 1));
  if (video) {
    const file = path.join(OUT, 'pagerlens-tutorial.webm');
    await video.saveAs(file);
    console.log(`[recorder] video: ${file}`);
  }
});
