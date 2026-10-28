import { test, expect, Page, Locator, Browser } from '@playwright/test';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import * as os from 'node:os';

/**
 * Records the on-screen part of the PagerLens customer video (docs/VIDEO-SCRIPT.md, scenes 1 to 12) with Playwright video.
 *
 * Problem first: a 3 a.m. incident, who-is-who (platform, scaffolding, sample app), the core investigation, then UNDER THE HOOD:
 * the real SQL of incident memory and runbook search, live updates with tcn, the slow query finding, database-enforced masking and
 * the Database insights tab with REAL output captured from the live AgentPG fleet (labelled as captured, never run here).
 *
 *   1920x1080, light theme, human pacing (moving cursor, smooth scrolling, typed text), callouts and lower-thirds. Output
 *   (git-ignored): docs/video/out/. Use docs/video/build.sh, which starts the whole stack (stack.sh) and the narration.
 *
 * Environment (nothing secret is stored in this file; secrets stay in the Playwright process):
 *   PAGERLENS_URL   default http://localhost:8000
 *   ADMIN_PASSWORD  required, throwaway, used off camera (setup and sign-in happen before the recording context exists)
 *   SETUP_CODE / SETUP_LOG   the first-run code, or the server's stderr log to read it from
 *   PSQL_BIN, PG_PORT        psql and the port of the local throwaway Postgres (the terminal cards run REAL psql against it)
 *   CAPTURES_DIR    folder with the real captures from the live AgentPG fleet (extensions-installed.txt, ecoctl-insights.txt)
 *   PACE            pause multiplier, default 1. HEADED=1 shows the browser.
 *
 * The recorder asserts what the narration claims: the Rules top hypothesis is the bad deploy, the AI run agrees, the second
 * report lists the first incident, the pgvector plan and lookups are real, the tcn notifications arrive and the list updates by
 * itself, the slow query evidence line appears, the read-only role is masked and denied, and the captures are present.
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
    term(open: boolean, label = 'Terminal', note = 'the request below is real: it runs against this local server', accent = '#3fb950', font = 26) {
      root().querySelectorAll('.__rec_term').forEach((n) => n.remove());
      if (!open) return;
      const box = el('div', { position: 'fixed', left: '110px', right: '110px', top: '120px', bottom: '120px', background: '#0d1117', color: '#e6edf3',
        borderRadius: '14px', boxShadow: '0 20px 60px rgba(0,0,0,.55)', border: '1px solid #30363d', display: 'flex', flexDirection: 'column' });
      box.className = '__rec_term';
      const bar = el('div', { padding: '12px 18px', background: '#161b22', color: accent, font: '700 22px system-ui, sans-serif',
        borderRadius: '14px 14px 0 0', borderBottom: '3px solid ' + accent }, label + '   |   ' + note);
      const pre = el('pre', { margin: '0', padding: '26px 30px', font: font + 'px/1.5 ui-monospace, Menlo, monospace', whiteSpace: 'pre-wrap',
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

    // ---- the problem card (staged: `step` panels are visible) and the who-is-who diagram (staged by group) ----------------------
    problem(step: number) {
      root().querySelectorAll('.__rec_prob').forEach((n) => n.remove());
      if (step < 0) return;
      const card = el('div', { position: 'fixed', inset: '0', background: 'linear-gradient(135deg,#1b0f12,#3a1219)', color: '#fff', display: 'flex',
        flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: '34px', padding: '0 120px' });
      card.className = '__rec_prob';
      card.appendChild(el('div', { font: '700 64px system-ui, sans-serif', color: '#ff9b8a' }, '03:07   ALERT: checkout error rate above 5%'));
      const row = el('div', { display: 'flex', gap: '36px' });
      [['Logs', 'in one tool'], ['Metrics', 'in another tool'], ['Runbooks', 'in a wiki']].forEach(([a, b], i) => {
        if (i + 1 > step) return;
        const box = el('div', { width: '480px', padding: '34px', border: '4px solid #ff9b8a', borderRadius: '16px', background: 'rgba(255,255,255,.07)', textAlign: 'center' });
        box.append(el('div', { font: '700 56px system-ui, sans-serif' }, a), el('div', { font: '500 38px system-ui, sans-serif', color: '#ffd0c7', marginTop: '10px' }, b));
        row.appendChild(box);
      });
      card.appendChild(row);
      if (step >= 4) card.appendChild(el('div', { font: '600 48px system-ui, sans-serif' }, 'Needed: the likely cause, in minutes.'));
      if (step >= 5) card.appendChild(el('div', { font: '600 48px system-ui, sans-serif', color: '#7ee787' }, 'Wanted: the next incident learns from this one.'));
      card.appendChild(el('div', { position: 'fixed', right: '40px', bottom: '28px', font: '500 24px system-ui, sans-serif', color: '#caa' }, 'Illustration of the problem, not product output'));
      root().appendChild(card);
    },
    diagram(visible: string[], hi: string | null) {
      root().querySelectorAll('.__rec_diag').forEach((n) => n.remove());
      if (!visible.length && !hi) return;
      const C: Record<string, [string, string]> = { platform: ['PLATFORM', '#1f6feb'], scaffold: ['REFERENCE SCAFFOLDING (swappable)', '#bf8700'], app: ['SAMPLE APP', '#2da44e'] };
      const card = el('div', { position: 'fixed', inset: '0', background: '#f6f8fa', color: '#1f2328', fontFamily: 'system-ui, sans-serif' });
      card.className = '__rec_diag';
      card.appendChild(el('div', { position: 'absolute', left: '0', right: '0', top: '34px', textAlign: 'center', font: '700 50px system-ui, sans-serif' }, 'Who is who in this demo'));
      const boxes: [string, string, string, string, number, number, number, number][] = [
        // id, group, title, detail, x, y, w, h
        ['signin', 'scaffold', 'Sign-in', 'any OpenID Connect provider that sends the roles the apps expect', 90, 150, 540, 190],
        ['gateway', 'scaffold', 'Model gateway', 'any OpenAI-compatible endpoint (the stand-in model in this video)', 690, 150, 540, 190],
        ['vault', 'scaffold', 'Secret vault', 'one small module of the shared kit; key from the platform', 1290, 150, 540, 190],
        ['watched', 'app', 'Apps it watches', 'the sample shop, CityPulse, other sample apps', 90, 430, 540, 190],
        ['pagerlens', 'app', 'PagerLens', 'the sample app: investigates incidents, remembers causes', 690, 430, 1140, 190],
        ['db', 'platform', 'Postgres on AgentPG (EDB)', 'the instance and its extensions: pgvector, pg_trgm, tcn, edb_stat_monitor, query_advisor; db-users; restricted MCP', 90, 710, 1740, 190],
      ];
      for (const [id, g, t, d, x, y, w, h] of boxes) {
        const on = visible.includes(id) || visible.includes(g) || hi === id || hi === g;
        const [label, col] = C[g];
        const box = el('div', { position: 'absolute', left: x + 'px', top: y + 'px', width: w + 'px', height: h + 'px', boxSizing: 'border-box', background: '#fff',
          border: (hi === id || hi === g ? 10 : 5) + 'px solid ' + col, borderRadius: '16px', padding: '16px 24px', opacity: on ? '1' : '0.0',
          boxShadow: hi === id || hi === g ? '0 0 30px ' + col : 'none' });
        box.append(el('div', { font: '700 22px system-ui, sans-serif', color: col, letterSpacing: '1px' }, label),
          el('div', { font: '700 38px system-ui, sans-serif', marginTop: '4px' }, t), el('div', { font: '500 26px/1.3 system-ui, sans-serif', color: '#57606a', marginTop: '6px' }, d));
        card.appendChild(box);
      }
      const leg = el('div', { position: 'absolute', left: '90px', right: '90px', bottom: '60px', display: 'flex', gap: '60px', justifyContent: 'center', font: '600 30px system-ui, sans-serif' });
      for (const k of ['platform', 'scaffold', 'app']) {
        const [label, col] = C[k];
        const chip = el('div', { display: 'flex', alignItems: 'center', gap: '14px' });
        chip.append(el('div', { width: '34px', height: '34px', borderRadius: '8px', background: col }), el('div', {}, label));
        leg.appendChild(chip);
      }
      card.appendChild(leg);
      root().appendChild(card);
    },
    textBox(needle: string, last = false) {   // screen box of a piece of text in the terminal card (all lines it covers)
      const p = document.getElementById('__rec_term_pre'); const node = p && p.firstChild; if (!node || !node.textContent) return null;
      const i = last ? node.textContent.lastIndexOf(needle) : node.textContent.indexOf(needle); if (i < 0) return null;
      const r = document.createRange(); r.setStart(node, i); r.setEnd(node, i + needle.length);
      const rects = Array.from(r.getClientRects()); if (!rects.length) return null;
      const x = Math.min(...rects.map((q) => q.left)), y = Math.min(...rects.map((q) => q.top));
      return { x, y, width: Math.max(...rects.map((q) => q.right)) - x, height: Math.max(...rects.map((q) => q.bottom)) - y };
    },
    lineBox(n: number, count = 1) {   // screen box of lines n..n+count-1 of the terminal card
      const p = document.getElementById('__rec_term_pre'); if (!p) return null;
      const r = p.getBoundingClientRect(); const fs = parseFloat(getComputedStyle(p).fontSize); const lh = fs * 1.5;
      return { x: r.left + 30, y: r.top + 26 + n * lh, width: r.width - 60, height: lh * count };
    },
    clearTitle() { root().querySelectorAll('.__rec_title').forEach((n) => n.remove()); },
    endcard(lines: string[], legend = true) {
      root().querySelectorAll('.__rec_end').forEach((n) => n.remove());
      const card = el('div', { position: 'fixed', inset: '0', background: 'rgba(11,18,32,.94)', color: '#fff', display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center', gap: '28px', textAlign: 'center' });
      card.className = '__rec_end';
      lines.forEach((l, i) => card.appendChild(el('div', { font: i === 0 ? '700 60px system-ui, sans-serif' : '500 38px system-ui, sans-serif' }, l)));
      const leg = el('div', { display: legend ? 'flex' : 'none', gap: '50px', marginTop: '20px', font: '600 30px system-ui, sans-serif' });
      for (const [label, col] of [['PLATFORM: Postgres on AgentPG (EDB)', '#1f6feb'], ['REFERENCE SCAFFOLDING: sign-in, gateway, vault', '#bf8700'], ['SAMPLE APP: PagerLens', '#2da44e']]) {
        const chip = el('div', { display: 'flex', alignItems: 'center', gap: '14px' });
        chip.append(el('div', { width: '30px', height: '30px', borderRadius: '8px', background: col }), el('div', {}, label));
        leg.appendChild(chip);
      }
      card.appendChild(leg);
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
  const ingestToken = await mk('demo-sender', 'ingest');   // used by the ingest calls (scene 8), never shown
  const metricsToken = await mk('scraper', 'metrics');     // used to read /metrics in scene 9, never shown
  const state = await ctx.storageState();
  await ctx.close();
  return { state, ingestToken, editorToken, metricsToken };
}

const clip = (s: string, n = 94) => (s.length > n ? s.slice(0, n - 1) + '…' : s);

// ---------------------------------------------------------------------------------------------------------------------
// The recording
// ---------------------------------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------------------------------
// Real database access for the terminal cards (psql against the local throwaway Postgres), real captures from the fleet
// ---------------------------------------------------------------------------------------------------------------------
const PSQL = process.env.PSQL_BIN || 'psql';
const PGPORT = process.env.PG_PORT || '5432';
const CAPTURES = process.env.CAPTURES_DIR || path.join(__dirname, '..', '..', '..', 'videos', 'live-captures');
const PSQL_ENV = { PATH: process.env.PATH || '', PSQLRC: '/dev/null', PAGER: 'cat', HOME: os.tmpdir() };
const psqlBase = (user: string) => ['-h', '127.0.0.1', '-p', PGPORT, '-U', user, 'pagerlens'];
/** The command line as it is shown on the card (the same arguments that are run). */
const psqlShown = (user: string, sql: string) => `$ psql -h 127.0.0.1 -p ${PGPORT} -U ${user} pagerlens -c "${sql}"`;
/** Run psql with one -c and return stdout + stderr (an error such as "permission denied" is the point of some cards). */
function psqlRun(user: string, sql: string): string {
  const r = spawnSync(PSQL, [...psqlBase(user), '-c', sql], { encoding: 'utf8', env: PSQL_ENV });
  return ((r.stdout || '') + (r.stderr || '')).replace(/\n+$/, '');
}
const psqlValue = (sql: string) => spawnSync(PSQL, [...psqlBase('postgres'), '-qtA', '-c', sql], { encoding: 'utf8', env: PSQL_ENV }).stdout.trim();

const readCapture = (file: string) => {
  const p = path.join(CAPTURES, file);
  if (!fs.existsSync(p)) throw new Error(`capture missing: ${p} (set CAPTURES_DIR)`);
  return fs.readFileSync(p, 'utf8');
};
/** One instance block of a capture: from the line that starts with `head` to the next blank line. */
const captureBlock = (text: string, head: string) => {
  const lines = text.split('\n');
  const i = lines.findIndex((l) => l.startsWith(head));
  if (i < 0) throw new Error(`capture block "${head}" not found`);
  const out: string[] = [];
  for (let j = i; j < lines.length && lines[j].trim() !== ''; j++) out.push(lines[j]);
  return out;
};

const calloutBox = async (page: Page, box: { x: number; y: number; width: number; height: number } | null, text: string, ms = 3000, place: 'above' | 'below' | 'right' = 'above') => {
  if (!box) return;
  await page.evaluate(([b, t, p]) => (window as any).__rec.callout(b, t, p), [box, text, place] as const);
  await page.waitForTimeout(Math.round(Math.max(ms * curPace, Math.min(ms, 2000) * PACE)));
  await page.evaluate(() => (window as any).__rec.clearCallouts());
};
const tbox = (page: Page, needle: string, last = false) => page.evaluate(([n, l]) => (window as any).__rec.textBox(n, l), [needle, last] as const);
const termOpen = (page: Page, label: string, note: string, accent = '#3fb950', font = 22) =>
  page.evaluate(([l, n, a, f]) => (window as any).__rec.term(true, l, n, a, f), [label, note, accent, font] as const);
const termClose = (page: Page) => page.evaluate(() => (window as any).__rec.term(false));

// ---------------------------------------------------------------------------------------------------------------------
// The recording
// ---------------------------------------------------------------------------------------------------------------------
test('record the PagerLens customer video', async ({ browser, playwright, context }) => {
  fs.mkdirSync(OUT, { recursive: true });
  const { state, ingestToken, editorToken, metricsToken } = await prepare(browser);
  const up = await playwright.request.newContext();
  expect((await up.get(BASE + '/healthz')).ok(), `PagerLens answers at ${BASE}`).toBeTruthy();
  await up.dispose();
  psqlValue('SELECT pg_stat_statements_reset()');   // the Database tab (scene 11) then shows only this recording's own traffic

  await context.addCookies(state.cookies); // signed in before the camera rolls: the password is never on screen
  await context.addInitScript(installOverlay);
  const page = await context.newPage(); // the camera starts here, after setup, sign-in and token creation

  const nav = (tab: string) => page.locator(`#nav a[data-tab="${tab}"]`);
  const hypotheses = page.locator('section', { has: page.getByRole('heading', { name: 'Hypotheses' }) });
  const runViewer = page.getByRole('heading', { name: 'Run viewer' });
  const investigateBtn = page.getByRole('button', { name: 'Investigate', exact: true });
  const R = (fn: string, ...a: any[]) => page.evaluate(([f, args]) => (window as any).__rec[f](...(args as any[])), [fn, a] as const);

  // ---- 0  Title card (no narration) -------------------------------------------------------------------------------
  curPace = PACE;
  const tTitle = Date.now();
  await page.goto('/#dashboard');
  await expect(page.locator('.svc-card')).toHaveCount(5);
  await R('title', ['PagerLens', 'Find the likely cause in minutes, and let the next incident learn: a sample app on Postgres with AgentPG']);
  await page.waitForTimeout(3500 * PACE);
  await R('clearTitle');
  sceneLog['0'] = { start: tTitle / 1000, end: Date.now() / 1000, natural: 0, hold: 3.5, pace: 1 };

  // ---- 1  The problem -------------------------------------------------------------------------------------------------
  await scene(page, 1, 'The problem', 20, async (b) => {
    await b.at('It is three in the morning');
    await R('problem', 0);
    await b.at('Your logs are in one tool');
    await R('problem', 1); await pause(page, 1300);
    await R('problem', 2); await pause(page, 1300);
    await R('problem', 3);
    await b.at('You need the likely cause');
    await R('problem', 4);
    await b.at('And you want the next incident');
    await R('problem', 5);
    await b.at('Here is how Postgres on AgentPG');
    await R('problem', -1);
    await lowerThird(page, 'PagerLens: one sample app, one Postgres');
    await b.endOfNarration();
    await lowerThird(page, null);
  });

  // ---- 2  Who is who (platform, scaffolding, sample app) --------------------------------------------------------------
  await scene(page, 2, 'Who is who', 40, async (b) => {
    await b.at('Who is who?');
    await R('diagram', ['app'], 'pagerlens');
    await b.at('Three things around it are scaffolding');
    await R('diagram', ['app', 'scaffold'], 'scaffold');
    await b.at('Sign-in works with any');
    await R('diagram', ['app', 'scaffold'], 'signin');
    await b.at('The gateway is any');
    await R('diagram', ['app', 'scaffold'], 'gateway');
    await b.at('The vault is one small module');
    await R('diagram', ['app', 'scaffold'], 'vault');
    await b.at('The platform part is Postgres');
    await R('diagram', ['app', 'scaffold', 'platform'], 'db');
    await b.endOfNarration();
    await R('diagram', ['app', 'scaffold', 'platform'], null);
  });

  // ---- 3  Break the shop and investigate with Rules -------------------------------------------------------------------
  await scene(page, 3, 'Break and investigate (Rules)', 50, async (b) => {
    await R('diagram', [], null);
    await click(page, nav('lab'), 300, 400);
    await expect(page.getByRole('heading', { name: 'Lab', level: 1 })).toBeVisible();
    const bad = page.locator('article', { hasText: 'Bad release breaks checkout' });
    await b.at('This is the Lab');
    for (const art of (await page.locator('article', { has: page.getByRole('button', { name: 'Break it' }) }).all()).slice(0, 3)) {
      const bx = await art.boundingBox();
      if (bx) await mmove(page, bx.x + bx.width / 2, bx.y + bx.height / 2, 20);
      await pause(page, 700);
    }
    await b.at('I pick a bad release');
    await click(page, bad.getByRole('button', { name: 'Break it' }), 400, 600);
    await b.at('An alert fires');
    await click(page, page.getByRole('button', { name: 'Continue' }), 300, 500);
    await expect(page).toHaveURL(/#incidents\/\d+/);
    await b.at('Now I ask why');
    await glide(page, page.locator('#inv-mode'));
    await b.at('I use the Rules method');
    await page.locator('#inv-mode').selectOption('rules');
    await expect(page.locator('#use-memory')).toBeChecked();
    await b.at('That is a fixed investigator');
    await callout(page, page.locator('#inv-mode'), 'Rules: no model, no cost', 2200, 'below');
    await click(page, investigateBtn, 200, 200);
    await toastText(page, 'Investigation finished');
    await b.at('Done, in seconds');
    await b.at('It asked read-only questions');
    await reveal(page, runViewer, [160, 300]);
    await b.at('Metrics against a baseline');
    await page.mouse.wheel(0, 140); await pause(page, 500);
    await b.at('And slow queries');
    await callout(page, page.getByText('slow_queries').first(), 'The new slow_queries step', 2600, 'right');
    await b.at('The answer is a ranked list');
    await reveal(page, hypotheses.locator('article.hyp').first(), [200, 600]);
    await callout(page, hypotheses.getByRole('heading', { name: 'Hypotheses' }), 'Ranked, each with a score', 2500, 'right');
  });
  const firstIncidentUrl = page.url();
  await expect(hypotheses.locator('article.hyp h3').first()).toContainText(/Release .* introduced the failure|deploy/i);
  await expect(hypotheses.locator('article.hyp h3').first()).toContainText('1.');

  // ---- 4  Evidence and report -----------------------------------------------------------------------------------------
  await scene(page, 4, 'Evidence and report', 35, async (b) => {
    const top = hypotheses.locator('article.hyp').first();
    await reveal(page, top, [200, 560]);
    await b.at('It says a release was deployed');
    await mmove(page, 900, 420, 20);
    await b.at('Every line is evidence');
    await callout(page, top.locator('.stance.supports').first(), 'Evidence for', 2400, 'right');
    await b.at('Open one, and you see');
    await click(page, top.getByRole('button', { name: /^evidence #\d+$/ }).first(), 400, 900);
    await expect(page.locator('.obs')).toBeVisible();
    await b.at('Here, a new error signature');
    await click(page, top.getByRole('button', { name: /^evidence #\d+$/ }).nth(1), 400, 700);
    await expect(page.locator('.obs')).toContainText(/error_signatures/);
    await b.at('Log text is untrusted');
    await callout(page, page.locator('.obs pre'), 'Log text is untrusted data: shown, never obeyed', 3000, 'above');
    await b.at('Below is the report');
    await click(page, page.locator('.obs').getByRole('button', { name: 'Close' }), 300, 300);
    await reveal(page, page.getByRole('heading', { name: 'Report', level: 2 }), [200, 500]);
    await callout(page, page.getByRole('heading', { name: /Most likely cause/ }), 'Markdown report', 1800, 'right');
    await b.at('The runbook steps are only');
    await callout(page, page.getByRole('heading', { name: /Suggested runbooks/ }), 'Manual steps only', 3000, 'right');
  });

  // ---- 5  AI investigation (stand-in model) ----------------------------------------------------------------------------
  await scene(page, 5, 'AI investigation (Rules + AI) with the demo stand-in', 40, async (b) => {
    const mode = page.locator('#inv-mode');
    await page.mouse.wheel(0, -4000);
    await pause(page, 600);
    await b.at('The method is Rules plus AI');
    await glide(page, mode);
    await mode.selectOption('hybrid');
    const account = page.locator('#inv-account');
    await expect(account).toBeVisible();
    await expect(account.locator('option')).not.toHaveCount(0);
    await b.at('Today the model is a stand-in');
    await lowerThird(page, 'DEMO STAND-IN model (scripts/fake_llm.py), not a real model');
    await b.at('So no key is needed');
    await callout(page, account, 'Same read-only tools, stand-in model', 2200, 'below');
    await click(page, page.getByRole('button', { name: /^Investigate/ }), 200, 200);
    await toastText(page, /Investigation finished|Finished with a warning/);
    await b.at('Each model turn shows up');
    await reveal(page, runViewer, [160, 300]);
    await page.mouse.wheel(0, 300);
    await pause(page, 400);
    await callout(page, page.locator('code', { hasText: 'AI turn' }).first(), 'Every AI turn and tool call is recorded', 2800, 'right');
    await b.at('Both answers blame the release');
    const top = hypotheses.locator('article.hyp').first();
    await reveal(page, top, [200, 560]);
    await callout(page, top.locator('p.hint').first(), 'Rules and AI agree: confidence goes up', 2800, 'below');
    await b.at('We have not measured accuracy');
    await lowerThird(page, 'AI accuracy on live models: not measured yet');
    await b.endOfNarration();
    await lowerThird(page, null);
  });
  await expect(hypotheses.locator('article.hyp').first().locator('.badge.src')).toContainText(/Rules \+ AI|both/i);

  // ---- 6  Memory: confirm the cause, break again, recalled --------------------------------------------------------------
  await scene(page, 6, 'Close the loop and recall', 45, async (b) => {
    const closing = page.getByRole('heading', { name: 'Close the loop' });
    await b.at('Now, the next incident should learn');
    await reveal(page, closing, [200, 400]);
    await expect(page.locator('#rc-cat')).toHaveValue('bad_deploy');
    await b.at('I confirm the real cause');
    await type(page, page.locator('#rc-note'), 'rollback of v2.14.0 fixed it');
    await b.at('PagerLens stores this incident');
    await click(page, page.getByRole('button', { name: 'Mark resolved' }), 300, 300);
    await toastText(page, 'Incident resolved and remembered', 15_000);
    await b.at('Now I break the same thing again');
    await click(page, nav('lab'), 250, 300);
    const bad = page.locator('article', { hasText: 'Bad release breaks checkout' });
    await click(page, bad.getByRole('button', { name: 'Break it' }), 250, 300);
    await click(page, page.getByRole('button', { name: 'Continue' }), 250, 300);
    await expect(page).toHaveURL(/#incidents\/\d+/);
    expect(page.url()).not.toBe(firstIncidentUrl);
    await expect(investigateBtn).toBeVisible();
    await page.locator('#inv-mode').selectOption('rules');
    await click(page, investigateBtn, 250, 250);
    await toastText(page, 'Investigation finished');
    const similar = page.getByRole('heading', { name: /Similar past incidents/ });
    await reveal(page, similar, [200, 450]);
    await b.at('The new report lists the earlier incident');
    await callout(page, similar, 'Recalled from Postgres with pgvector', 3000, 'right');
    await b.at('Nothing is learned from guesses');
    await b.endOfNarration();
  });
  await expect(page.locator('section.card', { has: page.getByRole('heading', { name: /Similar past incidents/ }) }))
    .toContainText(/#\d+ HighErrorRate \(checkout-api\), resolved as bad_deploy/);
  const newId = Number(psqlValue('SELECT max(id) FROM incident'));
  expect(newId).toBeGreaterThan(1);

  // ---- 7  Under the hood: incident memory (pgvector, HNSW) and runbook hybrid search ----------------------------------------
  await scene(page, 7, 'Under the hood: pgvector and hybrid search', 60, async (b) => {
    const D = 28;
    await b.at('Under the hood');
    await termOpen(page, 'Incident memory: SQL from src/pagerlens/retrieval.py (abridged), output from a real psql run',
      'local throwaway Postgres 17 with pgvector');
    let shown = await typeInTerm(page, '', [
      '-- similar_incidents(): which resolved incidents look like this one?',
      'SELECT i.id, i.root_cause_category,',
      '       1 - (i.embedding <=> :vec) AS similarity     -- <=> is the pgvector cosine distance',
      'FROM incident i',
      "WHERE i.status = 'resolved' AND i.embedding IS NOT NULL",
      'ORDER BY i.embedding <=> :vec',
      'LIMIT 5;'].join('\n'), D);
    await b.at('It sorts resolved incidents');
    await calloutBox(page, await tbox(page, '1 - (i.embedding <=> :vec) AS similarity'), 'pgvector: cosine distance', 2600, 'right');
    await b.at('An HNSW index serves');
    const idxSql = "SELECT indexdef FROM pg_indexes WHERE indexname IN ('incident_embedding', 'runbook_embedding', 'runbook_tsv') ORDER BY indexname";
    shown = await typeInTerm(page, shown, `\n\n${psqlShown('postgres', idxSql)}\n`, D);
    await b.at('These are the real index definitions');
    const idxOut = psqlRun('postgres', idxSql);
    expect(idxOut).toContain('USING hnsw (embedding vector_cosine_ops)');
    shown += idxOut;
    await showTerm(page, shown);
    await calloutBox(page, await tbox(page, 'USING hnsw (embedding vector_cosine_ops)'), 'HNSW index on the vectors', 2600, 'above');
    await b.at('Here is a real query plan');
    const planSql = `SET enable_seqscan = off; EXPLAIN SELECT id FROM incident ORDER BY embedding <=> (SELECT embedding FROM incident WHERE id = ${newId}) LIMIT 5`;
    const plan = psqlRun('postgres', planSql);
    shown = await typeInTerm(page, '', `${psqlShown('postgres', planSql)}\n`, D);
    shown += plan;
    await showTerm(page, shown);
    expect(plan, 'with sequential scans off the plan of the nearest-neighbour query uses the HNSW index').toContain('Index Scan using incident_embedding');
    await calloutBox(page, await tbox(page, 'Index Scan using incident_embedding on incident'), 'The plan uses the HNSW index', 2800, 'below');
    await b.at('And here is the real lookup');
    const lookup = `SELECT b.id, b.root_cause_category AS cause,\n       round((1 - (a.embedding <=> b.embedding))::numeric, 3) AS similarity\nFROM incident a, incident b\nWHERE a.id = ${newId} AND b.status = 'resolved'\nORDER BY a.embedding <=> b.embedding LIMIT 5`;
    const found = psqlRun('postgres', lookup);
    expect(found).toContain('bad_deploy');
    shown = await typeInTerm(page, '', `${psqlShown('postgres', lookup)}\n`, D);
    shown += found;
    await showTerm(page, shown);
    await b.at('The earlier one comes back');
    await calloutBox(page, await tbox(page, 'bad_deploy'), 'The confirmed earlier incident, with similarity', 2800, 'below');
    await b.at('Runbooks use a hybrid search');
    await termClose(page);
    await termOpen(page, 'Runbook search: SQL from src/pagerlens/retrieval.py (abridged), result from a real call to this app', 'local throwaway Postgres 17');
    shown = await typeInTerm(page, '', [
      '-- search_runbooks(): full-text and vector search in ONE query',
      'WITH vec AS (SELECT id, row_number() OVER (ORDER BY embedding <=> :vec) AS r',
      '             FROM runbook ORDER BY embedding <=> :vec LIMIT 20),   -- pgvector, HNSW index',
      '     lex AS (SELECT id, row_number() OVER (ORDER BY ts_rank(tsv, q) DESC) AS r',
      "             FROM runbook, websearch_to_tsquery('english', :q) q",
      '             WHERE tsv @@ q LIMIT 20),                             -- full-text, GIN index',
      '     fused AS (SELECT COALESCE(vec.id, lex.id) AS id,',
      '                      COALESCE(1.0/(60+vec.r),0) + COALESCE(1.0/(60+lex.r),0) AS score',
      '               FROM vec FULL OUTER JOIN lex ON vec.id = lex.id)     -- reciprocal rank fusion',
      'SELECT r.title, f.score FROM fused f JOIN runbook r ON r.id = f.id ORDER BY f.score DESC LIMIT 3;'].join('\n'), 12);
    await b.at('One query runs full-text');
    await calloutBox(page, await tbox(page, '-- search_runbooks(): full-text and vector search in ONE query'), 'Vector search + full-text search, fused', 3000, 'right');
    await b.at('Here is the real result');
    const mcp = await mcpSession(playwright, editorToken);
    const rb = await mcp.call('search_runbooks', { query: 'checkout errors after a release', limit: 3 });
    await mcp.dispose();
    const rows: any[] = (rb.content || []).map((c: any) => JSON.parse(c.text));
    expect(rows.length, 'search_runbooks returns runbooks').toBeGreaterThan(0);
    shown += `\n\n> search_runbooks {"query": "checkout errors after a release"}   (real MCP call to this app)\n`
      + rows.map((r, i) => clip(`  ${i + 1}. ${r.title}  [${r.category}]`, 100)).join('\n');
    await showTerm(page, shown);
    await calloutBox(page, await tbox(page, rows[0].title.slice(0, 30)), 'Best runbooks for the symptom', 2800, 'below');
    await b.endOfNarration();
    await termClose(page);
  });

  // ---- 8  Live updates with tcn -----------------------------------------------------------------------------------------
  await scene(page, 8, 'tcn live updates', 50, async (b) => {
    const D = 30;
    const alertBody = (service: string) => ({ service, name: 'HighErrorRate', summary: '5xx above 5%', severity: 'sev2' });
    const curl = (service: string) => `$ curl -sS -X POST ${BASE}/api/ingest/alerts \\\n    -H "Authorization: Bearer $PAGERLENS_TOKEN" -H "Content-Type: application/json" \\\n    -d '${JSON.stringify(alertBody(service))}'`;
    await b.at('Next, live updates');
    await click(page, nav('incidents'), 300, 500);
    await expect(page.locator('table')).toBeVisible();
    await b.at('The tcn extension makes');
    await lowerThird(page, 'tcn: Postgres sends NOTIFY on every incident and alert row change');
    await b.at('Here I listen to that channel');
    await lowerThird(page, null);
    await termOpen(page, 'psql LISTEN pl_changes: a real session on the local database', 'tcn = triggered change notification');
    // a real psql session: LISTEN, then an empty query every half second so psql prints any notification it has received
    const ps = spawn(PSQL, ['-qtA', ...psqlBase('postgres')], { env: PSQL_ENV });
    let out = '';
    ps.stdout.on('data', (d) => { out += d.toString(); });
    ps.stderr.on('data', (d) => { out += d.toString(); });
    ps.stdin.write('LISTEN pl_changes;\n');
    const tick = setInterval(() => { try { ps.stdin.write('SELECT 1 WHERE false;\n'); } catch { /* closed */ } }, 400);
    let shown = await typeInTerm(page, '', `$ psql -qtA -h 127.0.0.1 -p ${PGPORT} -U postgres pagerlens\nLISTEN pl_changes;\n(waiting for notifications)\n\n`, D);
    await b.at('Now I send an alert');
    shown += '-- in a second terminal --\n';
    shown = await typeInTerm(page, shown, curl('demo-api') + '\n', D);
    const api = await playwright.request.newContext();
    const res = await api.post(`${BASE}/api/ingest/alerts`, { headers: { Authorization: `Bearer ${ingestToken}`, 'Content-Type': 'application/json' }, data: alertBody('demo-api') });
    const reply = await res.json();
    expect(reply.new_incident).toBe(true);
    shown += JSON.stringify(reply) + '\n\n-- back in the psql session --\n';
    await showTerm(page, shown);
    const t0 = Date.now();
    while (!/"alert",I/.test(out) && Date.now() - t0 < 8000) await page.waitForTimeout(150);
    clearInterval(tick);
    const notes = out.split('\n').filter((l) => l.startsWith('Asynchronous notification'));
    expect(notes.length, 'tcn sent a notification for the incident and the alert').toBeGreaterThanOrEqual(2);
    expect(notes.join('\n')).toContain('"incident",I');
    shown += notes.map((l) => l.replace(/ received from server process with PID \d+\./, ' ...')).join('\n');
    await showTerm(page, shown);
    ps.stdin.end();
    await b.at('Two notifications arrive');
    await calloutBox(page, await tbox(page, 'Asynchronous notification'), 'One row change = one notification', 2400, 'above');
    await b.at('The payload is only a table');
    await calloutBox(page, await tbox(page, 'with payload'), 'Table, operation, row id. No row contents', 2800, 'above');
    await b.at('The app holds one listening connection');
    await termClose(page);
    await lowerThird(page, 'One LISTEN connection in the app, pushed to every browser as server-sent events');
    await expect(page.locator('tr', { hasText: 'demo-api' })).toBeVisible();
    await b.at('Watch the list');
    await lowerThird(page, null);
    await mmove(page, 960, 700, 20);
    await b.at('I send an alert for another service');
    const tPost = Date.now();
    const r2 = await api.post(`${BASE}/api/ingest/alerts`, { headers: { Authorization: `Bearer ${ingestToken}`, 'Content-Type': 'application/json' }, data: alertBody('demo-worker') });
    expect((await r2.json()).new_incident).toBe(true);
    await api.dispose();
    const row = page.locator('tr', { hasText: 'demo-worker' });
    await expect(row).toBeVisible({ timeout: 6000 });   // the list polls every 20 s: it appeared through the SSE stream, not by a timer
    console.log(`[recorder] the new row appeared ${(Date.now() - tPost) / 1000} s after the alert, with no reload`);
    expect(Date.now() - tPost).toBeLessThan(6000);
    await b.at('The new incident appears by itself');
    await callout(page, row, 'Appeared by itself: no reload, no polling', 3000, 'above');
    await b.endOfNarration();
  });

  // ---- 9  The slow query story (dogfooding) -----------------------------------------------------------------------------
  await scene(page, 9, 'Slow query', 60, async (b) => {
    const D = 30;
    await b.at('Now a quieter failure');
    await click(page, nav('lab'), 300, 400);
    const slow = page.locator('article', { hasText: 'A query regression slows inventory' });
    await glide(page, slow);
    await b.at('Every app on the kit exports');
    await termOpen(page, 'The gauge every kit app exports on /metrics: real output from this local PagerLens', 'source here: pg_stat_statements; on AgentPG: edb_stat_monitor');
    const m = await playwright.request.newContext();
    const metrics = await (await m.get(`${BASE}/metrics`, { headers: { Authorization: `Bearer ${metricsToken}` } })).text();
    await m.dispose();
    const gauge = metrics.split('\n').filter((l) => l.startsWith('db_insights_top_query_mean_seconds{')).slice(0, 4);
    expect(gauge.length, 'the gauge is exported').toBeGreaterThan(0);
    let shown = await typeInTerm(page, '', `$ curl -s ${BASE}/metrics -H "Authorization: Bearer $PAGERLENS_TOKEN" \\\n    | grep ^db_insights_top_query_mean_seconds\n`, D);
    await b.at('On this local Postgres it comes from');
    shown += gauge.join('\n');
    await showTerm(page, shown);
    await b.at('This is the real gauge');
    await calloutBox(page, await tbox(page, 'db_insights_top_query_mean_seconds{'), 'Mean seconds of a slow statement, per queryid', 2800, 'below');
    await b.at("PagerLens's agent scrapes it");
    await termClose(page);
    await lowerThird(page, 'pagerlens-agent: scrape /metrics, keep each statement\'s history, alert when it is 3x slower');
    await b.at('The Lab scenario writes the points');
    await lowerThird(page, 'Lab: writes the points the agent would have pushed (synthetic values)');
    await click(page, slow.getByRole('button', { name: 'Break it' }), 300, 500);
    await click(page, page.getByRole('button', { name: 'Continue' }), 250, 400);
    await expect(page).toHaveURL(/#incidents\/\d+/);
    await b.at('I break it, and investigate');
    await lowerThird(page, null);
    await page.locator('#inv-mode').selectOption('rules');
    await click(page, investigateBtn, 250, 250);
    await toastText(page, 'Investigation finished');
    await b.at('The top cause is a query');
    const top = hypotheses.locator('article.hyp').first();
    await reveal(page, top, [200, 520]);
    await expect(top.locator('h3').first()).toContainText(/slower/);
    await callout(page, top.locator('h3').first(), 'Top cause: Slow query', 2600, 'below');
    await b.at('The evidence names the query');
    const evText = await top.innerText();
    const ev = evText.match(/query \S+ on inventory-api: mean [\d.]+ ms before, [\d.]+ ms now \(x[\d.]+\)/);
    expect(ev, 'the slow query evidence line is shown').toBeTruthy();
    console.log(`[recorder] evidence: ${ev![0]}`);
    const supports = top.getByText(/ms before, .* ms now/).first();
    await callout(page, supports, ev![0].replace(/^query \S+ on inventory-api: /, ''), 3600, 'below');
    await b.at('The statement text itself');
    await click(page, nav('insights'), 300, 600);
    await expect(page.locator('#view-insights')).toContainText(/pg_stat_statements/, { timeout: 15_000 });
    await callout(page, page.locator('#view-insights table').first(), 'Statement text, by queryid', 3000, 'above');
    await b.endOfNarration();
  });

  // ---- 10  Database-enforced masking for a read-only user -------------------------------------------------------------------
  await scene(page, 10, 'Masking for a read-only user', 50, async (b) => {
    const D = 35;
    const owner = await playwright.request.newContext({ storageState: state, extraHTTPHeaders: CSRF });
    const note = await owner.post(`${BASE}/api/incidents/${newId}/notes`, { data: { body: 'Paged jordan.rivera@example.com, rollback in progress' } });
    expect(note.ok(), 'note for the masking card').toBeTruthy();
    await owner.dispose();
    await b.at('Now, who may read this data');
    await termOpen(page, 'Two database users on the same local database: the owner, and a read-only member of the group role a1p_readonly', 'real psql runs');
    let shown = await typeInTerm(page, '', '# what a read-only user or an assistant should see: incidents, but no personal data and no secrets\n', D);
    await b.at('On AgentPG, a read-only user comes');
    shown = await typeInTerm(page, shown, '\n# on AgentPG:  agentpg db-users create --permission read      (not run here)\n', D);
    await b.at('Locally, I created a role');
    shown = await typeInTerm(page, shown, '# here: pl_reader, a member of a1p_readonly, made the same way (LOGIN IN ROLE a1p_readonly)\n\n', D);
    await b.at('As the owner, a note holds');
    const q1 = 'SELECT author, body FROM incident_note ORDER BY id DESC LIMIT 1';
    const o1 = psqlRun('postgres', q1);
    expect(o1).toContain('jordan.rivera@example.com');
    shown = await typeInTerm(page, shown, `${psqlShown('postgres', q1)}\n`, D) + o1 + '\n\n';
    await showTerm(page, shown);
    await b.at('As the read-only role, the masked view');
    const q2 = 'SELECT author, body FROM incident_note_masked ORDER BY id DESC LIMIT 1';
    const o2 = psqlRun('pl_reader', q2);
    expect(o2).toContain('[EMAIL]');
    expect(o2).not.toContain('jordan.rivera');
    shown = await typeInTerm(page, shown, `${psqlShown('pl_reader', q2)}\n`, D) + o2 + '\n\n';
    await showTerm(page, shown);
    await calloutBox(page, await tbox(page, '[EMAIL]'), 'Author as an initial, e-mail removed', 2600, 'below');
    await b.at('The base table is denied');
    const q3 = 'SELECT title FROM incident LIMIT 1';
    const o3 = psqlRun('pl_reader', q3);
    expect(o3).toContain('permission denied');
    shown = await typeInTerm(page, '', `${psqlShown('pl_reader', q3)}\n`, D) + o3 + '\n\n';
    await showTerm(page, shown);
    await b.at('A write is denied too');
    const q4 = "UPDATE incident SET status = 'resolved'";
    const o4 = psqlRun('pl_reader', q4);
    expect(o4).toContain('permission denied');
    shown = await typeInTerm(page, shown, `${psqlShown('pl_reader', q4)}\n`, D) + o4 + '\n\n';
    await showTerm(page, shown);
    await b.at('And the tables with secrets');
    const q5 = 'SELECT * FROM api_token';
    const o5 = psqlRun('pl_reader', q5);
    expect(o5).toContain('permission denied');
    shown = await typeInTerm(page, shown, `${psqlShown('pl_reader', q5)}\n`, D) + o5 + '\n';
    await showTerm(page, shown);
    await b.at('Postgres enforces this');
    await calloutBox(page, await tbox(page, 'permission denied for table api_token'), 'Enforced by the database, not by application code', 3000, 'above');
    await b.endOfNarration();
    await termClose(page);
  });

  // ---- 11  Database insights: local pg_stat_statements, REAL captured output from the AgentPG fleet ------------------------
  await scene(page, 11, 'Database insights', 50, async (b) => {
    const D = 25;
    const exts = captureBlock(readCapture('extensions-installed.txt'), '# pagerlens (');
    const recs = captureBlock(readCapture('ecoctl-insights.txt'), 'pagerlens (');
    const footer = readCapture('ecoctl-insights.txt').split('\n').find((l) => l.startsWith('Read-only:')) || '';
    expect(exts.join('\n')).toContain('edb_stat_monitor');
    expect(exts.join('\n')).toContain('query_advisor');
    expect(recs.join('\n')).toContain('CREATE INDEX ON public.alert');
    await b.at('One more place to look');
    await click(page, nav('insights'), 300, 600);
    await expect(page.locator('#view-insights')).toContainText(/pg_stat_statements/, { timeout: 15_000 });
    await b.at('On this local Postgres it shows only');
    await callout(page, page.locator('#view-insights table').first(), 'Local Postgres: pg_stat_statements only', 3200, 'above');
    await b.at('On AgentPG, the same page also shows');
    await lowerThird(page, 'On AgentPG the same page also shows edb_stat_monitor, edb_pg_tuner (where installed) and query_advisor');
    await b.at('I cannot show that page here');
    await lowerThird(page, null);
    await termOpen(page, 'CAPTURED from our live AgentPG fleet on 2026-10-28, not run now: agentpg extensions list', 'real capture, videos/live-captures', '#d29922');
    await typeInTerm(page, '', exts.join('\n'), D);
    await b.at("PagerLens's instance has");
    await calloutBox(page, await tbox(page, 'edb_stat_monitor'), 'EDB query monitoring', 2200, 'right');
    await calloutBox(page, await tbox(page, 'query_advisor'), 'EDB index advisor', 2200, 'right');
    await b.at('And query_advisor already suggests');
    await termClose(page);
    await termOpen(page, 'CAPTURED from our live AgentPG fleet on 2026-10-28, not run now: ecoctl insights (runs agentpg recommend)', 'real capture, videos/live-captures', '#d29922', 20);
    await typeInTerm(page, '', recs.join('\n') + '\n\n' + footer, D);
    await calloutBox(page, await tbox(page, 'CREATE INDEX ON public.alert'), 'query_advisor: an index for the alert table', 2800, 'above');
    await b.at('It only suggests');
    await calloutBox(page, await tbox(page, 'Read-only: nothing was changed'), 'Suggestions only: nothing is changed', 2600, 'above');
    await b.endOfNarration();
    await termClose(page);
  });

  // ---- 12  Try it yourself ----------------------------------------------------------------------------------------------
  await scene(page, 12, 'Try it yourself', 25, async (b) => {
    await click(page, nav('dashboard'), 100, 100);
    await b.at('Try it yourself');
    await termOpen(page, 'Try it yourself (shown, not run)', 'from docs/GUIDE.md', '#58a6ff', 28);
    await typeInTerm(page, '', [
      '# needs a Postgres with pgvector and tcn',
      '$ pagerlens migrate',
      '$ pagerlens seed',
      '$ pagerlens serve          # then open the Lab and press Break it'].join('\n'), 35);
    await b.at('Then open the Lab');
    await b.at('The guide is in the docs folder');
    await termClose(page);
    await R('endcard', ['Guide: docs/GUIDE.md, section 15: EDB and AgentPG capabilities used by this app'], false);
    await b.at('Next, try the slow query');
    await R('endcard', ['Guide: docs/GUIDE.md, section 15: EDB and AgentPG capabilities used by this app', 'Next: the slow_query scenario in the Lab, and the Database tab'], false);
    await b.at('The end card repeats the legend');
    await R('endcard', ['Guide: docs/GUIDE.md, section 15: EDB and AgentPG capabilities used by this app', 'Next: the slow_query scenario in the Lab, and the Database tab'], true);
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
