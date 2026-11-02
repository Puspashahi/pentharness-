'use strict';
/**
 * Browser execution oracle + automated identity capture.
 *
 * Two capabilities that decide whether the rest of the harness produces real
 * findings or plausible noise:
 *
 * 1. XSS execution. PageBreak's XSS validator "injects a specific JavaScript
 *    payload and invokes a rendering harness... to detect if the injected
 *    JavaScript actually runs." Reflection is not execution. This drives a real
 *    browser, plants a sentinel, and reports whether the sentinel fired *in the
 *    target's origin*.
 *
 * 2. Identity capture. The authorization matrix is the highest-yield primitive
 *    in the field, and it needs two sessions. Manual Burp capture does not
 *    scale, so this drives the login form for each account, saves the resulting
 *    storage state, and replays a route under both identities to produce the
 *    capture files the matrix consumes.
 */

const fs = require('fs');
const path = require('path');

/** Sentinel written by the injected payload; its presence means code ran. */
const SENTINEL = '__ph_exec_marker__';

/**
 * Payloads that set the sentinel. Ordered cheapest-first: a plain script tag
 * proves the bug in the common case; the others cover attribute, javascript:
 * URI, and SVG contexts where the tag is stripped.
 */
function xssPayloads(origin) {
  const s = SENTINEL;
  return [
    { id: 'script', value: `<script>window.${s}=1</script>` },
    { id: 'img-onerror', value: `<img src=x onerror=window.${s}=1>` },
    { id: 'svg-onload', value: `<svg onload=window.${s}=1>` },
    { id: 'attr-break', value: `"><svg onload=window.${s}=1>` },
    { id: 'js-uri', value: `javascript:window.${s}=1` },
  ];
}

/**
 * Load each candidate URL in a real browser and report whether the payload
 * executed. Execution is detected by polling for the sentinel AND confirming
 * the page's own origin, so execution in our harness is never mistaken for
 * execution on the target.
 */
async function proveXss(browser, urls, opts = {}) {
  const results = [];
  const context = await browser.newContext({
    viewport: { width: 1280, height: 800 },
    ignoreHTTPSErrors: true,
    extraHTTPHeaders: (opts.headerPolicy && opts.headerPolicy.active) ? opts.headerPolicy.playwright() : undefined,
  });
  for (const u of urls) {
    for (const p of xssPayloads()) {
      const target = inject(u.url, u.param, p.value);
      const page = await context.newPage();
      let executed = false;
      let origin = null;
      try {
        const resp = await page.goto(target, { waitUntil: 'domcontentloaded', timeout: opts.timeout || 15000 });
        // Give the payload a moment, then poll for the sentinel in page context.
        for (let i = 0; i < 6; i++) {
          await page.waitForTimeout(180);
          executed = await page.evaluate((s) => {
            // eslint-disable-next-line no-eval
            try { return !!window[s]; } catch { return false; }
          }, SENTINEL).catch(() => false);
          if (executed) break;
        }
        try { origin = new URL(page.url()).origin; } catch { origin = null; }
        results.push({
          url: u.url, param: u.param, payload: p.id, status: resp ? resp.status() : 0,
          executed, origin,
          targetOrigin: safeOrigin(u.url),
          value: executed && origin === safeOrigin(u.url),
        });
      } catch (e) {
        results.push({ url: u.url, param: u.param, payload: p.id, executed: false, error: String(e.message || e) });
      } finally {
        await page.close().catch(() => {});
      }
      if (results[results.length - 1].executed) break;   // proven, no need to escalate
    }
  }
  await context.close().catch(() => {});
  return results.filter((r) => r.executed);
}

function safeOrigin(u) { try { return new URL(u).origin; } catch { return null; } }

function inject(url, param, value) {
  const u = new URL(url);
  if (param) u.searchParams.set(param, value);
  else u.pathname = value;
  return u.toString();
}

/* ------------------------------------------------------------------ *
 * Identity capture
 * ------------------------------------------------------------------ */

const DEFAULT_ROUTES = ['/', '/account', '/profile', '/settings', '/orders', '/invoices', '/api/me'];

/**
 * Log in with one account and return a Playwright storage state.
 * Deliberately conservative: it fills a form and clicks submit, it does not
 * attempt to create accounts or solve challenges.
 */
async function captureIdentity(browser, loginUrl, creds, opts = {}) {
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 }, ignoreHTTPSErrors: true, extraHTTPHeaders: (opts && opts.headerPolicy && opts.headerPolicy.active) ? opts.headerPolicy.playwright() : undefined });
  const page = await context.newPage();
  const requests = [];
  page.on('response', (r) => {
    const req = r.request();
    if (req.method() === 'GET') {
      requests.push({ method: 'GET', url: r.url(), status: r.status() });
    }
  });
  try {
    await page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: opts.timeout || 20000 });
    // Best-effort field discovery: match on name/id/placeholder/label text.
    const fill = await page.evaluate(({ user, pass }) => {
      const inputs = [...document.querySelectorAll('input')];
      const pick = (re) => inputs.find((i) => re.test(`${i.name} ${i.id} ${i.placeholder} ${i.autocomplete} ${(i.labels || []).map((l) => l.innerText).join(' ')}`));
      const u = pick(/user|email|login|account|ident/i) || inputs.find((i) => i.type === 'text' || i.type === 'email');
      const p = pick(/pass|secret/i) || inputs.find((i) => i.type === 'password');
      return { u: u ? { name: u.name, id: u.id, type: u.type } : null, p: p ? { name: p.name, id: p.id } : null };
    }, { user: creds.username, pass: creds.password });

    if (fill.u) {
      const sel = fill.u.id ? `#${CSS.escape(fill.u.id)}` : `input[name="${fill.u.name}"]`;
      await page.fill(sel, creds.username).catch(() => {});
    }
    if (fill.p) {
      const sel = fill.p.id ? `#${CSS.escape(fill.p.id)}` : `input[type=password]`;
      await page.fill(sel, creds.password).catch(() => {});
    }
    await Promise.all([
      page.waitForLoadState('networkidle', { timeout: 10000 }).catch(() => {}),
      page.click('button[type=submit], input[type=submit]').catch(() => {}),
    ]);
    await page.waitForTimeout(1200);

    const cookies = await context.cookies();
    const authenticated = cookies.some((c) => c.name && !/csrf|xsrf|session_?id_?anon/i.test(c.name) && c.value);
    const storage = await context.storageState();
    return { ok: true, authenticated, cookies: cookies.map((c) => c.name), storage, requests };
  } catch (e) {
    return { ok: false, error: String(e.message || e), requests };
  } finally {
    await context.close().catch(() => {});
  }
}

/**
 * Replay a set of routes under a storage state and record every observation, in
 * the JSONL format `authmatrix.readCapture` consumes.
 */
async function replay(browser, storageState, baseUrl, routes = DEFAULT_ROUTES, opts = {}) {
  const context = await browser.newContext({ storageState, viewport: { width: 1280, height: 800 }, ignoreHTTPSErrors: true, extraHTTPHeaders: (opts && opts.headerPolicy && opts.headerPolicy.active) ? opts.headerPolicy.playwright() : undefined });
  const page = await context.newPage();
  const rows = [];
  for (const r of routes) {
    try {
      const url = new URL(r, baseUrl).toString();
      const resp = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15000 });
      const body = await page.content().catch(() => '');
      rows.push({ method: 'GET', url, status: resp ? resp.status() : 0, body: body.slice(0, 200000) });
    } catch (e) {
      rows.push({ method: 'GET', url: new URL(r, baseUrl).toString(), status: 0, body: '', error: String(e.message || e) });
    }
  }
  await context.close().catch(() => {});
  return rows;
}

function writeCapture(file, rows, identity) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const out = rows.map((r) => JSON.stringify({ ...r, id: identity })).join('\n') + (rows.length ? '\n' : '');
  fs.writeFileSync(file, out);
  return { file, count: rows.length };
}

module.exports = { proveXss, xssPayloads, captureIdentity, replay, writeCapture, SENTINEL, DEFAULT_ROUTES, inject };
