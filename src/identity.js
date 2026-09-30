'use strict';
/**
 * Automated identity provisioning.
 *
 * The authorization matrix is the highest-yield primitive in the field and it
 * needs two sessions. Doing that by hand in a proxy does not scale, which is
 * the whole reason the $78,000 Meta report and the "under 5% of IDORs are
 * caught by scanners" statistic keep recurring together: the tooling gap is
 * the dual identity, not the technique.
 *
 * This module takes credentials and produces the capture files the matrix
 * consumes, with no manual step:
 *
 *   login(userA) ─┐
 *                 ├─> replay the same routes under both ─> authmatrix diff
 *   login(userB) ─┘
 *
 * It deliberately does not create accounts, solve CAPTCHAs, or bypass MFA. If
 * a challenge is present it says so and stops, because that is a human decision.
 */

const fs = require('fs');
const path = require('path');
const { readCapture, writeCaptureSafe } = require('./capture-io');

/** Routes worth walking under each identity. */
const ROUTES = [
  '/', '/account', '/profile', '/settings', '/dashboard',
  '/orders', '/invoices', '/tickets', '/cases', '/messages',
  '/api/me', '/api/user', '/api/account', '/api/orders', '/api/invoices',
];

/** Field-name heuristics for login forms. */
const FIELD = {
  user: /user(name)?|email|e-?mail|login|account|ident(ifier)?|phone|mobile/i,
  pass: /pass(word|wd|phrase)?|secret|pwd/i,
};

function firstMatch(inputs, re) {
  return inputs.find((i) => re.test(i.label)) || null;
}

/**
 * Fill and submit a login form, then return the authenticated storage state.
 * @param {import('playwright').Browser} browser
 */
async function login(browser, loginUrl, creds, opts = {}) {
  const context = await browser.newContext({
    viewport: { width: 1280, height: 800 },
    ignoreHTTPSErrors: true,
    // Program-mandated headers must ride on the session, or login succeeds
    // without them while every authenticated request is treated as unauthenticated.
    extraHTTPHeaders: (opts.headerPolicy && opts.headerPolicy.active) ? opts.headerPolicy.playwright() : undefined,
  });
  const page = await context.newPage();
  const result = { ok: false, authenticated: false, reason: null, cookies: [], storage: null, mfa: false, captcha: false };

  try {
    await page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: opts.timeout || 25000 });

    // Challenge detection: a captcha is a human decision, not something to bypass.
    const html = (await page.content()).toLowerCase();
    if (/captcha|recaptcha|hcaptcha|turnstile|g-recaptcha/.test(html)) result.captcha = true;
    if (/\bmfa\b|\b2fa\b|\botp\b|one[- ]time[- ]pass|verify.*device/.test(html)) result.mfa = true;

    // RegExp objects do not survive the page.evaluate boundary, so the patterns
    // are passed as source strings and recompiled inside the browser context.
    const fields = await page.evaluate((HINTS) => {
      const re = (s) => new RegExp(s, 'i');
      const userRx = re(HINTS.user), passRx = re(HINTS.pass);
      const inputs = [...document.querySelectorAll('input')].filter((i) => {
        const t = (i.type || 'text').toLowerCase();
        return !['hidden', 'submit', 'button', 'image', 'reset'].includes(t);
      });
      return inputs.map((i) => {
        const labels = [...(i.labels || [])].map((l) => (l.innerText || '').trim()).join(' ');
        const label = `${i.name} ${i.id} ${i.placeholder} ${i.autocomplete} ${labels}`;
        return {
          name: i.name || '', id: i.id || '', type: (i.type || 'text').toLowerCase(),
          placeholder: i.placeholder || '', autocomplete: i.autocomplete || '', label,
          test: /pass/i.test(label) || (i.type || '').toLowerCase() === 'password' ? 'p'
            : (userRx.test(label) || (i.type || '').toLowerCase() === 'email' ? 'u' : ''),
        };
      }).filter((f) => f.test);
    }, { user: FIELD.user.source, pass: FIELD.pass.source });

    const u = firstMatch(fields, FIELD.user) || fields.find((f) => f.type === 'email') || fields.find((f) => f.type === 'text');
    const p = firstMatch(fields, FIELD.pass) || fields.find((f) => f.type === 'password');
    if (!p) { result.reason = 'no password field found — is this a login page?'; return result; }

    // Two-step sign-in: many providers (MathWorks among them) show an
    // identifier step and only reveal the password panel after it is submitted.
    // Filling a still-hidden password field fails silently, so if the password
    // is not visible we submit the identifier step and wait for the reveal.
    const isVisible = async (sel) => {
      try { return await page.locator(sel).first().isVisible({ timeout: 2000 }); } catch { return false; }
    };
    const passSel = selectorFor(p);
    if (!(await isVisible(passSel))) {
      if (u) await page.fill(selectorFor(u), creds.username).catch(() => {});
      // Prefer the provider's own identifier/submit control, then fall back to
      // a generic submit. Select a *visible* control: on a two-step form the
      // hidden sibling can be first in DOM order.
      const visSubmit = async (cands) => {
        for (const sel of cands) {
          const loc = page.locator(sel);
          const n = await loc.count().catch(() => 0);
          for (let i = 0; i < n; i++) {
            if (!(await loc.nth(i).isVisible({ timeout: 1200 }).catch(() => false))) continue;
            await loc.nth(i).click({ timeout: 8000 }).catch(() => {});
            return true;
          }
        }
        return false;
      };
      const clicked = await visSubmit(['#submit_identifier', 'button[type=submit]', 'input[type=submit]', 'button:not([type])']);
      if (clicked) {
        await page.waitForTimeout(2500);
        result.steps = ['identifier step submitted'];
        if (!(await isVisible(passSel))) {
          const msgs = await page.locator('.alert, [role=alert], [id^=errorMessage]').allTextContents().catch(() => []);
          const clean = msgs.map((m) => m.trim()).filter(Boolean);
          result.reason = `identifier accepted but the password panel never appeared${clean.length ? `: ${clean[0].slice(0, 120)}` : ''}`;
          return result;
        }
      }
    }

    if (u) await page.fill(selectorFor(u), creds.username).catch(() => {});
    if (!(await isVisible(passSel))) {
      result.reason = 'password field stayed hidden — the login flow needs a recipe selector';
      return result;
    }
    await page.fill(passSel, creds.password).catch(() => {});

    // Prefer the provider's own password-submit control. A combined selector
    // like `#submit_password, button[type=submit]` picks the first *match in
    // DOM order*, which on a two-step form is the hidden identifier button, not
    // the visible one — the click then timed out and, because the error was
    // swallowed, the login silently failed. Select the visible control instead.
    const clickVisible = async (candidates) => {
      for (const sel of candidates) {
        const loc = page.locator(sel);
        const n = await loc.count().catch(() => 0);
        for (let i = 0; i < n; i++) {
          const el = loc.nth(i);
          if (!(await el.isVisible({ timeout: 1200 }).catch(() => false))) continue;
          await el.click({ timeout: 8000 }).catch(() => {});
          return sel;
        }
      }
      // Nothing visible: fall back to the first match so a plain form still works.
      await page.locator(candidates[0]).first().click({ timeout: 8000 }).catch(() => {});
      return null;
    };

    await Promise.all([
      page.waitForLoadState('networkidle', { timeout: 12000 }).catch(() => {}),
      clickVisible(['#submit_password', 'button[type=submit]', 'input[type=submit]', 'button:not([type])']),
    ]);
    // Do not race the provider's redirect with a fixed sleep. MathWorks sets
    // MOS_AUTH_TOKEN and bounces to matlab.mathworks.com several seconds after
    // the submit, so a short wait reported "still on the login page" for an
    // authentication that had actually succeeded.
    await page.waitForURL((u) => !/login|signin|sign-in/i.test(u.toString()), { timeout: 20000 })
      .catch(() => page.waitForTimeout(4000));

    // Authentication must be evidenced by a real session artifact, not merely
    // by having left the login URL. `!stillLogin` alone is not proof: a provider
    // can bounce a failed attempt to a marketing page, an error page, or a
    // generic interstitial that merely lacks "login" in its URL. Requiring a
    // genuine session cookie prevents a false "authenticated" verdict from
    // becoming IDOR evidence.
    const cookies = await context.cookies();
    result.cookies = cookies.map((c) => c.name);
    const named = cookies.filter((c) => c.value);
    const sessionCookie = named.some((c) => /session|sid|auth|token|jwt|remember/i.test(c.name));
    const stillLogin = /login|signin|sign-in/i.test(page.url());
    // A body-level tell, for providers whose session cookie name is unusual.
    const bodyLooksAuthed = await page.evaluate(() => {
      try {
        const t = (document.body && document.body.innerText || '').slice(0, 4000);
        return /sign ?out|log ?out|my ?account|your ?profile|preferences/i.test(t);
      } catch { return false; }
    }).catch(() => false);

    result.authenticated = sessionCookie && (!stillLogin || bodyLooksAuthed);
    result.sessionCookie = sessionCookie;
    result.reason = result.authenticated
      ? `authenticated (session cookie present, left ${hostOf(page.url())}; cookies: ${result.cookies.slice(0, 6).join(', ')})`
      : (stillLogin
        ? 'login appears to have failed — still on the login page'
        : (sessionCookie
          ? 'left the login page but no authenticated view was observed'
          : 'no session cookie observed — treated as unauthenticated'));
    result.storage = result.authenticated ? await context.storageState() : null;
    result.ok = result.authenticated;
  } catch (e) {
    result.reason = String(e.message || e).slice(0, 160);
  } finally {
    await context.close().catch(() => {});
  }
  return result;
}

function selectorFor(f) {
  if (f.id) return `#${cssEscape(f.id)}`;
  if (f.name) return `input[name="${f.name.replace(/"/g, '\\"')}"]`;
  return `input[type="${f.type}"]`;
}

function cssEscape(s) { return String(s).replace(/([^\w-])/g, '\\$1'); }

function hostOf(u) { try { return new URL(u).hostname; } catch { return String(u || '?'); } }

/**
 * Walk routes under a storage state, then FOLLOW the links found on those
 * pages. Object URLs almost never appear in a hand-written route list — they
 * are only reachable by navigating the app, which is exactly why the $78,000
 * report started from "open a legitimate ticket, observe the case ID format".
 * Without this the matrix has nothing with an identifier in it to diff.
 */
async function replay(browser, storageState, baseUrl, routes = ROUTES, opts = {}) {
  const context = await browser.newContext({ storageState, viewport: { width: 1280, height: 800 }, ignoreHTTPSErrors: true, extraHTTPHeaders: (opts && opts.headerPolicy && opts.headerPolicy.active) ? opts.headerPolicy.playwright() : undefined });
  const page = await context.newPage();
  const rows = [];
  const seen = new Set();
  const queue = routes.map((r) => ({ url: new URL(r, baseUrl).toString(), hop: 0 }));
  const maxHops = opts.maxHops || 2;
  const maxPages = opts.maxPages || 40;

  while (queue.length && rows.length < maxPages) {
    const item = queue.shift();
    const url = item.url;
    const hop = item.hop;
    if (seen.has(url)) continue;
    seen.add(url);
    try {
      const resp = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15000 });
      const body = await page.content().catch(() => '');
      const title = await page.title().catch(() => '');
      rows.push({ method: 'GET', url, status: resp ? resp.status() : 0, length: body.length, body: body.slice(0, 300000), title });

      // Harvest same-origin links that carry an object identifier, and enqueue
      // them for the next hop. This is what surfaces /case/100 style URLs.
      if (hop < maxHops) {
        const links = await page.evaluate(() => {
          const out = [];
          const hasId = (h) => {
            // matches /x/100, /x/100?q=1, and ?id=100 / ?case=100
            const path = h.split('?')[0];
            return /\/(\d{1,9})(\/|$)/.test(path) || /[?&](id|case|order|invoice|ticket|doc|user_id)=\d+/i.test(h);
          };
          for (const a of document.querySelectorAll('a[href]')) {
            const h = a.getAttribute('href') || '';
            if (!h || h.startsWith('#') || h.startsWith('javascript:')) continue;
            if (hasId(h)) { try { out.push(new URL(a.href, location.href).toString()); } catch { /* skip */ } }
          }
          return out.slice(0, 15);
        }).catch(() => []);
        for (const l of links) if (!seen.has(l) && !queue.some((q) => q.url === l)) queue.push({ url: l, hop: hop + 1 });
      }
    } catch (e) {
      rows.push({ method: 'GET', url, status: 0, length: 0, body: '', error: String(e.message || e).slice(0, 120) });
    }
  }
  await context.close().catch(() => {});
  return rows;
}

/**
 * Provision both identities and write the capture files.
 * @param accounts {userA:{username,password}, userB:{...}}
 * @returns {{identities:object, files:string[], notes:string[]}}
 */
async function provision(browser, loginUrl, accounts, outDir, opts = {}) {
  const notes = [];
  const identities = {};
  fs.mkdirSync(outDir, { recursive: true });

  for (const [id, creds] of Object.entries(accounts)) {
    if (!creds || !creds.username) { notes.push(`${id}: no username supplied, skipped`); continue; }
    // Reuse an already-established session rather than logging in again. A
    // second login for the same account is wasted requests against a target
    // that may be rate-limiting us, and it is pure risk for no gain.
    if (opts.reuseStorage && opts.reuseIdentity === id) {
      const rows = await replay(browser, opts.reuseStorage, opts.baseUrl || '', opts.routes || ROUTES);
      const f = writeCaptureSafe(path.join(outDir, `${id}.jsonl`), rows, id);
      const cap = f && typeof f === 'object' ? `${f.file} (${f.count} row(s))` : f;
      identities[id] = { ok: true, storage: opts.reuseStorage, cookies: (opts.reuseStorage.cookies || []).map((c) => c.name), reused: true };
      notes.push(`${id}: reused existing session, replayed ${rows.length} route(s) -> ${cap}`);
      continue;
    }
    let r;
    if (opts.mode === 'oauth' || opts.oauth) {
      // Delegated authentication: drive the IdP chain, then replay routes with
      // the resulting storage state. A block (captcha/MFA) is reported, never
      // worked around.
      const OA = require('./oauth');
      const o = await OA.oauthLogin(browser, {
        startUrl: loginUrl, username: creds.username, password: creds.password,
        appOrigin: opts.baseUrl || new URL(loginUrl).origin,
        selectors: opts.selectors, timeout: opts.timeout, headerPolicy: opts.headerPolicy,
      });
      r = { ok: o.authenticated, reason: o.reason, storage: o.storage, steps: o.steps, blocked: o.blocked, mode: 'oauth' };
    } else {
      r = await login(browser, loginUrl, creds, opts);
    }
    identities[id] = r;
    if (!r.ok) {
      notes.push(`${id}: ${r.reason}${r.captcha ? ' (captcha present — needs a human)' : ''}${r.mfa ? ' (MFA/2FA present — needs a human)' : ''}${r.blocked ? ` (blocked: ${r.blocked.join(', ')} — needs a human)` : ''}`);
      continue;
    }
    if (r.mode === 'oauth' && Array.isArray(r.steps) && r.steps.length) {
      notes.push(`${id}: oauth flow ${r.steps.length} step(s) — ${r.steps.join(' | ')}`);
    }
    const rows = await replay(browser, r.storage, opts.baseUrl || new URL(loginUrl).origin, opts.routes || ROUTES);
    const f = writeCaptureSafe(path.join(outDir, `${id}.jsonl`), rows, id);
    // writeCaptureSafe returns an object; interpolating it produced
    // "-> [object Object]" in the run log, which looked like a broken path.
    const cap = f && typeof f === 'object' ? `${f.file} (${f.count} row(s))` : f;
    notes.push(`${id}: authenticated, replayed ${rows.length} route(s) -> ${cap}`);
  }

  const usable = Object.entries(identities).filter(([, r]) => r.ok).map(([id]) => id);
  if (usable.length < 2) {
    notes.push(`only ${usable.length} identity/identities usable — the authorization matrix needs 2; IDOR cannot be proven without it`);
  }
  return { identities, files: usable.map((id) => path.join(outDir, `${id}.jsonl`)), notes, usable };
}

module.exports = { login, replay, provision, ROUTES, FIELD, readCapture };
