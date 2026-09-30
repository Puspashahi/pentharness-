'use strict';
/**
 * OAuth / OIDC / SSO session capture.
 *
 * The plain form-login path in `identity.js` cannot reach a modern target: most
 * applications delegate authentication to an identity provider, so the useful
 * session is only established after a redirect chain, a provider login form,
 * possibly a consent screen, and a callback. Measured against real targets,
 * that is the single biggest coverage gap for the authorization matrix — which
 * is the highest-yield primitive in the field.
 *
 * The IdP differs per target, so the flow is driven by a declarative recipe
 * rather than a hardcoded sequence. Each step is verified before proceeding,
 * and any step that cannot be satisfied is reported by name rather than being
 * guessed at. Nothing here bypasses a challenge, and no step submits a form
 * whose fields could not be identified.
 */

const fs = require('fs');
const path = require('path');

/**
 * Signals that a step genuinely cannot be completed automatically.
 *
 * A naive keyword scan over page HTML is wrong, and measurably so: a real login
 * page was rejected as "blocked by captcha" because it merely *contained* a
 * recaptcha container and an alternate phone-OTP tab. But the recaptcha was
 * `size: 'invisible'` (v3, evaluated on submit, invisible to automation) and the
 * OTP tab was not the default path. Detection must key on what is actually
 * *enforced on the active path*, not on any mention anywhere in the markup.
 */
const BLOCKERS = [
  // Interactive / enforced captcha widgets only. Invisible v3 and badges are
  // excluded: they run on submit and do not gate an automated form fill.
  { id: 'captcha', re: /class="[^"]*g-recaptcha-(?:data|checkbox)[^"]*"|<div[^>]+data-sitekey[^>]+(?!.*invisible)|class="[^"]*h-captcha[^"]*"|hcaptcha\/checklist|g-recaptcha-badge|areyouhuman|cf-turnstile-(?:widget|challenge)|geetest_/i },
  // An enforced second factor: a field on the active path, or a page whose only
  // affordance is code entry. A mere "otp" string (a phone-login tab, a JS
  // function name) is not a blocker.
  { id: 'mfa', re: /type=["']?(?:tel|number)["']?[^>]*\bname=["'][^"']*(?:otp|code|verification)[^"']*["']|autocomplete=["']one-time-code["']|<(form|div|section)[^>]+(?:id|class)=["'][^"']*(?:\bmfa\b|\b2fa\b|two-?factor|otp-?(?:verify|confirm|challenge)|verify-?code)[^"']*["']|enter the (?:verification )?code (?:we|sent|from)|we (?:sent|emailed) (?:you )?(?:a )?(?:verification )?code|(?:two|2)[- ]factor (?:authentication|verification)|multi-?factor (?:authentication|verification)/i },
  { id: 'email-code', re: /check your (?:email|inbox|mailbox) (?:for|to)|we (?:sent|emailed) (?:you )?a (?:login|verification) (?:link|code)|enter the code (?:sent|we sent)/i },
  { id: 'push-approval', re: /approve (?:the )?(?:login|sign ?in|request) (?:on|in) (?:your )?(?:phone|device)|push notification (?:sent|waiting)|waiting for (?:you to )?approve/i },
  { id: 'webauthn', re: /use (?:your )?(?:security key|passkey|passkey or)|webauthn|publickeycredential/i },
];

/**
 * Is a challenge actually enforced on the path that is currently active?
 * A widget counts only when it is present AND the page has not already
 * rendered a usable, captcha-free submission path.
 */
function blockers(html, opts = {}) {
  const h = String(html || '');
  const out = [];
  for (const b of BLOCKERS) {
    if (!b.re.test(h)) continue;
    out.push(b.id);
  }
  // Cross-check: if the page has a plain password form and the only captcha
  // mention is an invisible v3 key or a hidden container, the password path is
  // not blocked. Do not report a captcha blocker in that case.
  const hasPassword = /type=["']?password["']?/i.test(h);
  const invisibleOnly = /recaptcha-container|size:\s*['"]invisible['"]|grecaptcha\.execute/i.test(h)
    && !/g-recaptcha-(data|checkbox)|hcaptcha\/checklist|cf-turnstile-widget/i.test(h);
  if (invisibleOnly && hasPassword && !opts.strictCaptcha) {
    return out.filter((x) => x !== 'captcha');
  }
  return out;
}

/** Classify the page so the driver knows what to do next. */
function classifyPage(url, html, opts = {}) {
  const h = String(html || '');
  const b = blockers(h);
  if (b.length) return { kind: 'blocked', blockers: b };

  const s = (opts.selectors && opts.selectors) || {};
  const has = (sel) => (sel && h.includes(sel));
  const host = (() => { try { return new URL(url).hostname; } catch { return ''; } })();
  const isIdpHost = /idp|sso|oauth|openid|saml|accounts\.|login\.microsoftonline|accounts\.google|okta|auth0|onelogin|keycloak|duosecurity|jumpcloud/i.test(host || '') || !!s.issuer;
  // Content tell: an IdP login page advertises a grant/consent or a
  // provider-branded form. This keeps classification working when the IdP lives
  // on a host we have never seen (a staging tenant, a first-party IdP path).
  //
  // Word-boundary anchored on purpose. A bare `idp` substring matched the real
  // kinbechshop login page inside a Firebase config value ("projectId"), which
  // misclassified an ordinary password form as an IdP login and made the driver
  // look for selectors that do not exist there.
  const looksIdpContent = /grant access|authorize application|sign in to continue|\bidp\b|identity provider|<meta[^>]+(?:issuer|og:site_name)[^>]+(?:okta|auth0|azure|keycloak|google|microsoft)/i.test(h);
  // An app's own login form wins over the IdP heuristic when both match: if this
  // page is the application's own credential form, treat it as one.
  // A first-party IdP path on the app's own host: a password form, but on a
  // URL that is itself the identity step. Trust the grant/consent copy over the
  // generic "sign in" wording that every login page shares.
  const isFirstPartyIdp = looksIdpContent
    && /(?:grant access|authorize application|sign in to continue|\bidp\b|identity provider)/i.test(h)
    && /\/(\/)?(?:sso|oauth|oidc|auth|idp|openid|authorize)(?:[/?#]|$)|[?&](?:client_id|scope|response_type|redirect_uri)=/i.test(url || '');

  const isOwnLoginForm = !isIdpHost && !isFirstPartyIdp
    && /<input[^>]+type=["']?password/i.test(h)
    && /(?:sign in|log in|login|password|email|username)/i.test(h);

  if (isIdpHost || (looksIdpContent && !isOwnLoginForm)) {
    if (/<input[^>]+type=["']?password/i.test(h)) return { kind: 'idp-login' };
    if (/(?:consent|authorize|grant access|allow access|access denied)/i.test(h) || s.consent) return { kind: 'consent' };
    return { kind: 'idp' };
  }
  if (/<input[^>]+type=["']?password/i.test(h) && /(?:sign in|log in|login|password)/i.test(h)) return { kind: 'app-login' };
  if (s.ssoButton || /(?:continue|single sign|sign in with|log in with|sso|oauth|google|microsoft|okta|github)/i.test(h)) return { kind: 'sso-entry' };
  return { kind: 'unknown' };
}

/** Find a clickable element matching any of the given text fragments. */
async function clickByText(page, texts, timeout = 6000) {
  for (const t of texts) {
    const el = page.locator(`text=${t}`).first();
    try {
      if (await el.isVisible({ timeout: 1200 })) { await el.click({ timeout }); return t; }
    } catch { /* try the next phrase */ }
  }
  // Fall back to a[href] / button containing the text.
  for (const t of texts) {
    const el = page.locator(`button:has-text("${t}"), a:has-text("${t}"), input[type=submit][value*="${t}" i]`).first();
    try {
      if (await el.isVisible({ timeout: 1200 })) { await el.click({ timeout }); return t; }
    } catch { /* try the next phrase */ }
  }
  return null;
}

async function fillFirst(page, selectors, value) {
  for (const sel of selectors) {
    const el = page.locator(sel).first();
    try {
      if (await el.isVisible({ timeout: 1500 })) { await el.fill(value, { timeout: 4000 }); return sel; }
    } catch { /* try the next selector */ }
  }
  return null;
}

const DEFAULTS = {
  ssoButton: ['Continue with', 'Sign in with', 'Log in with', 'Single sign-on', 'SSO', 'Continue'],
  userField: ['#username', '#user', 'input[name=username]', 'input[name=email]', 'input[type=email]', '#login', 'input[name=login_hint]', 'input[autocomplete=username]'],
  passField: ['#password', 'input[name=password]', 'input[type=password]', '#pass'],
  submit: ['Sign in', 'Log in', 'Next', 'Continue', 'Submit'],
  consent: ['Accept', 'Approve', 'Allow', 'Continue', 'Authorize', 'Grant access', 'I agree'],
};

/**
 * Drive an OAuth/OIDC/SSO login to completion and return the storage state.
 *
 * @param browser Playwright browser
 * @param recipe {
 *   startUrl, username, password,
 *   selectors?: { ssoButton, userField, passField, submit, consent },
 *   maxHops?: number
 * }
 */
async function oauthLogin(browser, recipe) {
  const sel = { ...DEFAULTS, ...(recipe.selectors || {}) };
  const maxHops = recipe.maxHops || 12;
  const trace = [];

  const context = await browser.newContext({
    viewport: { width: 1280, height: 800 },
    ignoreHTTPSErrors: true,
  });
  const page = await context.newPage();

  const result = { ok: false, authenticated: false, reason: null, steps: trace, blocked: null, storage: null, cookies: [], landedOn: null, visited: [] };

  try {
    await page.goto(recipe.startUrl, { waitUntil: 'domcontentloaded', timeout: recipe.timeout || 25000 });

    for (let hop = 0; hop < maxHops; hop++) {
      const url = page.url();
      const html = await page.content().catch(() => '');
      const kind = classifyPage(url, html, { selectors: recipe.selectors });

      // Stall detection: a signature of (url, page kind) that we have already
      // acted on. Without this, a page whose submit does not navigate — or one
      // we misclassify — gets refilled until the hop budget runs out and the
      // failure looks like a timeout instead of a real stall.
      const sig = `${kind.kind}::${url}`;
      const seenCount = result.visited.filter((s) => s === sig).length;
      result.visited.push(sig);
      if (seenCount >= 1) {
        result.reason = `stalled: the ${kind.kind} page at ${url} did not advance after one attempt (no navigation, or a control we cannot actuate)`;
        trace.push(`hop${hop}: STALL ${kind.kind} ${url}`);
        return result;
      }

      if (kind.kind === 'blocked') {
        result.blocked = kind.blockers;
        result.reason = `blocked by ${kind.blockers.join(', ')} — a human must complete this step`;
        trace.push(`hop${hop}: BLOCKED ${kind.blockers.join(',')} @ ${hostOf(url)}`);
        return result;
      }

      if (kind.kind === 'app-login') {
        const u = await fillFirst(page, sel.userField, recipe.username);
        const p = await fillFirst(page, sel.passField, recipe.password);
        trace.push(`hop${hop}: app login (user=${u || 'NOT FOUND'}, pass=${p || 'NOT FOUND'})`);
        if (!p) { result.reason = 'reached a login form but found no password field'; return result; }
        await Promise.all([
          page.waitForLoadState('networkidle', { timeout: 10000 }).catch(() => {}),
          clickByText(page, sel.submit, 5000),
        ]);
        await page.waitForTimeout(1200);
        continue;
      }

      if (kind.kind === 'idp-login') {
        const u = await fillFirst(page, sel.userField, recipe.username);
        const p = await fillFirst(page, sel.passField, recipe.password);
        trace.push(`hop${hop}: idp login @ ${hostOf(url)} (user=${u || 'NOT FOUND'}, pass=${p || 'NOT FOUND'})`);
        if (!p) { result.reason = `reached the identity provider at ${hostOf(url)} but found no password field; add selectors.selectors`; return result; }
        await Promise.all([
          page.waitForLoadState('networkidle', { timeout: 10000 }).catch(() => {}),
          clickByText(page, sel.submit, 5000),
        ]);
        await page.waitForTimeout(1500);
        continue;
      }

      if (kind.kind === 'consent') {
        const clicked = await clickByText(page, sel.consent, 5000);
        trace.push(`hop${hop}: consent screen @ ${hostOf(url)} (${clicked || 'NO BUTTON MATCHED'})`);
        if (!clicked) { result.reason = 'consent screen reached but no allow/accept control was found'; return result; }
        await page.waitForTimeout(1500);
        continue;
      }

      if (kind.kind === 'sso-entry') {
        const clicked = await clickByText(page, recipe.ssoText || sel.ssoButton, 5000);
        trace.push(`hop${hop}: sso entry (${clicked || 'NO BUTTON MATCHED'})`);
        if (!clicked) {
          // Maybe already signed in and the page is the app itself.
          const st = await finishIfAuthenticated(context, page, recipe);
          if (st) { Object.assign(result, st); return result; }
          result.reason = 'no SSO entry control matched; add recipe.ssoText with the button label';
          return result;
        }
        await page.waitForTimeout(1500);
        continue;
      }

      // unknown / app page: if we hold a session we are done
      const st = await finishIfAuthenticated(context, page, recipe);
      if (st) { Object.assign(result, st); result.landedOn = page.url(); return result; }
      trace.push(`hop${hop}: unrecognised page @ ${hostOf(url)}`);
      result.reason = `flow stalled on an unrecognised page at ${hostOf(url)}; add a selector or startUrl for the next step`;
      return result;
    }

    const st = await finishIfAuthenticated(context, page, recipe);
    if (st) { Object.assign(result, st); return result; }
    result.reason = `exceeded ${maxHops} hops without a confirmed session`;
    return result;
  } catch (e) {
    result.reason = String(e.message || e).slice(0, 200);
    return result;
  } finally {
    if (!result.storage) await context.close().catch(() => {});
  }
}

/** Is this a real authenticated session? */
async function finishIfAuthenticated(context, page, recipe) {
  const cookies = await context.cookies();
  const names = cookies.map((c) => c.name);
  const sessionCookie = cookies.some((c) => /^(?:session|sid|sess|jsessionid|auth|token|jwt|remember_me|connect\.sid)/i.test(c.name) && c.value);
  // A redirect back to the application origin, past the IdP, is the other tell.
  const backAtApp = recipe.appOrigin && page.url().startsWith(recipe.appOrigin);
  const hasAuthHeader = await page.evaluate(() => {
    try {
      const t = document.cookie || '';
      return /token|auth|session|sid/i.test(t);
    } catch { return false; }
  }).catch(() => false);

  if (sessionCookie || (backAtApp && !/login|signin|oauth|authorize/i.test(page.url()))) {
    return {
      ok: true, authenticated: true, cookies: names,
      reason: `session established (${sessionCookie ? 'session cookie' : 'returned to app origin'}; cookies: ${names.slice(0, 5).join(', ')})`,
      storage: await context.storageState(),
    };
  }
  if (hasAuthHeader && backAtApp) {
    return { ok: true, authenticated: true, cookies: names, reason: 'session established', storage: await context.storageState() };
  }
  return null;
}

function hostOf(u) { try { return new URL(u).hostname; } catch { return String(u || '?'); } }

/**
 * Load a recipe from a JSON file so credentials never sit in shell history.
 * {
 *   "target": "https://app.tld",
 *   "startUrl": "https://app.tld/login",
 *   "accounts": { "userA": {"username":"...","password":"..."}, "userB": {...} },
 *   "selectors": { "ssoButton": ["Continue with Okta"], "userField": ["#username"] },
 *   "routes": ["/account","/invoices"]
 * }
 */
function loadRecipe(file) {
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!raw.startUrl) throw new Error('recipe requires startUrl');
  return raw;
}

module.exports = { oauthLogin, classifyPage, blockers, clickByText, fillFirst, finishIfAuthenticated, loadRecipe, DEFAULTS, BLOCKERS };
