'use strict';
/**
 * Live JavaScript capture and analysis.
 *
 * The gap this closes: the harness probed HTTP endpoints but never read the
 * JavaScript the application actually serves. That is where the highest-value
 * bugs hide, and published hunter methodology is blunt about it — "JavaScript
 * files are goldmines... read them for explicit references to interesting
 * links, and keep a close eye on hard-coded credentials."
 *
 * Why a browser rather than a fetch loop: a request for `/static/app.js` tells
 * you nothing about which bundles the *authenticated* application loads. Only
 * driving the app and observing its network traffic reveals the JS behind the
 * features that matter, including bundles fetched only after login.
 *
 * Two problems dominate real-world JS and both are handled here:
 *
 * 1. Minification. Production bundles are minified, and the existing local
 *    scanner deliberately skipped `.min.js` because regexes over minified
 *    source produce garbage. Minified code is parsed instead, and quoted string
 *    literals are extracted and analysed individually — that is what makes
 *    obfuscation-minification survivable.
 *
 * 2. Source maps. A `.map` file is usually referenced by a trailing
 *    `//# sourceMappingURL=` comment and often published in production. It
 *    hands over the original, unobfuscated source, so it is fetched and
 *    preferred over the bundle whenever available.
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { URL } = require('url');

const JL = require('./jslogic');

/** Third-party analytics/marketing scripts: noisy, and not the app's surface. */
const THIRD_PARTY = [
  /adobedtm\.com/i, /googletagmanager\.com/i, /google-analytics\.com/i,
  /treasuredata\.com/i, /doubleclick\.net/i, /facebook\.net/i, /clarity\.ms/i,
  /hotjar\.com/i, /segment\.(io|com)/i, /sentry\.io/i, /newrelic\.com/i,
  /cdn\.jsdelivr\.net/i, /unpkg\.com/i, /bootstrapcdn\.com/i,
  /cdn\.skypack\.com/i, /esm\.sh/i, /jspm\.io/i, /cdnjs\.cloudflare\.com/i,
  /polyfill\.io/i, /fonts\.googleapis\.com/i, /use\.fontawesome\.com/i,
  /googletagservices\.com/i, /criteo\.com/i, /taboola\.com/i, /outbrain\.com/i,
];

/** A JS response worth analysing. */
function isAppScript(url, contentType = '') {
  if (/\.js(\?|$)/i.test(url)) return true;
  if (/javascript|ecmascript/i.test(contentType)) return true;
  return false;
}

function isThirdParty(url) {
  return THIRD_PARTY.some((rx) => rx.test(url));
}

/**
 * Decode a response body, handling gzip/deflate/br.
 * Returning text matters: a bundle that arrives compressed and is never
 * decoded is the classic reason a capture "found nothing".
 */
function decodeBody(buf, encoding = '') {
  if (!buf || !buf.length) return '';
  const enc = String(encoding).toLowerCase();
  try {
    if (enc.includes('gzip')) return zlib.gunzipSync(buf).toString('utf8');
    if (enc.includes('deflate')) return zlib.inflateSync(buf).toString('utf8');
    if (enc.includes('br') && typeof zlib.brotliDecompressSync === 'function') return zlib.brotliDecompressSync(buf).toString('utf8');
  } catch {
    // Fall through: a failed decode must not lose the capture entirely.
    try { return buf.toString('utf8'); } catch { return ''; }
  }
  return buf.toString('utf8');
}

/**
 * Pull every string literal out of a JavaScript source.
 *
 * This is the core trick for minified bundles. An attacker-relevant string —
 * `/api/invoices/`, `admin`, `role`, a postMessage origin — survives
 * minification intact as a quoted literal, even when every identifier around
 * it has been mangled to `a` or `n`. Analysing the literals individually is
 * what makes minified code analysable with a regex-based analyser.
 */
function stringLiterals(src = '', maxOut = 4000) {
  const out = new Set();
  const s = String(src);
  // Single, double, and template literals, plus the common escaped forms.
  const rx = /(['"`])((?:\\.|(?!\1)[^\\\n]){2,300})\1/g;
  let m;
  while ((m = rx.exec(s)) !== null && out.size < maxOut) {
    const v = m[2];
    // Skip obvious noise: minified code is full of single chars and base64.
    if (v.length < 3) continue;
    if (/^[A-Za-z0-9+/=]{40,}$/.test(v)) continue;   // base64 blob
    out.add(v);
  }
  return [...out];
}

/**
 * Extract the source-map reference from a bundle.
 * Supports the standard comment and the HTTP `SourceMap` header.
 */
function sourceMapRef(src = '') {
  const m = String(src).match(/\/\/[#@]\s*sourceMappingURL=(\S+)/);
  return m ? m[1] : null;
}

/**
 * Analyse one captured script.
 *
 * Both the raw source and, when the source is minified, its string literals are
 * fed to the analyser. The existing analyser is regex/keyword based and was
 * written for readable source, so the literal list is what carries the signal
 * once identifiers are mangled.
 */
function analyseScript(source, meta = {}) {
  const findings = [];
  const minified = meta.minified !== undefined
    ? meta.minified
    : (String(source).length > 20000 || !/\n\s*\/\//.test(String(source).slice(0, 4000)));

  // 1. The existing analyser on the whole source.
  try {
    const a = JL.analyseJs(source, meta);
    if (a && (a.leads || a.signals || []).length) findings.push(...(a.leads || a.signals).map((l) => ({ ...l, via: 'source' })));
  } catch { /* analyser must never abort a capture */ }

  // 2. Literal-level analysis for minified bundles.
  if (minified) {
    const lits = stringLiterals(source);
    // Group literals so the analyser sees context, not isolated words.
    const synthetic = lits.join('\n');
    try {
      const a = JL.analyseJs(synthetic, { ...meta, fromLiterals: true });
      if (a && (a.leads || a.signals || []).length) {
        findings.push(...(a.leads || a.signals).map((l) => ({ ...l, via: 'literals' })));
      }
    } catch { /* ignore */ }
  }

  return { findings, minified, literalCount: minified ? stringLiterals(source).length : 0 };
}

/**
 * Pull candidate endpoints out of any JS source.
 *
 * Independent of the analyser on purpose: this is the highest-yield single
 * extraction in bug bounty, and it must not be gated behind whatever else the
 * analyser happens to detect.
 */
function extractEndpoints(source, baseUrl = '') {
  const found = new Set();
  const s = String(source);

  const ABS = /(?:https?:)?\/\/[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}(?::\d+)?(\/[A-Za-z0-9._~%!$&'()*+,;=:@/-]*)/g;
  let m;
  while ((m = ABS.exec(s)) !== null) {
    // `m[0]` is the WHOLE match including the path, so appending `m[1]`
    // duplicated it: "https://api/x/graphql" + "/graphql" became
    // ".../graphql/graphql". The match is already the endpoint.
    const url = m[0];
    if (isThirdParty(url)) continue;
    found.add(url);
  }

  // The relative scan must not re-match the path of an absolute URL found
  // above: "https://api/x/graphql" contains "/graphql", which the relative
  // pattern also matches, and naively prefixing the base host produced
  // "https://api/x/graphql/graphql". Blank the path out of absolute URLs
  // before running the relative scan, so each string is attributed once.
  const blanked = s.replace(
    /(?:https?:)?\/\/[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}(?::\d+)?\/[A-Za-z0-9._~%!$&'()*+,;=:@/-]*/g,
    (m) => m.replace(/\/[A-Za-z0-9._~%!$&'()*+,;=:@/-]*$/, '/'),
  );
  const REL = /['"`](\/(?:api|v\d|graphql|gql|rest|rpc|ajax|auth|oauth|user|users|admin|account|accounts|profile|orders?|invoices?|payments?|checkout|cart|upload|download|files?|media|internal|debug|health|metrics|config|settings|webhook|webhooks|search|query)\b[A-Za-z0-9._~%!$&'()*+,;=:@/${}?-]*)/gi;
  while ((m = REL.exec(blanked)) !== null) {
    const p = m[1].split(/['"`?]/)[0];
    if (p.length > 2 && p.length < 300) found.add(p);
  }

  const base = baseUrl ? (() => { try { return new URL(baseUrl).origin; } catch { return ''; } })() : '';
  const out = [];
  for (const u of found) {
    if (/^(data|javascript|mailto|tel|blob):/i.test(u)) continue;
    // An absolute URL matched by BOTH patterns (e.g. "https://api/x/graphql"
    // and the "/graphql" relative match) used to be concatenated twice, giving
    // "https://api/x/graphql/graphql". Skip a relative match that the
    // absolute pattern already covered.
    out.push(u.startsWith('http') ? u : (base ? base + u : u));
  }
  return [...new Set(out)];
}

/** Credentials and tokens embedded in client code. */
function extractSecrets(source) {
  const s = String(source);
  const out = [];
  const push = (kind, rx, cap = (m) => m) => {
    const g = new RegExp(rx.source, rx.flags.includes('g') ? rx.flags : rx.flags + 'g');
    let m; let n = 0;
    while ((m = g.exec(s)) !== null && n < 5) { out.push({ kind, sample: String(cap(m)).slice(0, 12) }); n++; }
  };
  push('aws-access-key', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/, (m) => m);
  push('google-api-key', /\bAIza[0-9A-Za-z_-]{35}\b/, (m) => m);
  push('github-token', /\bgh[pousr]_[A-Za-z0-9]{20,}\b/, (m) => m);
  push('slack-token', /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/, (m) => m);
  push('stripe-key', /\b(?:sk|rk|pk)_(?:live|test)_[0-9a-zA-Z]{10,}\b/, (m) => m);
  push('private-key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/);
  push('jwt', /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/, (m) => m);
  return out;
}

/**
 * Capture every script a page loads, then try to fetch its source map.
 *
 * @param page     Playwright page
 * @param opts     {
 *                   maxScripts, fetchSourceMaps, settleMs,
 *                   url        navigate to this URL and capture from the start,
 *                   gotoOpts   override for page.goto
 *                 }
 *
 * Ordering matters. The response listener MUST be attached before navigation,
 * otherwise the page's own scripts have already loaded by the time capture
 * starts and the result is silently empty — which is exactly what happened the
 * first time this ran against a live target that served five bundles.
 */
async function capture(page, opts = {}) {
  const maxScripts = opts.maxScripts || 60;
  const captured = [];
  const seen = new Set();

  const listener = async (res) => {
    const url = res.url();
    if (seen.has(url) || captured.length >= maxScripts) return;
    const ct = (res.headers() || {})['content-type'] || '';
    if (!isAppScript(url, ct)) return;
    if (isThirdParty(url)) return;
    seen.add(url);
    try {
      const body = await res.body();
      const src = decodeBody(body, (res.headers() || {})['content-encoding'] || '');
      captured.push({ url, bytes: body.length, source: src, contentType: ct });
    } catch {
      // Body unavailable (redirect, aborted, or already navigated away). The
      // URL alone is still worth keeping so it can be fetched directly.
      captured.push({ url, bytes: 0, source: '', contentType: ct });
    }
  };

  page.on('response', listener);
  try {
    if (opts.url) {
      // Navigate with the listener already attached.
      await page.goto(opts.url, { waitUntil: 'domcontentloaded', timeout: opts.gotoTimeout || 30000 }).catch(() => {});
    }
    await page.waitForLoadState('networkidle', { timeout: opts.settleMs || 8000 }).catch(() => {});
    await page.waitForTimeout(opts.settleMs || 1500);

    // Anything served without a content-type we recognise still needs a second
    // look: some CDNs return application/octet-stream for .js.
    if (captured.length === 0) {
      for (const u of await page.evaluate(() => [...document.querySelectorAll('script[src]')].map((s) => s.src)).catch(() => [])) {
        if (!u || seen.has(u) || isThirdParty(u)) continue;
        if (!isAppScript(u)) continue;
        seen.add(u);
        try {
          const r = await page.request.get(u, { timeout: 8000 });
          if (r.ok()) captured.push({ url: u, bytes: (await r.body()).length, source: await r.text(), contentType: (r.headers() || {})['content-type'] || '' });
        } catch { /* unreadable; the url is still recorded below */ }
        if (captured.length === 0) captured.push({ url: u, bytes: 0, source: '', contentType: '' });
      }
    }
  } finally {
    page.off('response', listener);
  }

  // Source maps: usually the whole point. A published .map is the original
  // source with identifiers intact.
  if (opts.fetchSourceMaps !== false) {
    for (const c of captured.slice(0, 20)) {
      if (!c.source) continue;
      const ref = sourceMapRef(c.source);
      if (!ref) continue;
      const mapUrl = (() => { try { return new URL(ref, c.url).toString(); } catch { return null; } })();
      if (!mapUrl || isThirdParty(mapUrl)) continue;
      try {
        const r = await page.request.get(mapUrl, { timeout: 8000 });
        if (r.ok()) {
          const t = await r.text();
          // A real map has `sources`; reject an HTML error page.
          if (/"sources"\s*:/.test(t)) {
            const parsed = JSON.parse(t);
            const orig = (parsed.sourcesContent || []).filter((x) => typeof x === 'string' && x.length);
            if (orig.length) {
              c.sourceMap = { url: mapUrl, sources: parsed.sources.length, bytes: t.length };
              // Prefer original sources when they carry real content.
              c.source = orig.join('\n;\n');
              c.fromSourceMap = true;
            }
          }
        }
      } catch { /* a missing map is normal, not an error */ }
    }
  }

  return captured;
}

/** Analyse a capture set and return endpoints, secrets and logic findings. */
function analyseCapture(captured = [], baseUrl = '') {
  const endpoints = new Set();
  const secrets = [];
  const findings = [];
  let bytes = 0, minified = 0, fromMaps = 0;

  for (const c of captured) {
    bytes += c.bytes || 0;
    if (c.fromSourceMap) fromMaps++;
    const src = c.source || '';
    if (src) {
      for (const e of extractEndpoints(src, baseUrl)) endpoints.add(e);
      for (const s of extractSecrets(src)) secrets.push({ ...s, url: c.url });
      const a = analyseScript(src, { url: c.url, minified: c.minified });
      if (a.minified) minified++;
      for (const f of a.findings) findings.push({ ...f, script: c.url });
    }
    // The script URL itself is an endpoint-adjacent asset worth knowing.
    if (/\.js(\?|$)/i.test(c.url)) endpoints.add(c.url);
  }

  return {
    scripts: captured.length,
    bytes,
    minified,
    fromSourceMaps: fromMaps,
    endpoints: [...endpoints],
    secrets,
    findings,
  };
}

module.exports = {
  capture, analyseCapture, analyseScript, extractEndpoints, extractSecrets,
  stringLiterals, sourceMapRef, decodeBody, isAppScript, isThirdParty,
  THIRD_PARTY,
};
