'use strict';
/**
 * Web cache poisoning via unkeyed headers.
 *
 * If a header is reflected into a response but is NOT part of the cache key,
 * an attacker can seed a cached response containing their own injected content,
 * which is then served to every subsequent visitor. This has produced paid
 * reports (Host-header cache poisoning on Shopify's themes host is in the
 * disclosed set) and is the same primitive PageBreak credits with an XSS found
 * from a service misconfiguration.
 *
 * The test is a two-request differential:
 *   1. send a unique canary in a candidate header  -> is it reflected?
 *   2. send the same request again WITHOUT the header
 *      -> if the canary is still present, the response was cached and the
 *         header is unkeyed, i.e. poisonable.
 */

const crypto = require('crypto');
const { makeLead } = require('./leads');

/** Headers commonly reflected but omitted from the cache key. */
const CANDIDATE_HEADERS = [
  'x-forwarded-host', 'x-host', 'x-original-host', 'x-rewrite-url',
  'x-forwarded-server', 'x-forwarded-for', 'x-original-url', 'x-originating-ip',
  'x-http-method-override', 'x-override-url', 'forwarded', 'x-custom-ip-authorization',
  'x-forwarded-proto', 'x-forwarded-prefix', 'x-amz-cf-pop',
];

const canary = (n = 8) => crypto.randomBytes(n).toString('hex');

/** Where a reflected header value might appear in the body. */
function appearsIn(body, value) {
  if (!body) return false;
  const b = String(body);
  if (b.includes(value)) return true;
  // Also catch URL-encoded and JSON-escaped forms.
  return b.includes(encodeURIComponent(value)) || b.includes(value.replace(/[^a-z0-9]/gi, ''));
}

/**
 * Probe one URL for an unkeyed, reflected header.
 * @param ctx request context
 */
async function probeHeader(ctx, url, header, opts = {}) {
  const value = opts.value || canary(6);
  const attempts = opts.attempts || 2;

  // 1. Seed with the header set.
  const seeded = await fetchWith(ctx, url, { [header]: value });
  if (!seeded.ok) return { header, poisoned: false, reason: seeded.reason, seeded };
  if (!appearsIn(seeded.body, value)) {
    return { header, poisoned: false, reason: 'header not reflected in the body', seeded };
  }

  // 2. Re-request WITHOUT the header. Reflection on a clean request is a
  //    different bug (header injection); reflection on a *cached* response is
  //    cache poisoning.
  const cached = [];
  for (let i = 0; i < attempts; i++) {
    const clean = await fetchWith(ctx, url, {});
    if (clean.ok && appearsIn(clean.body, value)) cached.push(clean);
  }

  if (cached.length) {
    return {
      header, poisoned: true, value,
      seeded, clean: cached[0],
      reason: `canary present on a request that did not send the header (${cached.length}/${attempts + 1} responses)`,
    };
  }
  return {
    header, poisoned: false, reflectedOnly: true, value, seeded,
    reason: 'header is reflected but not cached — reflection only, not poisonable',
  };
}

async function fetchWith(ctx, url, extraHeaders) {
  try {
    const r = await ctx.request.fetch(url, {
      method: 'GET',
      headers: { ...extraHeaders },
      timeout: 12000,
      failOnStatusCode: false,
    });
    return { ok: true, status: r.status(), body: (await r.text().catch(() => '')).slice(0, 200000) };
  } catch (e) {
    return { ok: false, reason: String(e.message || e).slice(0, 120) };
  }
}

/** Probe every candidate header against a URL. */
async function probe(ctx, url, opts = {}) {
  const headers = opts.headers || CANDIDATE_HEADERS;
  const found = [];
  const examined = [];
  for (const h of headers) {
    const r = await probeHeader(ctx, url, h, opts);
    examined.push({ header: h, poisoned: r.poisoned, reason: r.reason });
    if (r.poisoned) found.push(r);
    if (found.length >= (opts.maxFindings || 3)) break;
  }
  return { url, found, examined };
}

function toLeads(result, opts = {}) {
  const leads = [];
  for (const f of result.found) {
    leads.push(makeLead({
      cls: 'xss',
      title: `Web cache poisoning: ${f.header} is unkeyed and reflected`,
      url: result.url,
      source: 'cache',
      severity_hint: 'high',
      confidence: 'confirmed',
      confidence: 'confirmed',
      evidence: `Sent "${f.header}: ${f.value}". The value appeared in ${f.reason}. An attacker can seed a cached response containing their own content, which is then served to other visitors.`,
      proof_needed: [
        'show the seeded value is served to a request that never sent the header',
        'demonstrate the injected value executes as script for an unrelated visitor',
        'identify whether a CDN or reverse proxy sits in front of the origin',
      ],
      chain_hints: ['business'],
    }));
  }
  return leads;
}

module.exports = { CANDIDATE_HEADERS, probe, probeHeader, toLeads, appearsIn, canary };
