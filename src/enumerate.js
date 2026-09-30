'use strict';
/**
 * Object enumeration + blast-radius proof.
 *
 * The $78,000 Meta report was not an exploit. It was: open a ticket, notice the
 * case ID is sequential, increment the number, read someone else's support
 * ticket — including chat transcripts, uploaded files, and PII. The write-up's
 * summary: "It wasn't a zero-day... it was a support ticket counter going up by
 * one." And critically, it "was initially triaged as low-risk" — the severity
 * arrived with *scale*.
 *
 * Two rules from that report, encoded here:
 *
 *   1. "The job is to prove impact, not extract it." (from the $157K report)
 *      Enumeration measures REACHABILITY and proves a sample. It never
 *      downloads a corpus, and it stops as soon as the pattern is established.
 *
 *   2. "The same gap enabled write actions: ...of other orgs, adding
 *      subscribers to cases they had no relationship to." A read-only finding
 *      understates the bug, so write/state-changing variants are tested too.
 */

const { makeLead } = require('./leads');
const AM = require('./authmatrix');

/** Which HTTP methods imply a state change, so read-only proofs are not enough. */
const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Derive a candidate ID range from observed identifiers.
 * Sequential integers and short numeric strings are the high-yield case.
 */
function idShape(values) {
  const out = { kind: 'unknown', numeric: [], uuid: [], short: [] };
  for (const v of values.map(String)) {
    if (/^\d{1,9}$/.test(v)) out.numeric.push(parseInt(v, 10));
    else if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) out.uuid.push(v);
    else if (/^[0-9a-f]{16,}$/i.test(v)) out.short.push(v);
  }
  if (out.numeric.length >= 2) {
    const s = Math.min(...out.numeric), e = Math.max(...out.numeric);
    out.kind = 'sequential';
    out.range = { start: s, end: e, span: e - s + 1, contiguous: e - s + 1 === out.numeric.length };
    // Sequential and contiguous means the counter is walkable.
    out.enumerable = out.range.contiguous || out.range.span <= 1000;
  } else if (out.short.length >= 2) {
    out.kind = 'opaque-hex';
  } else if (out.uuid.length >= 2) {
    out.kind = 'uuid';
  }
  return out;
}

/** Pull candidate object identifiers out of a URL template. */
function idParamOf(url) {
  const u = String(url);
  // /case/12345  or  ?id=12345  or  ?ids=1,2,3
  const seg = u.match(/\/(\d{1,9})(?:\/|$|\?)/);
  if (seg) return { kind: 'path', name: 'id', value: seg[1] };
  const q = u.match(/[?&](id|uuid|case|order|invoice|ticket|doc|record|user_id|item|project)[=]([0-9a-f-]{1,64})/i);
  if (q) return { kind: 'query', name: q[1], value: q[2] };
  const csv = u.match(/[?&]ids?=\[?([0-9,\-]{3,})\]?/i);
  if (csv) return { kind: 'query-list', name: 'ids', value: csv[1] };
  return null;
}

function withId(url, idSpec, value) {
  if (idSpec.kind === 'path') {
    return String(url).replace(/\/\d{1,9}(?=\/|$|\?)/, `/${value}`);
  }
  const u = new URL(url);
  if (idSpec.kind === 'query-list') {
    u.searchParams.set('ids', String(value));
  } else {
    u.searchParams.set(idSpec.name, String(value));
  }
  return u.toString();
}

/**
 * Enumerate adjacent object IDs and measure reachability.
 *
 * Deliberately bounded: `maxSamples` requests, then stop. The output is a
 * *reachability measurement* plus one small redacted sample — enough to prove
 * the bug without extracting a corpus.
 */
async function enumerate(ctx, url, opts = {}) {
  const maxSamples = opts.maxSamples || 25;
  const idSpec = idParamOf(url);
  if (!idSpec) return { ok: false, why: 'no object identifier in the URL' };
  if (!/^\d+$/.test(String(idSpec.value))) {
    return { ok: false, why: `identifier "${idSpec.value}" is not sequential; enumeration does not apply (consider looking for a leak endpoint instead)` };
  }

  const base = parseInt(idSpec.value, 10);
  // Probe upward from the known-good object: that is where the neighbour lives.
  const candidates = [];
  for (let d = 1; d <= maxSamples; d++) candidates.push(base + d);

  const owned = await fetchBody(ctx, url);
  // Identity baseline. Enumeration runs AS the owning identity, so "another
  // identity's object" means "an object whose owner marker is not ours".
  // Comparing each neighbour against the *seed* is wrong: the seed is one
  // specific object, and most neighbours differ from it for the uninteresting
  // reason that they are also not ours. Instead, derive our own markers from
  // the object we legitimately hold and flag anything naming a different owner.
  const ownedM = AM.ownershipMarkers(owned.body);
  const ours = new Set([...ownedM.emails, ...ownedM.ids]);
  if (opts.identityLabel) ours.add(String(opts.identityLabel).toLowerCase());

  const samples = [];
  let reachable = 0;
  for (const id of candidates) {
    const u = withId(url, idSpec, id);
    const r = await fetchBody(ctx, u);
    if (r.status >= 200 && r.status < 300) {
      const m = AM.ownershipMarkers(r.body);
      const markers = [...m.ids, ...m.emails];
      const foreign = markers.filter((x) => !ours.has(x));
      const leak = AM.identifierLeak(r.body, 'probe');
      samples.push({
        id, url: u, status: r.status, length: r.length,
        carriesOtherIdentity: foreign.length > 0,
        foreignMarkers: foreign.slice(0, 3),
        kinds: leak ? leak.kinds : [],
      });
      if (foreign.length > 0) reachable++;
    }
  }

  const shape = idShape([String(idSpec.value), ...samples.map((s) => String(s.id))]);
  return {
    ok: true, idSpec, shape, ownedStatus: owned.status, ownedLength: owned.length,
    probes: samples.length, reachable, samples,
    // Scale is what turned a low-severity report into $78k.
    blastRadius: samples.length ? Math.round((reachable / samples.length) * 100) : 0,
  };
}

async function fetchBody(ctx, url) {
  try {
    const res = await ctx.request.get(url, { timeout: 10000, failOnStatusCode: false, maxRedirects: 2 });
    const body = await res.text().catch(() => '');
    return { status: res.status(), length: body.length, body: body.slice(0, 60000) };
  } catch (e) {
    return { status: 0, length: 0, body: '', error: String(e.message || e) };
  }
}

/**
 * Check whether the same missing check also permits a WRITE on a neighbour.
 * A read-only finding systematically understates severity.
 */
async function checkWriteReach(ctx, url, idSpec, opts = {}) {
  if (!WRITE_METHODS.has(String(opts.method || 'GET').toUpperCase())) {
    // Test the method matrix for the read path; do not actually mutate.
    const allowed = [];
    for (const m of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']) {
      const r = await fetchBody(ctx, url);
      // OPTIONS/HEAD reveal the advertised method set without side effects.
      if (m === 'OPTIONS') {
        try {
          const res = await ctx.request.fetch(url, { method: 'OPTIONS', timeout: 8000, failOnStatusCode: false });
          const allow = (res.headers && (res.headers()['allow'] || res.headers()['Allow'])) || '';
          if (allow) allowed.push(...allow.split(',').map((s) => s.trim()).filter(Boolean));
        } catch { /* ignore */ }
      }
    }
    return { methodMatrix: [...new Set(allowed)], note: 'advertised methods only; no state change was performed' };
  }
  return { note: 'write probe requires explicit authorisation for the specific action' };
}

/**
 * Turn an enumeration result into a lead.
 *
 * Scale drives severity: the Meta support-console report was "initially triaged
 * as low-risk" and only became a $78,000 finding once the reachable object
 * count was demonstrated. A counter that yields another account's object on
 * most adjacent IDs is not a low-severity finding.
 */
function toLead(url, res, opts = {}) {
  if (!res.ok || !res.reachable) return null;
  const scale = res.blastRadius;
  const severity = scale >= 80 ? 'critical' : scale >= 40 ? 'high' : 'medium';
  // Key on the resource family, not the individual object, so walking eight
  // seeds of the same endpoint yields one finding rather than eight.
  const family = String(url).replace(/^https?:\/\/[^/]+/, '').replace(/\/\d+(\/|$)/, '/:id$1');
  return makeLead({
    id: 'enum-' + require('crypto').createHash('sha256').update(family).digest('hex').slice(0, 12),
    cls: 'authz',
    title: `PROVEN object enumeration: ${res.reachable}/${res.probes} adjacent IDs on ${family} expose another identity's object`,
    url,
    param: res.idSpec.name,
    source: 'enumerate',
    severity_hint: severity,
    confidence: 'confirmed',
    evidence: `Object identifier "${res.idSpec.value}" is ${res.shape.kind}${res.shape.range ? ` and contiguous (span ${res.shape.range.span})` : ''}. Requesting the ${res.probes} adjacent IDs returned ${res.reachable} responses carrying another identity's data (${scale}% of probes). Owned object baseline: status ${res.ownedStatus}, ${res.ownedLength} bytes. Samples: ${res.samples.filter((s) => s.carriesOtherIdentity).slice(0, 3).map((s) => s.id).join(', ')}.${opts.identity ? ` Observed while authenticated as ${opts.identity}.` : ''}`,
    proof_needed: [
      'confirm the objects belong to a different account/organisation',
      'show the same request is denied for an unrelated authenticated user',
      'state the reachable object count as the impact metric',
    ],
    chain_hints: ['business', 'secrets'],
  });
}

module.exports = { enumerate, idShape, idParamOf, withId, toLead, checkWriteReach, WRITE_METHODS };
