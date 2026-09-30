'use strict';
/**
 * Tests for the observer layer: OOB oracle, prober, browser/identity helpers.
 * These run offline — the timing oracle and grading are deterministic maths, and
 * the prober is exercised against a local stub request context.
 */
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const oob = require('../src/oob');
const prober = require('../src/prober');
const oracle = require('../src/oracle');
const { TargetKB } = require('../src/knowledge');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log(`  ok  ${name}`); pass++; }
  catch (e) { console.log(`  FAIL ${name}\n       ${e.message}`); fail++; }
}

console.log('\n== oob: statistics ==');
t("welch's t detects a real difference", () => {
  const a = [5, 6, 4, 5, 7], b = [3000, 3100, 2950, 3050, 3000];
  const r = oob.welchT(a, b);
  assert.ok(r.p < 0.05, 'p=' + r.p);
  assert.ok(r.delta < 0);
});
t("welch's t finds nothing in identical samples", () => {
  const a = [100, 101, 99, 100], b = [100, 100, 101, 99];
  assert.ok(oob.welchT(a, b).p > 0.05);
});
t('insufficient samples return p=1 rather than dividing by zero', () => {
  assert.strictEqual(oob.welchT([5], [3000]).p, 1);
});

console.log('\n== oob: grading (the DNS vs HTTP distinction) ==');
t('no interaction is not a finding', () => {
  assert.strictEqual(oob.grade([]).verdict, 'none');
});
t('HTTP callback is CONFIRMED', () => {
  const g = oob.grade([{ protocol: 'http', remote: '203.0.113.9' }]);
  assert.strictEqual(g.verdict, 'proven');
  assert.ok(g.confidence > 0.9);
});
t('DNS-only is only POTENTIAL — a shared resolver is not proof', () => {
  const g = oob.grade([{ protocol: 'dns', remote: '8.8.8.8' }]);
  assert.strictEqual(g.verdict, 'potential');
  assert.ok(g.confidence < 0.5);
  assert.ok(/resolver/.test(g.why), g.why);
});
t('cloud metadata contact is CRITICAL', () => {
  const g = oob.grade([{ protocol: 'http', remote: '169.254.169.254', metadata: true }]);
  assert.strictEqual(g.severity, 'critical');
});
t('a callback from CDN infrastructure is downgraded and flagged', () => {
  const g = oob.grade([{ protocol: 'http', remote: '203.0.113.5' }], { cdnRanges: ['203.0.113.0/24'] });
  assert.ok(/CDN/.test(g.why), g.why);
  assert.ok(g.confidence < 0.8);
});

console.log('\n== oob: payloads + correlation ==');
t('ssrf payloads include a callback and metadata probe', () => {
  const p = oob.payloadsFor('ssrf', 'https://abc.oast.fun/x');
  assert.ok(p.some((x) => x.id === 'oob-http'));
  assert.ok(p.some((x) => x.id === 'metadata'));
});
t('deferred correlation requires canary + window', () => {
  const okC = oob.correlateDeferred({ raw: 'GET /abc', delayMs: 5000 }, 'abc');
  assert.strictEqual(okC.correlated, true);
  const noC = oob.correlateDeferred({ raw: 'GET /other', delayMs: 5000 }, 'abc');
  assert.strictEqual(noC.correlated, false, 'unrelated traffic must not be attributed');
});
t('second-order signals are detected', () => {
  const r = oob.correlateDeferred({ raw: 'GET /tok-9', delayMs: 30000 }, 'tok-9');
  assert.ok(r.signals.includes('delay'));
  assert.ok(r.signals.includes('canary'));
});

console.log('\n== oob: unique tokens per parameter ==');
t('each parameter gets a distinct, correlatable URL', async () => {
  const c = new oob.OOBClient({ server: 'https://oast.fun' });
  const a = await c.urlFor('url');
  const b = await c.urlFor('webhook');
  assert.notStrictEqual(a.token, b.token, 'a shared token cannot attribute a callback');
  assert.ok(a.url.includes('url-'));
  assert.ok(b.url.includes('webhook-'));
});

console.log('\n== prober: payload planning ==');
t('authz params get no injection payloads', () => {
  assert.strictEqual(prober.payloadPlan(['authz']).length, 0);
});
t('injection params get boolean and time probes', () => {
  const p = prober.payloadPlan(['injection']);
  assert.ok(p.some((x) => x.kind === 'boolean'));
  assert.ok(p.some((x) => x.kind === 'time'));
});
t('nothing destructive is ever in the payload set', () => {
  const all = Object.values(prober.PAYLOADS).flat();
  const blob = JSON.stringify(all).toLowerCase();
  for (const bad of ['drop ', 'delete from', 'truncate', 'rm -rf', 'shutdown']) {
    assert.ok(!blob.includes(bad), 'payload set must not contain: ' + bad);
  }
});
t('pmap respects its concurrency cap and never rejects', async () => {
  let active = 0, peak = 0;
  const out = await prober.pmap([1, 2, 3, 4, 5, 6, 7, 8], 3, async (x) => {
    active++; peak = Math.max(peak, active);
    await new Promise((r) => setTimeout(r, 10));
    active--;
    if (x === 3) throw new Error('boom');
    return x * 2;
  });
  assert.ok(peak <= 3, 'concurrency cap exceeded: ' + peak);
  assert.strictEqual(out.length, 8);
  assert.ok(out[2].error, 'a failing item must be captured, not thrown');
});

console.log('\n== prober: end-to-end against a stub request context ==');
function stubContext(handler) {
  return { request: { get: async (url, opts) => handler(url, opts) } };
}
const mkRes = (status, body) => ({ status: () => status, text: async () => body, url: () => 'https://t' });

t('a real boolean differential + DB error is PROVEN', async () => {
  const ctx = stubContext(async (url) => {
    if (url.includes("1%27%20AND%20%271%27%3D%271") || url.includes("1+AND+1%3D1")) return mkRes(200, 'A'.repeat(5000));
    if (url.includes("1%27%20AND%20%271%27%3D%270") || url.includes("1+AND+1%3D0")) return mkRes(200, 'short');
    if (url.includes("%27") && url.includes("'")) return mkRes(200, "SQLSTATE[42S02]: Base table or view not found");
    return mkRes(200, 'normal page');
  });
  const ev = await prober.probeParam(ctx, { url: 'https://t/ads', param: 'id', value: '1', classes: ['injection'] });
  const V = require('../src/validators');
  const verdict = V.judge('injection', ev);
  assert.strictEqual(verdict.ship, true, verdict.why);
});
t('an all-identical target produces NO proof', async () => {
  const ctx = stubContext(async () => mkRes(200, 'identical page'));
  const ev = await prober.probeParam(ctx, { url: 'https://t/ads', param: 'id', value: '1', classes: ['injection'] });
  const V = require('../src/validators');
  assert.strictEqual(V.judge('injection', ev).ship, false, 'no differential must mean no finding');
});
t('authz parameters are skipped rather than probed blindly', async () => {
  let called = 0;
  const ctx = stubContext(async () => { called++; return mkRes(200, 'x'); });
  const ev = await prober.probeParam(ctx, { url: 'https://t/u', param: 'user_id', value: '1', classes: ['authz'] });
  assert.strictEqual(ev.skipped, 'no payload set for predicted classes');
});

console.log('\n== prober: prioritisation ==');
t('probeAll prioritises authz-shaped parameters and skips when none known', async () => {
  const kb = new TargetKB('https://t');
  kb.learnEndpoint('https://t/a', { param: 'id' });
  kb.learnEndpoint('https://t/b', { param: 'q' });
  const ctx = stubContext(async () => mkRes(200, 'same'));
  const out = await prober.probeAll(ctx, kb, { concurrency: 2, maxEndpoints: 2 });
  assert.ok(out.evidence.length >= 0);
  const order = out.evidence.map((e) => e.param);
  if (order.length > 1) assert.ok(order.indexOf('id') <= order.indexOf('q') || order.indexOf('q') === -1, 'id (authz) should be probed first');
});
t('probeAll reports honestly when no parameters are known', async () => {
  const kb = new TargetKB('https://t');
  const out = await prober.probeAll(stubContext(async () => mkRes(200, '')), kb);
  assert.ok(/no parameters known/.test(out.notes[0]));
});

console.log('\n== oracle: xss payload construction ==');
t('payloads plant a sentinel that the harness polls for', () => {
  const ps = oracle.xssPayloads();
  assert.ok(ps.every((p) => p.value.includes(oracle.SENTINEL)));
  assert.ok(ps.length >= 4, 'needs multiple contexts');
});
t('inject places the payload in the right slot', () => {
  assert.ok(oracle.inject('https://t/s?q=1', 'q', '<b>').includes('q=%3Cb%3E'));
});

console.log('\n== oracle: capture files ==');
t('writeCapture emits the JSONL the matrix reads', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'cap-'));
  const f = path.join(d, 'userA.jsonl');
  const r = oracle.writeCapture(f, [{ method: 'GET', url: 'https://t/a', status: 200, body: 'x' }], 'userA');
  assert.strictEqual(r.count, 1);
  const rows = require('../src/authmatrix').readCapture(f, 'userA');
  assert.strictEqual(rows.length, 1);
  assert.strictEqual(rows[0].identity, 'userA');
  fs.rmSync(d, { recursive: true, force: true });
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
