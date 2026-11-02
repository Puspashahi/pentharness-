'use strict';
const assert = require('assert');
const W = require('../src/workflow');
const R = require('../src/race');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log(`  ok  ${name}`); pass++; }
  catch (e) { console.log(`  FAIL ${name}\n       ${e.message}`); fail++; }
}

console.log('\n== workflow engine ==');
t('discovers ordered transitions', () => {
  const steps = W.discoverTransitions([
    { id: 'create', stateAfter: 'created' },
    { id: 'pay', stateAfter: 'paid' },
  ]);
  assert.strictEqual(steps[1].stateBefore, 'created');
});
t('generates bounded skip/reorder/duplicate mutations', () => {
  const m = W.mutate({ steps: [{ id: 'a' }, { id: 'b' }, { id: 'c' }] }, { maxMutations: 5 });
  assert.strictEqual(m.length, 5);
  assert.ok(m.some((x) => x.kind === 'skip'));
  assert.ok(m.some((x) => x.kind === 'reorder'));
  assert.ok(m.some((x) => x.kind === 'duplicate'));
});
t('reports state status invariant hypotheses', () => {
  const r = W.analyzeSequence({
    states: { paid: { statuses: [201] } },
    steps: [{ id: 'pay', stateAfter: 'paid', effect: 'write' }],
  }, [{ status: 200 }]);
  assert.strictEqual(r.hypotheses.length, 1);
});

console.log('\n== race engine ==');
t('blocks state-changing races by default', async () => {
  const r = await R.runRace({}, { method: 'POST', url: 'https://t/pay' });
  assert.strictEqual(r.skipped, true);
});
t('measures duplicate concurrent success with explicit opt-in', async () => {
  const ctx = { request: { fetch: async () => ({ status: () => 201, text: async () => 'ok' }) } };
  const r = await R.runRace(ctx, { method: 'POST', url: 'https://t/coupon' }, { allowStateChange: true, rounds: 3 });
  assert.strictEqual(r.analysis.successfulResponses, 3);
  assert.strictEqual(r.analysis.duplicateAcceptance, true);
});

Promise.resolve().then(() => {
  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
});
