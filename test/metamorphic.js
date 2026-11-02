'use strict';
const assert = require('assert');
const M = require('../src/metamorphic');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log(`  ok  ${name}`); pass++; }
  catch (e) { console.log(`  FAIL ${name}\n       ${e.message}`); fail++; }
}

console.log('\n== metamorphic testing ==');
t('requires repeated stable samples', () => {
  const r = M.evaluateCase({
    id: 'unstable',
    relation: 'presentation-invariance',
    baseline: [{ status: 200, body: '{"owner_id":"a"}' }],
    variant: [{ status: 200, body: '{"owner_id":"b"}' }],
  });
  assert.strictEqual(r.verdict, 'hold');
});
t('detects stable ownership drift under presentation mutation', () => {
  const sample = { status: 200, body: '{"owner_id":"alice","name":"A"}' };
  const changed = { status: 200, body: '{"owner_id":"bob","name":"B"}' };
  const r = M.evaluateCase({
    id: 'display-change',
    relation: 'presentation-invariance',
    baseline: [sample, sample],
    variant: [changed, changed],
  });
  assert.strictEqual(r.verdict, 'candidate');
  assert.ok(r.proof_needed.length > 0);
});
t('refutes a secure permission revocation', () => {
  const r = M.evaluateCase({
    id: 'revoke',
    relation: 'permission-revocation',
    before: [{ status: 200, body: '{"id":"x"}' }, { status: 200, body: '{"id":"x"}' }],
    after: [{ status: 403, body: 'denied' }, { status: 403, body: 'denied' }],
  });
  assert.strictEqual(r.verdict, 'refuted');
});
t('detects access retained after logout', () => {
  const r = M.evaluateCase({
    id: 'logout',
    relation: 'logout-invalidation',
    before: [{ status: 200, body: '{"id":"x"}' }, { status: 200, body: '{"id":"x"}' }],
    after: [{ status: 200, body: '{"id":"x"}' }, { status: 200, body: '{"id":"x"}' }],
  });
  assert.strictEqual(r.verdict, 'candidate');
});
t('records invalid and unstable cases as contradictions', () => {
  const r = M.evaluate([{ id: 'bad', relation: 'missing' }]);
  assert.strictEqual(r.contradictions.length, 1);
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
