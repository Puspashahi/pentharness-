'use strict';
const assert = require('assert');
const T = require('../src/tenant-graph');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log(`  ok  ${name}`); pass++; }
  catch (e) { console.log(`  FAIL ${name}\n       ${e.message}`); fail++; }
}

console.log('\n== multi-tenant relationship graph ==');
t('models membership, ownership, and tenant boundaries', () => {
  const r = T.build([
    { userId: 'alice', tenantId: 'org-a', resourceId: 'invoice-a', owner: true },
    { userId: 'bob', tenantId: 'org-b', resourceId: 'invoice-a' },
  ]);
  assert.ok(r.nodes.some((n) => n.key === 'user:alice'));
  assert.ok(r.edges.some((e) => e.relation === 'owns'));
  assert.ok(r.candidates.some((c) => c.actor === 'user:bob' && c.target === 'resource:invoice-a'));
});
t('does not infer a cross-tenant candidate for same-tenant users', () => {
  const r = T.build([
    { userId: 'alice', tenantId: 'org-a', resourceId: 'doc', owner: true },
    { userId: 'bob', tenantId: 'org-a', resourceId: 'doc' },
  ]);
  assert.strictEqual(r.candidates.length, 0);
});
t('tracks contradictory access observations', () => {
  const r = T.build([
    { userId: 'bob', tenantId: 'org-b', resourceId: 'invoice-a', access: 'denied', status: 403 },
    { userId: 'bob', tenantId: 'org-b', resourceId: 'invoice-a', access: 'allowed', status: 200 },
  ]);
  assert.strictEqual(r.contradictions.length, 1);
});
t('keeps hypotheses below confirmed finding status', () => {
  const r = T.build([{ userId: 'bob', tenantId: 'org-b', resourceId: 'invoice-a' }, { userId: 'alice', tenantId: 'org-a', resourceId: 'invoice-a', owner: true }]);
  assert.ok(r.candidates.every((c) => c.confidence === 'candidate'));
  assert.match(r.proof_policy, /no vulnerability is confirmed/i);
});
t('validates a modeled disclosure from identical captured requests', () => {
  const model = T.build([
    { userId: 'alice', tenantId: 'org-a', resourceId: 'invoice-a', owner: true },
    { userId: 'bob', tenantId: 'org-b', resourceId: 'invoice-a' },
  ]);
  const r = T.proveFromCaptures(model, [
    { id: 'alice', data: [{ method: 'GET', url: '/api/invoice-a', status: 200, body: '{"owner_id":"alice","amount":42}' }] },
    { id: 'bob', data: [{ method: 'GET', url: '/api/invoice-a', status: 200, body: '{"owner_id":"alice","amount":42}' }] },
  ]);
  assert.strictEqual(r.validated.length, 1);
  assert.strictEqual(r.validated[0].confidence, 'runtime-validated');
});
t('does not validate a foreign response without owner markers', () => {
  const model = T.build([
    { userId: 'alice', tenantId: 'org-a', resourceId: 'invoice-a', owner: true },
    { userId: 'bob', tenantId: 'org-b', resourceId: 'invoice-a' },
  ]);
  const r = T.proveFromCaptures(model, [
    { id: 'alice', data: [{ method: 'GET', url: '/api/invoice-a', status: 200, body: '{"owner_id":"alice"}' }] },
    { id: 'bob', data: [{ method: 'GET', url: '/api/invoice-a', status: 200, body: '{"message":"not found"}' }] },
  ]);
  assert.strictEqual(r.validated.length, 0);
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
