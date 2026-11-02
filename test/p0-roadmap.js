'use strict';
const assert = require('assert');
const D = require('../src/differential');
const A = require('../src/api-sequence');
const L = require('../src/auth-lifecycle');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log(`  ok  ${name}`); pass++; }
  catch (e) { console.log(`  FAIL ${name}\n       ${e.message}`); fail++; }
}

console.log('\n== semantic differential ==');
t('ignores irrelevant body changes but detects ownership changes', () => {
  const r = D.compare(
    { status: 200, body: JSON.stringify({ owner_id: 'alice', nonce: '1' }) },
    { status: 200, body: JSON.stringify({ owner_id: 'bob', nonce: '2' }) },
  );
  assert.ok(r.differs);
  assert.ok(r.changes.some((x) => x.kind === 'ownership-field'));
});
t('redacts security fields in semantic shapes', () => {
  const r = D.semanticShape({ status: 200, body: JSON.stringify({ access_token: 'live-secret' }) });
  assert.strictEqual(r.securityFields.access_token, '<redacted>');
});

console.log('\n== API sequence planner ==');
t('ingests OpenAPI operations and creates lifecycle sequences', () => {
  const r = A.plan({ paths: {
    '/orders': { get: { operationId: 'listOrders' } },
    '/orders/{id}': { get: { operationId: 'getOrder' }, post: { operationId: 'updateOrder' } },
  } });
  assert.strictEqual(r.operations.length, 3);
  assert.ok(r.sequences.some((s) => s.kind === 'lifecycle'));
});

console.log('\n== auth lifecycle ==');
t('detects session fixation and logout invalidation', () => {
  const r = L.analyzeLifecycle({
    preLogin: { session: 'same' },
    postLogin: { session: 'same' },
    logout: { oldSessionAccepted: true },
  });
  assert.ok(r.issues.some((x) => x.kind === 'session-fixation'));
  assert.ok(r.issues.some((x) => x.kind === 'logout-invalidation'));
});
t('classifies secure session cookies', () => {
  const r = L.classifyCookie({ name: 'session', secure: true, httpOnly: true, sameSite: 'Lax' });
  assert.ok(r.sessionLike && r.secure && r.httpOnly);
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
