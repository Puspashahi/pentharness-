'use strict';
const assert = require('assert');
const S = require('../src/secrets');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log(`  ok  ${name}`); pass++; }
  catch (e) { console.log(`  FAIL ${name}\n       ${e.message}`); fail++; }
}

console.log('\n== secret scanner ==');
t('detects provider-specific formats', () => {
  const src = [
    'AKIAIOSFODNN7EXAMPLE',
    'AIzaSyA1234567890abcdefghijklmnopqrstuv',
    'ghp_abcdefghijklmnopqrstuvwxyz01',
    'xoxb-123456789012-abcdefghijkl',
    'sk_live_1234567890abcdef',
    'SG.abcdefghijklmnop.qrstuvwxyz0123456789',
    'npm_abcdefghijklmnopqrstuvwxyz1234567890',
  ].join('\n');
  const kinds = new Set(S.scanText(src).map((x) => x.kind));
  for (const kind of ['aws-access-key', 'google-api-key', 'github-token', 'slack-token', 'stripe-key', 'sendgrid-key', 'npm-token']) {
    assert.ok(kinds.has(kind), `${kind} missing: ${[...kinds]}`);
  }
});
t('detects generic high-entropy assignments but rejects placeholders', () => {
  assert.ok(S.scanText('client_secret = "aB9_xY7-qP2!mN8@zK4#";').some((x) => x.kind === 'generic-secret-assignment'));
  assert.strictEqual(S.scanText('api_key = "changeme";').length, 0);
});
t('never returns the secret value', () => {
  const out = S.scanText('token = "aB9_xY7-qP2!mN8@zK4#";');
  assert.ok(out.length);
  assert.ok(!JSON.stringify(out).includes('aB9_xY7-qP2!mN8@zK4#'));
});
t('ordinary code is quiet', () => {
  assert.strictEqual(S.scanText('const answer = 42; function add(a,b){ return a+b; }').length, 0);
});
t('entropy is bounded and deterministic', () => {
  assert.strictEqual(S.entropy('aaaa'), 0);
  assert.ok(S.entropy('aB9_xY7-qP2!mN8@zK4#') > 3);
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
