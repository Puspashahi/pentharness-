'use strict';
const assert = require('assert');
const R = require('../src/replay');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createApprovalToken } = require('../src/approval');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log(`  ok  ${name}`); pass++; }
  catch (e) { console.log(`  FAIL ${name}\n       ${e.message}`); fail++; }
}

console.log('\n== replay engine ==');
t('scope-gates and blocks state changes by default', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pentharness-replay-'));
  const file = path.join(dir, 'a.jsonl');
  fs.writeFileSync(file, [
    JSON.stringify({ method: 'GET', url: 'https://api.test/me', headers: { Authorization: 'Bearer secret' } }),
    JSON.stringify({ method: 'POST', url: 'https://api.test/delete' }),
    JSON.stringify({ method: 'GET', url: 'https://outside.test/x' }),
  ].join('\n'));
  const result = R.plan([{ identity: 'alice', file }], { scope: ['api.test'], maxRequests: 100 });
  assert.strictEqual(result.requests.length, 2);
  assert.strictEqual(result.requests[1].replayable, false);
  assert.strictEqual(result.blocked.length, 1);
});
t('executes safe requests and redacts ambient credentials', async () => {
  const plan = R.plan([{ identity: 'alice', file: '/missing' }], { scope: ['api.test'], maxRequests: 100 });
  plan.requests = [{ identity: 'alice', method: 'GET', url: 'https://api.test/me', headers: { Authorization: 'Bearer secret' }, body: null, replayable: true }];
  const report = await R.execute(plan, async () => ({ status: 200, body: '{"ok":true}' }));
  assert.strictEqual(report.schemaVersion, 1);
  assert.match(report.observations[0].evidence.request.headers.Authorization, /redacted/i);
  assert.strictEqual(report.audit[0].decision, 'allow');
});
t('requires a scoped approval token for state-changing replay', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pentharness-replay-'));
  const file = path.join(dir, 'a.jsonl');
  fs.writeFileSync(file, JSON.stringify({ method: 'POST', url: 'https://api.test/update' }));
  assert.throws(
    () => R.plan([{ identity: 'alice', file }], { scope: ['api.test'], allowStateChange: true, approvalSecret: 'test-secret', maxRequests: 100 }),
    /approvalToken/,
  );
  const blocked = R.plan([{ identity: 'alice', file }], { scope: ['api.test'], maxRequests: 100 });
  assert.strictEqual(blocked.requests[0].replayable, false);
  const token = createApprovalToken({ action: 'state-change', scope: 'api.test', expiresAt: Date.now() + 60000, secret: 'test-secret' });
  const approved = R.plan([{ identity: 'alice', file }], { scope: ['api.test'], allowStateChange: true, approvalToken: token, approvalSecret: 'test-secret', maxRequests: 100 });
  assert.strictEqual(approved.requests[0].replayable, true);
  assert.ok(!JSON.stringify(approved).includes('test-secret'));
});
t('enforces hard request and byte budgets', async () => {
  const plan = R.plan([{ identity: 'alice', file: '/missing' }], { scope: ['api.test'], maxRequests: 100 });
  plan.requests = [
    { identity: 'alice', method: 'GET', url: 'https://api.test/1', headers: {}, body: '123', replayable: true },
    { identity: 'alice', method: 'GET', url: 'https://api.test/2', headers: {}, body: '123', replayable: true },
  ];
  await assert.rejects(() => R.execute(plan, async () => ({ status: 200, body: 'ok' }), { budget: { maxRequests: 1, maxBytes: 3 } }), /resource budget exceeded/);
});

Promise.resolve().then(() => {
  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
});
