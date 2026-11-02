'use strict';
const assert = require('assert');
const O = require('../src/openapi');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log(`  ok  ${name}`); pass++; }
  catch (e) { console.log(`  FAIL ${name}\n       ${e.message}`); fail++; }
}

console.log('\n== OpenAPI planner ==');
t('builds safe read and approval-gated write plans', () => {
  const result = O.plan({
    openapi: '3.0.3',
    info: { title: 'Billing' },
    servers: [{ url: 'https://api.test/v1' }],
    paths: {
      '/invoices/{id}': {
        get: { operationId: 'getInvoice', parameters: [{ name: 'id', in: 'path', required: true, example: 'inv-1' }] },
        delete: { operationId: 'deleteInvoice', parameters: [{ name: 'id', in: 'path', required: true, example: 'inv-1' }] },
      },
    },
  });
  assert.strictEqual(result.operations[0].request.url, 'https://api.test/v1/invoices/inv-1');
  assert.strictEqual(result.sequences[0].safeToReplay, true);
  assert.strictEqual(result.sequences[1].approvalRequired, true);
});
t('derives body examples without inventing network activity', () => {
  const result = O.plan({ paths: { '/users': { post: { requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { role: { enum: ['user'] } } } } } } } } } });
  assert.deepStrictEqual(result.operations[0].request.body, { role: 'user' });
  assert.match(result.safety, /no network requests/);
});
t('creates stable provenance fingerprints', () => {
  assert.strictEqual(O.provenance({ b: 2, a: 1 }).digest, O.provenance({ a: 1, b: 2 }).digest);
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
