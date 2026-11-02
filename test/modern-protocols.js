'use strict';
const assert = require('assert');
const WS = require('../src/websocket');
const G = require('../src/grpc');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log(`  ok  ${name}`); pass++; }
  catch (e) { console.log(`  FAIL ${name}\n       ${e.message}`); fail++; }
}

console.log('\n== websocket analysis ==');
t('finds handlers lacking origin and auth checks', () => {
  const r = WS.analyze(`socket.onmessage = (e) => { if (e.data.action === "admin") socket.send(e.data); };`);
  assert.ok(r.findings.some((x) => x.kind === 'missing-origin-check'));
  assert.ok(r.findings.some((x) => x.kind === 'missing-message-authorization'));
});
t('does not report missing origin when checked', () => {
  const r = WS.analyze(`socket.addEventListener("message", e => { if (e.origin !== "https://app.test" && e.data.token) return; });`);
  assert.ok(!r.findings.some((x) => x.kind === 'missing-origin-check'));
});

console.log('\n== grpc analysis ==');
t('parses services and streaming RPCs', () => {
  const r = G.parseProto('service Billing { rpc GetInvoice (InvoiceRequest) returns (Invoice); rpc streamInvoices (stream InvoiceRequest) returns (stream Invoice); }');
  assert.strictEqual(r.length, 1);
  assert.strictEqual(r[0].methods.length, 2);
  assert.strictEqual(r[0].methods[1].streaming, true);
});
t('flags sensitive RPCs without auth metadata signals', () => {
  const r = G.analyze('service Admin { rpc DeleteUser (DeleteRequest) returns (Reply); }');
  assert.ok(r.findings.some((x) => x.method === 'DeleteUser'));
});
t('auth metadata suppresses the static auth-signal lead', () => {
  const r = G.analyze('import "auth.proto"; service Admin { rpc DeleteUser (DeleteRequest) returns (Reply); } // authorization metadata');
  assert.strictEqual(r.findings.length, 0);
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
