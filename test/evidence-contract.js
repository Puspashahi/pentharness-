'use strict';
const assert = require('assert');
const C = require('../src/evidence-contract');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log(`  ok  ${name}`); pass++; }
  catch (e) { console.log(`  FAIL ${name}\n       ${e.message}`); fail++; }
}

console.log('\n== evidence contract ==');
t('normalizes reports from every producer', () => {
  const report = C.normalize({ tool: 'python', candidates: [] });
  assert.strictEqual(report.schemaVersion, 1);
  assert.deepStrictEqual(C.validate(report), []);
});
t('rejects malformed or unversioned reports', () => {
  assert.ok(C.validate({ tool: '', safety: '', schemaVersion: 0 }).length >= 3);
});
t('accepts stable provenance fingerprints', () => {
  const a = C.digest({ b: 2, a: 1 });
  const b = C.digest({ a: 1, b: 2 });
  assert.strictEqual(a, b);
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
