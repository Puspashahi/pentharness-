'use strict';

const assert = require('assert');
const C = require('../src/capabilities');
const S = require('../src/run-status');

const matrix = new C.CapabilityMatrix([
  { id: 'idor', area: 'authz', state: 'proven', evidence: 'golden/idor.json' },
  { id: 'sqli', area: 'injection', state: 'planned', reason: 'fixture pending' },
]);
assert.strictEqual(matrix.toJSON().summary.proven, 1);
assert.strictEqual(matrix.toJSON().summary.planned, 1);
assert.throws(() => matrix.add({ id: 'x', area: 'x', state: 'invalid' }), /invalid capability state/);

assert.deepStrictEqual(S.classify(), { status: 'clean', exitCode: 0 });
assert.deepStrictEqual(S.classify({ findings: 1 }), { status: 'findings', exitCode: 10 });
assert.deepStrictEqual(S.classify({ coverageComplete: false }), { status: 'incomplete', exitCode: 11 });
assert.deepStrictEqual(S.classify({ policyBlocked: true }), { status: 'policy-blocked', exitCode: 12 });
assert.deepStrictEqual(S.classify({ infrastructureFailure: true }), { status: 'infrastructure-failure', exitCode: 13 });

console.log('capabilities-status: ok');
