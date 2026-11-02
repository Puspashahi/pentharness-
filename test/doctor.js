'use strict';

const assert = require('assert');
const D = require('../src/doctor');

const report = D.run({ root: process.cwd() });
assert.strictEqual(report.schemaVersion, 1);
assert.strictEqual(report.tool, 'pentharness-doctor');
assert.strictEqual(report.ok, true);
assert.strictEqual(report.exitCode, 0);
assert.ok(report.checks.some((item) => item.name === 'node' && item.status === 'ok'));
assert.ok(report.checks.some((item) => item.name === 'workspace-permissions' && item.status === 'ok'));
assert.match(D.format(report), /pentharness-doctor: ok/);

const missing = D.run({ root: '/definitely/missing/pentharness', requirePython: true });
assert.strictEqual(missing.ok, false);
assert.strictEqual(missing.exitCode, 2);

console.log('doctor: ok');
