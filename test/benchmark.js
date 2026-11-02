'use strict';
const assert = require('assert');
const { spawnSync } = require('child_process');
const path = require('path');

const result = spawnSync(process.execPath, [path.join(__dirname, '..', 'benchmark', 'run.js')], { encoding: 'utf8' });
assert.strictEqual(result.status, 0, result.stderr);
const report = JSON.parse(result.stdout);
assert.strictEqual(report.tool, 'pentharness-benchmark');
assert.strictEqual(report.metrics.falsePositives, 0);
assert.strictEqual(report.metrics.falseNegatives, 0);
assert.strictEqual(report.metrics.tested, 3);
assert.strictEqual(report.metrics.notTested, 7);
assert.ok(report.metrics.coverage > 0 && report.metrics.coverage < 1);
assert.ok(report.results.some((item) => item.id === 'idor-cross-user' && item.outcome === 'true-positive'));
assert.ok(report.results.some((item) => item.id === 'secure-owner-control' && item.expected === 'no-candidate'));
console.log('benchmark: ok');
