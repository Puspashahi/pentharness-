'use strict';
const assert = require('assert');
const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const { validate } = require('../src/evidence-contract');

const result = spawnSync(process.execPath, [path.join(__dirname, '..', 'benchmark', 'run.js')], { encoding: 'utf8' });
assert.strictEqual(result.status, 0, result.stderr);
const report = JSON.parse(result.stdout);
assert.deepStrictEqual(validate(report), []);
assert.strictEqual(report.runManifest.schemaVersion, 1);
assert.match(report.runManifest.runId, /^[0-9a-f-]{36}$/);
assert.match(report.runManifest.startedAt, /^\d{4}-\d{2}-\d{2}T/);
assert.match(report.runManifest.finishedAt, /^\d{4}-\d{2}-\d{2}T/);
assert.ok(report.runManifest.inputs.benchmarkManifestSha256.match(/^[a-f0-9]{64}$/));
assert.ok(report.runManifest.inputs.packageJsonSha256.match(/^[a-f0-9]{64}$/));
assert.strictEqual(report.runManifest.options.loopbackOnly, true);
assert.strictEqual(report.runManifest.environment.cwd, path.join(__dirname, '..'));
assert.ok(report.runManifest.tools.node.startsWith('v'));
assert.strictEqual(report.tool, 'pentharness-benchmark');
assert.strictEqual(report.metrics.falsePositives, 0);
assert.strictEqual(report.metrics.falseNegatives, 0);
assert.strictEqual(report.metrics.tested, 3);
assert.strictEqual(report.metrics.notTested, 7);
assert.ok(report.metrics.coverage > 0 && report.metrics.coverage < 1);
assert.ok(report.results.some((item) => item.id === 'idor-cross-user' && item.outcome === 'true-positive'));
assert.ok(report.results.some((item) => item.id === 'secure-owner-control' && item.expected === 'no-candidate'));

for (const id of ['idor-cross-user', 'reflected-xss', 'secure-owner-control']) {
  const golden = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'benchmark', 'golden', `${id}.json`), 'utf8'));
  const actual = report.results.find((item) => item.id === id);
  assert.ok(actual, `missing benchmark result: ${id}`);
  assert.deepStrictEqual(
    { id: actual.id, class: actual.class, expected: actual.expected, observed: actual.observed, outcome: actual.outcome, evidence: actual.evidence },
    golden,
    `golden evidence mismatch: ${id}`,
  );
}
console.log('benchmark: ok');
