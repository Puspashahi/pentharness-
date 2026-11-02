'use strict';

const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');
const { start } = require('./lab');
const { create: createRunManifest } = require('../src/run-manifest');

const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, 'manifest.json'), 'utf8'));

async function request(base, route, headers = {}) {
  const response = await fetch(`${base}${route}`, { headers });
  return { status: response.status, body: await response.text() };
}

async function main() {
  const startedAt = new Date().toISOString();
  const fixture = await start();
  const base = `http://127.0.0.1:${fixture.port}`;
  const executable = manifest.scenarios.filter((scenario) => scenario.status === 'executable');
  const results = [];
  let requests = 0;
  const started = performance.now();

  for (const scenario of executable) {
    const scenarioStart = performance.now();
    let observed = 'no-candidate';
    let reason = '';
    let evidence = {};
    if (scenario.id === 'idor-cross-user') {
      const owner = await request(base, scenario.route, { 'x-user': 'bob' });
      const foreign = await request(base, scenario.route, { 'x-user': 'alice' });
      requests += 2;
      observed = foreign.status === 200 && foreign.body.includes('"owner":"bob"') ? 'candidate' : 'no-candidate';
      reason = `owner=${owner.status}, foreign=${foreign.status}, foreignContainsOwner=${foreign.body.includes('"owner":"bob"')}`;
      evidence = {
        requestCount: 2,
        identities: ['bob', 'alice'],
        statuses: [owner.status, foreign.status],
        ownershipMarker: foreign.body.includes('"owner":"bob"'),
      };
    } else if (scenario.id === 'reflected-xss') {
      const payload = '<benchmark-xss>';
      const response = await request(base, `/search?q=${encodeURIComponent(payload)}`);
      requests++;
      observed = response.status === 200 && response.body.includes(payload) ? 'candidate' : 'no-candidate';
      reason = `status=${response.status}, reflected=${response.body.includes(payload)}`;
      evidence = {
        requestCount: 1,
        status: response.status,
        payload,
        reflected: response.body.includes(payload),
      };
    } else if (scenario.id === 'secure-owner-control') {
      const owner = await request(base, scenario.route, { 'x-user': 'alice' });
      const foreign = await request(base, scenario.route, { 'x-user': 'bob' });
      requests += 2;
      observed = foreign.status === 200 ? 'candidate' : 'no-candidate';
      reason = `owner=${owner.status}, foreign=${foreign.status}`;
      evidence = {
        requestCount: 2,
        identities: ['alice', 'bob'],
        statuses: [owner.status, foreign.status],
        deniedForeign: foreign.status === 403,
      };
    }
    results.push({
      id: scenario.id,
      class: scenario.class,
      expected: scenario.expectation,
      observed,
      outcome: observed === scenario.expectation ? 'true-positive' : 'false-negative',
      reason,
      evidence,
      proofMs: Math.round((performance.now() - scenarioStart) * 100) / 100,
    });
  }

  const planned = manifest.scenarios.filter((scenario) => scenario.status !== 'executable');
  for (const scenario of planned) {
    results.push({
      id: scenario.id,
      class: scenario.class,
      expected: 'unsupported',
      observed: 'unsupported',
      outcome: 'not-tested',
      reason: 'fixture and oracle are not implemented yet',
      proofMs: 0,
    });
  }

  const truePositives = results.filter((result) => result.outcome === 'true-positive').length;
  const falsePositives = results.filter((result) => result.expected === 'no-candidate' && result.observed === 'candidate').length;
  const falseNegatives = results.filter((result) => result.expected === 'candidate' && result.observed !== 'candidate').length;
  const report = {
    schemaVersion: 1,
    tool: 'pentharness-benchmark',
    safety: manifest.safety,
    manifest: 'benchmark/manifest.json',
    runManifest: createRunManifest({
      root: path.join(__dirname, '..'),
      startedAt,
      finishedAt: new Date().toISOString(),
      options: { mode: 'local-benchmark', loopbackOnly: true },
    }),
    metrics: {
      scenarios: manifest.scenarios.length,
      executable: executable.length,
      tested: executable.length,
      notTested: planned.length,
      truePositives,
      falsePositives,
      falseNegatives,
      requests,
      proofMs: Math.round((performance.now() - started) * 100) / 100,
      coverage: executable.length / manifest.scenarios.length,
    },
    results,
  };
  await new Promise((resolve) => fixture.server.close(resolve));
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  process.exitCode = falseNegatives || falsePositives ? 1 : 0;
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
