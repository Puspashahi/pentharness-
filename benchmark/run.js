'use strict';

const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');
const { start } = require('./lab');
const { create: createRunManifest } = require('../src/run-manifest');
const { fromManifest } = require('../src/capabilities');
const { RequestBroker } = require('../src/request-broker');

const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, 'manifest.json'), 'utf8'));

function createBenchmarkBroker() {
  return new RequestBroker({
    config: { scope: ['127.0.0.1'], maxRequests: 100, maxBytes: 1024 * 1024, maxConcurrency: 2 },
    transport: async ({ url, method, headers, body, upgrade: wantsUpgrade }) => {
      if (!wantsUpgrade) {
        const response = await fetch(url, { method, headers, body, redirect: 'manual' });
        return {
          response: {
            status: response.status,
            headers: Object.fromEntries(response.headers.entries()),
            url: response.url,
          },
          body: await response.text(),
        };
      }

      const target = new URL(url);
      return new Promise((resolve, reject) => {
        const req = require('http').request({
          hostname: target.hostname,
          port: target.port,
          path: target.pathname + target.search,
          method,
          headers: { Connection: 'Upgrade', Upgrade: 'websocket', ...headers },
        });
        req.on('upgrade', (response, socket) => {
          let responseBody = '';
          socket.on('data', (chunk) => { responseBody += chunk; });
          socket.on('end', () => resolve({
            response: {
              status: response.statusCode,
              headers: response.headers,
              url,
            },
            body: responseBody,
          }));
        });
        req.on('response', (response) => {
          response.resume();
          reject(new Error(`upgrade rejected with status ${response.statusCode}`));
        });
        req.on('error', reject);
        req.end(body);
      });
    },
  });
}

function createClient(broker) {
  async function send(base, route, headers = {}, options = {}) {
    const body = options.body;
    const result = await broker.request({
      url: `${base}${route}`,
      method: options.method || 'GET',
      headers: { ...(headers || {}), ...(body ? { 'content-type': 'application/json' } : {}) },
      body,
      phase: 'benchmark',
      authorizationBasis: 'local-loopback-fixture',
      approval: options.method && options.method !== 'GET' ? { approved: true, reason: 'benchmark fixture' } : undefined,
      upgrade: options.upgrade === true,
    });
    if (result.blocked) throw new Error(`benchmark request blocked: ${result.reason}`);
    return {
      status: result.response.status,
      body: result.body,
      headers: result.response.headers || {},
    };
  }

  return {
    request: send,
    upgrade: (base, route, headers = {}) => send(base, route, headers, { upgrade: true }),
  };
}

async function main() {
  const startedAt = new Date().toISOString();
  const fixture = await start();
  const base = `http://127.0.0.1:${fixture.port}`;
  const broker = createBenchmarkBroker();
  const client = createClient(broker);
  const request = client.request;
  const upgrade = client.upgrade;
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
    } else if (scenario.id === 'sqli') {
      const baseline = await request(base, '/api/search?q=benchmark');
      const probe = await request(base, '/api/search?q=' + encodeURIComponent("' OR '1'='1"));
      requests += 2;
      observed = probe.status === 500 && baseline.status === 200 ? 'candidate' : 'no-candidate';
      reason = `baseline=${baseline.status}, probe=${probe.status}, errorDifferential=${probe.status !== baseline.status}`;
      evidence = { requestCount: 2, baselineStatus: baseline.status, probeStatus: probe.status, errorDifferential: probe.status !== baseline.status };
    } else if (scenario.id === 'ssrf') {
      const target = `${base}/internal`;
      const response = await request(base, `/api/fetch?url=${encodeURIComponent(target)}`);
      requests++;
      observed = response.status === 200 && response.body.includes('internal-benchmark') ? 'candidate' : 'no-candidate';
      reason = `status=${response.status}, internalMarker=${response.body.includes('internal-benchmark')}`;
      evidence = { requestCount: 1, status: response.status, callbackTarget: 'loopback fixture', internalMarker: response.body.includes('internal-benchmark') };
    } else if (scenario.id === 'race-condition') {
      const responses = await Promise.all([
        request(base, scenario.route, {}, { method: 'POST', body: '{}' }),
        request(base, scenario.route, {}, { method: 'POST', body: '{}' }),
      ]);
      requests += 2;
      const accepted = responses.filter((response) => response.status === 200).length;
      observed = accepted > 1 ? 'candidate' : 'no-candidate';
      reason = `concurrentRequests=2, accepted=${accepted}`;
      evidence = { requestCount: 2, statuses: responses.map((response) => response.status), accepted };
    } else if (scenario.id === 'graphql-authz') {
      const owner = await request(base, scenario.route, { 'x-user': 'alice' }, { method: 'POST', body: JSON.stringify({ query: 'query Order($id: ID!) { order(id: $id) { id owner total } }', variables: { id: '1' } }) });
      const foreign = await request(base, scenario.route, { 'x-user': 'alice' }, { method: 'POST', body: JSON.stringify({ query: 'query Order($id: ID!) { order(id: $id) { id owner total } }', variables: { id: '2' } }) });
      requests += 2;
      observed = foreign.status === 200 && foreign.body.includes('"owner":"bob"') ? 'candidate' : 'no-candidate';
      reason = `owner=${owner.status}, foreign=${foreign.status}, foreignOwnerData=${foreign.body.includes('"owner":"bob"')}`;
      evidence = { requestCount: 2, statuses: [owner.status, foreign.status], identity: 'alice', foreignOwnerData: foreign.body.includes('"owner":"bob"') };
    } else if (scenario.id === 'oauth') {
      const response = await request(base, `/oauth/authorize?client_id=benchmark&redirect_uri=${encodeURIComponent('https://attacker.invalid/callback')}&state=s1`);
      requests++;
      const       location = response.headers.location || '';
      observed = response.status === 302 ? 'candidate' : 'no-candidate';
      reason = `status=${response.status}, redirectUriAccepted=${response.status === 302}`;
      evidence = { requestCount: 1, status: response.status, redirectUri: 'https://attacker.invalid/callback', redirectAccepted: response.status === 302, location };
    } else if (scenario.id === 'websocket-authz') {
      const response = await upgrade(base, scenario.route, { 'x-user': 'alice' });
      requests++;
      const foreignOwnerData = response.headers['x-benchmark-owner'] === 'bob' || response.body.includes('"owner":"bob"');
      observed = response.status === 101 && foreignOwnerData ? 'candidate' : 'no-candidate';
      reason = `status=${response.status}, foreignOwnerData=${foreignOwnerData}`;
      evidence = { requestCount: 1, status: response.status, upgrade: response.status === 101, foreignOwnerData };
    } else if (scenario.id === 'mcp-tool-authz') {
      const response = await request(base, scenario.route, { 'x-user': 'alice' }, { method: 'POST', body: JSON.stringify({ tool: 'get_order', arguments: { id: '2' } }) });
      requests++;
      observed = response.status === 200 && response.body.includes('"owner":"bob"') ? 'candidate' : 'no-candidate';
      reason = `status=${response.status}, crossUserToolData=${response.body.includes('"owner":"bob"')}`;
      evidence = { requestCount: 1, status: response.status, tool: 'get_order', crossUserToolData: response.body.includes('"owner":"bob"') };
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
    capabilities: fromManifest(manifest).toJSON(),
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
    policy: broker.toJSON(),
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
