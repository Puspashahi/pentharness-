'use strict';

const assert = require('assert');
const { RequestBroker } = require('../src/request-broker');

async function main() {
  const seen = [];
  const broker = new RequestBroker({
    config: { scope: ['api.test'], maxRequests: 2, maxBytes: 100, maxConcurrency: 1 },
    transport: async (request) => { seen.push(request.url); return { status: 200, body: 'ok' }; },
  });
  const allowed = await broker.request({ method: 'GET', url: 'https://api.test/me' });
  assert.strictEqual(allowed.status, 200);
  const blocked = await broker.request({ method: 'GET', url: 'https://outside.test/me' });
  assert.strictEqual(blocked.blocked, true);
  assert.strictEqual(seen.length, 1);
  assert.deepStrictEqual(broker.audit.map((entry) => entry.decision), ['allow', 'block']);
  assert.match(broker.audit[1].reason, /scope/i);
  console.log('request-broker: ok');
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
