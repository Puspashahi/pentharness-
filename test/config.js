'use strict';

const assert = require('assert');
const { resolve, publicConfig } = require('../src/config');

const config = resolve({ scope: ['api.test'], execute: true, maxRequests: 4, headers: { 'X-Research': 'authorized' } });
assert.strictEqual(config.execute, true);
assert.strictEqual(config.maxRequests, 4);
assert.deepStrictEqual(config.headers, { 'X-Research': 'authorized' });
assert.deepStrictEqual(publicConfig({ ...config, approvalToken: 'secret', approvalSecret: 'secret' }).approvalConfigured, true);

assert.throws(() => resolve({ execute: true }), /explicit scope/);
assert.throws(() => resolve({ scope: ['api.test'], allowStateChange: true }), /approvalToken/);
assert.throws(() => resolve({ scope: ['api.test'], maxRequests: 0 }), /positive integer/);
assert.throws(() => resolve({ scope: ['api.test'], headers: 'broken-header' }), /invalid header/);

const env = resolve({ scope: ['api.test'] }, {
  PENTHARNESS_MAX_REQUESTS: '9',
  PENTHARNESS_MAX_BYTES: '1000',
  PENTHARNESS_HEADERS: 'X-Env: yes',
  PENTHARNESS_AI_PROVIDER: 'ollama',
  PENTHARNESS_AI_MODEL: 'llama3.2',
});
assert.strictEqual(env.maxRequests, 9);
assert.strictEqual(env.maxBytes, 1000);
assert.deepStrictEqual(env.headers, { 'X-Env': 'yes' });
assert.strictEqual(env.aiProvider, 'ollama');
assert.strictEqual(env.aiModel, 'llama3.2');

console.log('config: ok');
