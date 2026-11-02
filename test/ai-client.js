'use strict';

const assert = require('assert');
const { AIClient, configFromEnv, normalizeProvider, publicConfig } = require('../src/ai-client');

assert.strictEqual(normalizeProvider('copilot'), 'github-models');
assert.strictEqual(configFromEnv({
  PENTHARNESS_AI_PROVIDER: 'nvidia',
  PENTHARNESS_AI_MODEL: 'meta/llama-3.1-8b-instruct',
  NVIDIA_API_KEY: 'nvidia-secret',
}).baseUrl, 'https://integrate.api.nvidia.com/v1');

assert.throws(() => configFromEnv({ PENTHARNESS_AI_PROVIDER: 'unknown', PENTHARNESS_AI_MODEL: 'x' }), /unsupported AI provider/);
assert.throws(() => configFromEnv({ PENTHARNESS_AI_PROVIDER: 'ollama' }), /model is required/);

let captured;
const client = new AIClient(configFromEnv({
  PENTHARNESS_AI_PROVIDER: 'ollama',
  PENTHARNESS_AI_MODEL: 'llama3.2',
}), async (url, options) => {
  captured = { url, options };
  return {
    ok: true,
    status: 200,
    headers: { get: () => 'req-1' },
    text: async () => JSON.stringify({ choices: [{ message: { content: 'hypothesis only' } }], usage: { total_tokens: 3 } }),
  };
});

client.chat([{ role: 'user', content: 'token=super-secret Bearer abcdefghijklmnop' }]).then((result) => {
  assert.strictEqual(result.text, 'hypothesis only');
  assert.ok(!captured.options.body.includes('super-secret'));
  assert.ok(!captured.options.body.includes('abcdefghijklmnop'));
  assert.strictEqual(JSON.parse(captured.options.body).temperature, 0);
  assert.strictEqual(publicConfig(client.config).apiKeyConfigured, false);
  return client.advise('Prioritize this lead', { token: 'another-secret', endpoint: '/api/orders' });
}).then(() => console.log('ai-client: ok'));
