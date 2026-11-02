'use strict';
const assert = require('assert');
const AI = require('../src/ai');

const nvidia = AI.providerConfig({ provider: 'nvidia' }, { NVIDIA_API_KEY: 'nvapi_test_key_123456' });
assert.strictEqual(nvidia.baseUrl, 'https://integrate.api.nvidia.com/v1');
assert.strictEqual(nvidia.key, 'nvapi_test_key_123456');
assert.strictEqual(AI.providerConfig({ provider: 'ollama' }, {}).key, '');
assert.throws(() => AI.providerConfig({ provider: 'grok' }, {}), /missing AI API key/);
assert.strictEqual(AI.redact('Authorization: Bearer secret-token password=hunter2'), 'Authorization: Bearer [REDACTED_TOKEN] password=[REDACTED]');
assert.deepStrictEqual(AI.extractJson('```json\n{"answers":{"a":{"impact":"unknown"}}}\n```'), { answers: { a: { impact: 'unknown' } } });

let captured;
const fakeFetch = async (url, options) => {
  captured = { url, options };
  return {
    ok: true,
    status: 200,
    text: async () => JSON.stringify({ choices: [{ message: { content: '{"answers":{"lead-1":{"impact":"review"}}}' } }], usage: { total_tokens: 4 } }),
  };
};
(async () => {
  const result = await AI.triageQueue([{ kind: 'lead', id: 'lead-1', prompt: 'evidence: password=hunter2' }], {
    provider: 'ollama',
    model: 'llama3.2',
    env: {},
  }, fakeFetch);
  assert.deepStrictEqual(result.answers, { 'lead-1': { impact: 'review' } });
  assert.strictEqual(captured.url, 'http://127.0.0.1:11434/v1/chat/completions');
  assert.ok(!captured.options.body.includes('hunter2'));
  console.log('ai: 6 passed, 0 failed');
})().catch((error) => { console.error(error.stack); process.exitCode = 1; });
