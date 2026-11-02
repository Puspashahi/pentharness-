'use strict';
const assert = require('assert');
const R = require('../src/recon-pipeline');

let pass = 0, fail = 0;
async function t(name, fn) {
  try { await fn(); console.log(`  ok  ${name}`); pass++; }
  catch (e) { console.log(`  FAIL ${name}\n       ${e.message}`); fail++; }
}

console.log('\n== recon pipeline safety ==');
const tests = [
['requires a matching explicit scope', () => {
  assert.strictEqual(R.plan('example.com', [], {}).ok, false);
  assert.strictEqual(R.plan('example.com', ['other.com'], {}).ok, false);
}],
['accepts in-scope subdomains', () => {
  assert.strictEqual(R.hostInScope('api.example.com', ['example.com']), true);
  assert.strictEqual(R.hostInScope('example.com.evil.test', ['example.com']), false);
}],
['filters URLs to scope', () => {
  const r = R.filterScoped(['https://api.example.com/a', 'https://evil.test/x', 'not-a-url'], ['example.com']);
  assert.deepStrictEqual(r, ['https://api.example.com/a']);
}],
['filters structured tool output by host fields', () => {
  const r = R.filterToolOutput(
    '{"url":"https://api.example.com/a"}\n{"url":"https://evil.test/x"}',
    ['example.com'],
  );
  assert.strictEqual(r, '{"url":"https://api.example.com/a"}');
}],
['builds bounded tool plan', () => {
  const p = R.plan('example.com', ['example.com'], { maxTargets: 20 });
  assert.strictEqual(p.ok, true);
  assert.strictEqual(p.maxTargets, 20);
  assert.deepStrictEqual(p.steps.map((x) => x.tool), ['subfinder', 'uncover', 'dnsx', 'httpx', 'katana', 'nuclei']);
}],
['does not execute missing tools as a hard failure', async () => {
  const r = await R.run('example.com', ['example.com'], { workdir: require('fs').mkdtempSync('/tmp/ph-recon-') });
  assert.ok(Array.isArray(r.results));
  assert.ok(r.results.every((x) => x.ok || x.skipped));
}],
];

Promise.resolve().then(async () => {
  for (const [name, fn] of tests) await t(name, fn);
  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
});
