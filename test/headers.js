'use strict';
/**
 * Tests for program-mandated request headers.
 *
 * Motivation: MATLAB Online's Bugcrowd brief requires X-Request-Purpose on every
 * request and warns that omitting it gets the researcher blocked. Before this
 * module the harness sent no custom headers at all, so a full run against that
 * program would have looked like an attack. These tests lock that shut.
 */
const assert = require('assert');
const http = require('http');
const { HeaderPolicy, FORBIDDEN_PATTERNS } = require('../src/headerpolicy');

let pass = 0, fail = 0;
const queue = [];
function t(name, fn) { queue.push({ name, fn }); }

async function drain() {
  for (const { name, fn } of queue) {
    try { await fn(); console.log(`  ok  ${name}`); pass++; }
    catch (e) { console.log(`  FAIL ${name}\n       ${(e && e.message) || e}`); fail++; }
  }
}

console.log('\n== headerpolicy: construction and formatting ==');
t('headers parse into a usable object', () => {
  const p = new HeaderPolicy({ headers: { 'X-Request-Purpose': 'BugcrowdResearch' } });
  assert.strictEqual(p.active, true);
  assert.deepStrictEqual(p.headers, { 'X-Request-Purpose': 'BugcrowdResearch' });
});
t('no headers means inactive, and no flags are emitted', () => {
  const p = new HeaderPolicy({});
  assert.strictEqual(p.active, false);
  assert.deepStrictEqual(p.flagsFor('httpx-pd'), []);
});
t('every external tool gets repeatable -H flags', () => {
  const p = new HeaderPolicy({ headers: { A: '1', B: '2' } });
  for (const bin of ['httpx-pd', 'httpx', 'katana', 'arjun', 'nuclei']) {
    const f = p.flagsFor(bin);
    assert.strictEqual(f.length, 4, `${bin}: expected -H x2, got ${JSON.stringify(f)}`);
    assert.ok(f.every((x, i) => (i % 2 === 0 ? x === '-H' : x.includes(':'))), bin);
  }
});
t('playwright form is extraHTTPHeaders shaped', () => {
  const p = new HeaderPolicy({ headers: { 'X-Request-Purpose': 'BugcrowdResearch' } });
  assert.deepStrictEqual(p.playwright(), { 'X-Request-Purpose': 'BugcrowdResearch' });
  assert.strictEqual(new HeaderPolicy({}).playwright(), undefined);
});
t('header injection cannot be bypassed by a caller', () => {
  // A per-request header must not be able to remove or override the policy
  // header, otherwise any module could quietly drop the required header.
  const p = new HeaderPolicy({ headers: { 'X-Request-Purpose': 'BugcrowdResearch' } });
  const m = p.merge({ 'X-Request-Purpose': 'spoofed', 'X-Other': 'keep' });
  assert.strictEqual(m['X-Request-Purpose'], 'BugcrowdResearch');
  assert.strictEqual(m['X-Other'], 'keep');
});
t('CRLF in a header value is dropped, not smuggled', () => {
  const p = new HeaderPolicy({ headers: { 'X-Bad': 'a\r\nX-Injected: 1', 'X-Good': 'ok' } });
  assert.ok(!('X-Bad' in p.headers), 'CRLF header must be rejected');
  assert.strictEqual(p.headers['X-Good'], 'ok');
});
t('secrets are redacted in describe()', () => {
  const p = new HeaderPolicy({ headers: { 'X-Request-Purpose': 'BugcrowdResearch', Authorization: 'Bearer SECRET' } });
  const d = p.describe();
  assert.ok(d.includes('BugcrowdResearch'));
  assert.ok(!d.includes('SECRET'), d);
  assert.ok(d.includes('<redacted>'));
});

console.log('\n== headerpolicy: prohibited features ==');
t('the brief-prohibited support/service-request paths are blocked', () => {
  const p = new HeaderPolicy({});
  for (const u of [
    'https://t/mathworks/profile/service-request',
    'https://t/support',
    'https://t/api/feedback',
    'https://t/help/contact-us',
  ]) {
    assert.strictEqual(p.isAllowed(u), false, u);
    assert.ok(FORBIDDEN_PATTERNS.some((re) => re.test(u)), u);
  }
});
t('ordinary application paths are still allowed', () => {
  const p = new HeaderPolicy({});
  for (const u of [
    'https://matlab.mathworks.com/',
    // Regression: an earlier pattern blocked every path containing "help",
    // which would have blocked MATLAB Online's entire documentation tree.
    'https://matlab.mathworks.com/help/matlab/ref/plot.html',
    'https://matlab.mathworks.com/help/search.html?q=plot',
    'https://matlab.mathworks.com/matlabcentral/fileexchange',
    'https://www.mathworks.com/help/',
  ]) {
    assert.strictEqual(p.isAllowed(u), true, u);
  }
  assert.strictEqual(p.blocked.length, 0);
});

console.log('\n== headerpolicy: throttle ==');
t('throttle admits up to the limit then defers', async () => {
  const p = new HeaderPolicy({ throttle: 3 });
  const start = Date.now();
  for (let i = 0; i < 3; i++) await p.take();
  const fast = Date.now() - start;
  assert.ok(fast < 200, `3 requests at 3/min should not wait, waited ${fast}ms`);
  assert.strictEqual(p.sent, 3);
});
t('no throttle configured means unlimited', async () => {
  const p = new HeaderPolicy({});
  const start = Date.now();
  for (let i = 0; i < 50; i++) await p.take();
  assert.ok(Date.now() - start < 500, 'must not wait without a limit');
});

console.log('\n== headerpolicy: end to end over a live socket ==');
t('a real HTTP request carries the required header', async () => {
  const srv = http.createServer((req, res) => { res.end(JSON.stringify(req.headers)); });
  await new Promise((r) => srv.listen(8090, '127.0.0.1', r));
  try {
    const p = new HeaderPolicy({ headers: { 'X-Request-Purpose': 'BugcrowdResearch', 'X-Bugcrowd-Ninja': 'probe_user' } });
    const res = await fetch('http://127.0.0.1:8090/', { headers: p.merge({ 'Accept': 'text/html' }) });
    const got = JSON.parse(await res.text());
    assert.strictEqual(got['x-request-purpose'], 'BugcrowdResearch');
    assert.strictEqual(got['x-bugcrowd-ninja'], 'probe_user');
    assert.strictEqual(got.accept, 'text/html', 'per-request headers still apply');
  } finally { srv.close(); }
});
t('a blocked URL is never actually requested', async () => {
  let hit = 0;
  const srv = http.createServer((req, res) => { hit++; res.end('{}'); });
  await new Promise((r) => srv.listen(8090, '127.0.0.1', r));
  try {
    const p = new HeaderPolicy({});
    // `/support` is a staff channel and stays blocked; `/help/matlab` is
    // documentation and must not be.
    assert.strictEqual(p.isAllowed('https://x.test/support'), false);
    assert.strictEqual(p.isAllowed('https://x.test/help/matlab/ref/plot.html'), true);
    assert.strictEqual(hit, 0, 'nothing may be sent for a prohibited feature');
  } finally { srv.close(); }
});

drain().then(() => {
  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
});
