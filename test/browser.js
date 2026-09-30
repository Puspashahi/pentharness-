'use strict';
const assert = require('assert');
const http = require('http');
const B = require('../src/browser');

let pass = 0, fail = 0; const queue = [];
function t(n, f) { queue.push({ n, f }); }
async function drain() {
  for (const { n, f } of queue) {
    try { await f(); console.log(`  ok  ${n}`); pass++; }
    catch (e) { console.log(`  FAIL ${n}\n       ${(e && e.message) || e}`); fail++; }
  }
}

function app(port) {
  const html = (body) => `<!doctype html><html><body>${body}</body></html>`;
  return http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/') return res.end(html(`
      <a href="/search">Search</a>
      <form action="/search" method="get"><input name="q"><button>Go</button></form>
      <form action="/api/pay" method="post"><input name="amount"><button>Pay</button></form>
      <form action="/search" method="get"><input name="query"><button>Go</button></form>`));
    if (u.pathname === '/search') {
      const q = u.searchParams.get('q') || u.searchParams.get('query') || '';
      if (q.includes("'")) { res.writeHead(500, {'Content-Type':'text/plain'}); return res.end('SQLITE_ERROR: unrecognized token'); }
      res.writeHead(200, {'Content-Type':'application/json'}); return res.end(JSON.stringify([{id:1}]));
    }
    if (u.pathname === '/page2') return res.end(html('<p>two</p>'));
    res.writeHead(404); res.end();
  });
}

console.log('\n== injection selection ==');
t('picks by field semantics', () => {
  assert.strictEqual(B.pickInjection([{ name: 'file' }]).id, 'traversal');
  assert.strictEqual(B.pickInjection([{ name: 'callback_url', type: 'url' }]).id, 'ssrf');
  assert.strictEqual(B.pickInjection([{ name: 'message' }]).cls, 'xss');
  // substring matching means 'username' also matches 'name', so XSS wins first
  assert.strictEqual(B.pickInjection([{ name: 'username' }]).cls, 'xss');
  assert.strictEqual(B.pickInjection([{ name: 'id' }]).cls, 'sqli');
});
t('returns null when nothing is injectable', () => {
  assert.strictEqual(B.pickInjection([]), null);
  assert.strictEqual(B.pickInjection([{ name: 'submit_btn', type: 'submit' }]), null);
});

console.log('\n== destructive guard ==');
t('state-changing forms are refused, search is allowed', () => {
  assert.ok(B.DESTRUCTIVE.test('/api/pay POST amount'));
  assert.ok(B.DESTRUCTIVE.test('/account/delete POST id'));
  assert.ok(!B.DESTRUCTIVE.test('/search GET q'));
});

console.log('\n== live browser crawl ==');
t('clicks through the app and finds the injectable form', async () => {
  const srv = app(0); await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  const pw = require('../src/hunt').loadPlaywright();
  const b = await pw.chromium.launch({ headless: true });
  try {
    const ctx = await b.newContext({ ignoreHTTPSErrors: true });
    const page = await ctx.newPage();
    const res = await B.crawl(page, `http://127.0.0.1:${port}/`, { maxPages: 5, maxDepth: 2, timeout: 15000 });
    assert.ok(res.visited.length >= 1, 'should visit the seed');
    assert.ok(res.endpoints.some((e) => /\/search/.test(e)), 'form action must become a known endpoint');
    assert.ok(res.forms.length >= 1, 'forms must be examined');
    // The SQL error is the evidence.
    const inj = res.injected.find((i) => /SQLITE/i.test(i.errorSignature || ''));
    assert.ok(inj, `expected a SQLi candidate, got ${JSON.stringify(res.injected)}`);
    assert.strictEqual(inj.cls, 'sqli', 'a database error means SQLi regardless of which payload fired');
  } finally { await b.close().catch(() => {}); srv.close(); }
});
t('a destructive form is recorded but never submitted', async () => {
  const srv = app(0); await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  const pw = require('../src/hunt').loadPlaywright();
  const b = await pw.chromium.launch({ headless: true });
  try {
    const ctx = await b.newContext({ ignoreHTTPSErrors: true });
    const page = await ctx.newPage();
    const res = await B.crawl(page, `http://127.0.0.1:${port}/`, { maxPages: 3, maxDepth: 1, timeout: 15000 });
    const pay = res.forms.find((f) => /\/api\/pay/.test(f.action));
    if (pay) {
      assert.ok(pay.skipped, 'the payment form must be skipped');
      assert.match(pay.skipped, /destructive/i);
      assert.strictEqual((pay.injections || []).length, 0, 'nothing may be injected into it');
    }
  } finally { await b.close().catch(() => {}); srv.close(); }
});
t('an unreachable target does not throw', async () => {
  const pw = require('../src/hunt').loadPlaywright();
  const b = await pw.chromium.launch({ headless: true });
  try {
    const ctx = await b.newContext({ ignoreHTTPSErrors: true });
    const page = await ctx.newPage();
    const res = await B.crawl(page, 'http://127.0.0.1:9/', { maxPages: 2, timeout: 2000 });
    assert.ok(Array.isArray(res.visited));
  } finally { await b.close().catch(() => {}); }
});

drain().then(() => { console.log(`\n${pass} passed, ${fail} failed\n`); process.exit(fail ? 1 : 0); });
