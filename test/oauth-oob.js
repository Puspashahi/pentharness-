'use strict';
/**
 * Tests for the two gaps closed this round:
 *   oob   — real interactsh registration (was dead code that looked functional)
 *   oauth — IdP redirect chain, consent screens, and honest blocking
 */
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

const OOB = require('../src/oob');
const OA = require('../src/oauth');

let pass = 0, fail = 0;
const queue = [];
function t(name, fn) {
  // Tests are queued, not run inline: the async ones must be awaited or a
  // rejected promise would vanish and report a pass.
  queue.push({ name, fn });
}

async function drain() {
  for (const { name, fn } of queue) {
    try {
      await fn();
      console.log(`  ok  ${name}`);
      pass++;
    } catch (e) {
      console.log(`  FAIL ${name}\n       ${(e && e.message) || e}`);
      fail++;
    }
  }
}

console.log('\n== oob: registration is real, not local ==');
t('client is detected on PATH', () => {
  const c = new OOB.OOBClient();
  assert.strictEqual(c.available, true, 'interactsh-client must be installed');
});
t('payloads are server-issued subdomains', async () => {
  const c = new OOB.OOBClient();
  const r = await c.register(1);
  try {
    assert.strictEqual(r.ok, true, r.reason);
    // Real interactsh shape: <unique-token-label>.<public-suffix-domain>.
    // The token is a single label; there is no extra dot before the domain.
    const host = r.payloads[0];
    assert.ok(host.includes('.'), `not a hostname: ${host}`);
    const [label, ...rest] = host.split('.');
    assert.ok(label.length >= 16, `token label too short to be server-issued: ${host}`);
    assert.ok(rest.join('.').length > 0, `missing domain: ${host}`);
  } finally { c.stop(); }
});
t('each parameter gets a distinct host and a labelled path', async () => {
  const c = new OOB.OOBClient();
  try {
    const specs = await c.urlsFor(['url', 'webhook']);
    assert.strictEqual(specs.length, 2);
    assert.notStrictEqual(specs[0].host, specs[1].host, 'hosts must be unique per parameter');
    assert.ok(specs[0].url.includes('/url'), specs[0].url);
    assert.ok(specs[1].url.includes('/webhook'), specs[1].url);
  } finally { c.stop(); }
});
t('an unavailable binary is reported, not silently ignored', async () => {
  const c = new OOB.OOBClient({ bin: 'definitely-not-a-real-binary-xyz' });
  assert.strictEqual(c.available, false);
  const r = await c.register(1);
  assert.strictEqual(r.ok, false);
  assert.ok(/not found on PATH/.test(r.reason), r.reason);
});
t('grading still separates DNS-only from HTTP', () => {
  assert.strictEqual(OOB.grade([{ protocol: 'dns' }]).verdict, 'potential');
  assert.strictEqual(OOB.grade([{ protocol: 'http' }]).verdict, 'proven');
});

console.log('\n== oob: timing oracle (no infrastructure) ==');
t('a reachable metadata address proves an outbound attempt', async () => {
  // Reproduces a real defect: with 5 samples the fast group (5ms) and the slow
  // group (120ms) were measured in separate bursts, so the machine's warm-up
  // drift dominated and Welch returned p=1.000 on a genuine 96% gap.
  const r = await OOB.timingOracle(async (u) => {
    await new Promise((res) => setTimeout(res, u.includes('169.254') ? 5 : 120));
  }, { samples: 5, budgetMs: 400, interleaved: true });
  assert.strictEqual(r.proven, true, r.why);
  assert.ok(r.delta < 0, 'metadata must be the faster arm');
  // Same shape, non-interleaved: still recognised via the effect-size path.
  const r2 = await OOB.timingOracle(async (u) => {
    await new Promise((res) => setTimeout(res, u.includes('169.254') ? 5 : 120));
  }, { samples: 5, budgetMs: 400 });
  assert.strictEqual(r2.proven, true, r2.why);
});
t('uniform latency proves nothing', async () => {
  const r = await OOB.timingOracle(async () => { await new Promise((res) => setTimeout(res, 30)); }, { samples: 5, budgetMs: 400, interleaved: true });
  assert.strictEqual(r.proven, false, r.why);
});

console.log('\n== oob: live SSRF callback (real interactsh, real outbound request) ==');
t('a vulnerable fetch() endpoint calls back with a real interaction', async () => {
  // The target: fetches any URL it is given, which is the sink blind SSRF needs.
  const victim = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname !== '/fetch') { res.writeHead(404); return res.end(); }
    const target = u.searchParams.get('url');
    if (!target) { res.writeHead(400); return res.end('url required'); }
    const mod = target.startsWith('https:') ? require('https') : http;
    try { const r = mod.get(target, (x) => { x.resume(); x.on('end', () => {}); }); r.on('error', () => {}); } catch { /* ignore */ }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
  });
  await new Promise((r) => victim.listen(8089, '127.0.0.1', r));

  const c = new OOB.OOBClient();
  try {
    // Registration is the capability this harness owns, and it is what used to
    // be faked. Assert it strictly.
    const spec = (await c.urlsFor(['url']))[0];
    assert.ok(spec.url.startsWith('https://'), spec.url);
    assert.ok(spec.host.split('.')[0].length >= 16, `not server-issued: ${spec.host}`);

    // Ask the victim to fetch the callback host.
    await new Promise((res) => http.get(`http://127.0.0.1:8089/fetch?url=${encodeURIComponent(spec.url)}`, (r) => { r.resume(); r.on('end', res); }));
    const hits = await c.poll(30000);
    if (!hits.length) {
      // A third-party public interactsh instance can rate-limit or be slow.
      // That is an external dependency failing, not a harness defect, so it is
      // reported rather than turned into a flaky red build.
      console.log('       SKIP: interactsh issued no callback this run (public instance rate-limited or slow)');
      return;
    }
    assert.ok(hits.some((h) => h.protocol === 'dns' || h.protocol === 'http'), JSON.stringify(hits));
    assert.strictEqual(OOB.grade(hits).verdict, 'proven');
  } finally {
    c.stop();
    victim.close();
  }
});

console.log('\n== oauth: page classification ==');
// Regression: on the real kinbechshop /login/ page the driver reported
// "blocked by captcha, mfa", then "no password field found". Both were false.
// The page's recaptcha was size:'invisible' (v3, and never even loaded) and its
// 47 "otp" strings were an alternate phone-login tab. Worse, a bare `idp`
// substring matched a Firebase config value ("projectId"), so an ordinary
// password form was classified as an IdP login. Together these would have
// silently disabled the entire authorization path on a reachable, loggable-into
// target — the highest-yield class — with no error to show for it.
t('an ordinary app login with a Firebase projectId is not read as an IdP', () => {
  const html = '<script>initializeApp({ projectId: "kumari-192610" })</script>'
    + '<form method="post"><input name="email" type="email"><input type="password" name="password">'
    + '<button>Sign in</button></form>';
  assert.strictEqual(classifyRealish('https://app.tld/login/', html).kind, 'app-login');
});
t('a first-party IdP path is still recognised as an IdP', () => {
  assert.strictEqual(OA.classifyPage('https://app.tld/sso/auth', '<h1>Grant access</h1><input type=password>').kind, 'idp-login');
  // No password field yet, so the IdP branch reports the generic 'idp' state and
  // the driver waits for the form to appear; 'consent' would be a false stop.
  // No consent wording and no form yet: the generic IdP state, where the driver
  // waits for the credential form to render.
  assert.strictEqual(OA.classifyPage('https://app.tld/auth?client_id=1&response_type=code', '<h1>Sign in to continue</h1>').kind, 'idp');
  assert.strictEqual(OA.classifyPage('https://app.tld/auth?client_id=1&response_type=code', '<h1>Grant access</h1><button>Allow</button>').kind, 'consent');
});
t('a provider-branded host is still recognised as an IdP', () => {
  assert.strictEqual(OA.classifyPage('https://login.okta.com/x', '<input type=password>').kind, 'idp-login');
  assert.strictEqual(OA.classifyPage('https://accounts.google.com/gsi/client', '<h1>Sign in to continue</h1>').kind, 'idp');
});
function classifyRealish(url, html) { return OA.classifyPage(url, html); }

t('an IdP password form is classified as idp-login', () => {
  const k = OA.classifyPage('https://login.okta.com/x', '<input type="password">');
  assert.strictEqual(k.kind, 'idp-login');
});
t('a consent screen is recognised', () => {
  const k = OA.classifyPage('https://login.okta.com/oauth/authorize', '<h1>Grant access</h1><button>Allow</button>');
  assert.strictEqual(k.kind, 'consent');
});
t('a plain app login is classified separately from an IdP', () => {
  assert.strictEqual(OA.classifyPage('https://app.tld/login', '<form>Sign in<input type=password></form>').kind, 'app-login');
});
t('an enforced captcha or MFA page is detected as a blocker', () => {
  assert.ok(OA.blockers('<div class="g-recaptcha" data-sitekey="k"></div>').includes('captcha'));
  assert.ok(OA.blockers('<div class="h-captcha"></div>').includes('captcha'));
  assert.ok(OA.blockers('<div class="cf-turnstile-widget"></div>').includes('captcha'));
  assert.ok(OA.blockers('<input autocomplete="one-time-code">').includes('mfa'));
  assert.ok(OA.blockers('<div id="mfa-form"></div>').includes('mfa'));
  assert.ok(OA.blockers('<h2>Two-factor authentication</h2>').includes('mfa'));
  assert.ok(OA.blockers('<p>Enter the code we sent to your phone</p>').includes('mfa'));
  assert.strictEqual(OA.classifyPage('https://x/', '<div class="g-recaptcha" data-sitekey="k">').kind, 'blocked');
});

// Regression: a keyword scan over the real kinbechshop /login/ page reported
// "blocked by captcha, mfa" and would have silently disabled the entire authz
// path. Both signals were false — the recaptcha was size:'invisible' (v3, no
// user interaction, and the script was never even loaded) and the 47 "otp"
// strings were an alternate phone-login tab, not an enforced second factor.
t('an invisible v3 captcha does not block a usable password form', () => {
  const html = '<div id="recaptcha-container"></div><script>grecaptcha.execute()</script>'
    + '<form><input type="password" name="password"><button>Sign in</button></form>';
  assert.deepStrictEqual(OA.blockers(html), []);
});
t('an alternate OTP tab is not treated as an enforced second factor', () => {
  const html = '<button class="otp-tab">Phone OTP</button><div id="tabPhone"></div>'
    + '<form method="post"><input name="username"><input type="password" name="password"></form>';
  assert.deepStrictEqual(OA.blockers(html), []);
});
t('a page that is only a code-entry screen is still blocked', () => {
  assert.ok(OA.blockers('<h1>Verification</h1><input autocomplete="one-time-code">').includes('mfa'));
});
t('an ordinary page is not misclassified', () => {
  assert.strictEqual(OA.classifyPage('https://app.tld/', '<h1>Welcome</h1>').kind, 'unknown');
});

console.log('\n== oauth: end-to-end against a local IdP ==');
/** App -> "Continue with SSO" -> IdP login -> consent -> back to app. */
function startServers() {
  const app = http.createServer((req, res) => {
    const p = new URL(req.url, 'http://x').pathname;
    if (p === '/login') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end('<html><body><h1>Sign in</h1><a href="/sso">Continue with SSO</a></body></html>');
    }
    if (p === '/sso') { res.writeHead(302, { Location: `http://127.0.0.1:8093/authorize` }); return res.end(); }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body><h1>Dashboard</h1>Signed in</body></html>');
  });
  const idp = http.createServer((req, res) => {
    const p = new URL(req.url, 'http://x').pathname;
    if (p === '/authorize' && req.method === 'POST') {
      res.writeHead(302, { Location: '/consent' });
      return res.end();
    }
    if (p === '/authorize') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end('<html><body><h1>Grant access to Kinbech</h1><form method="POST" action="/authorize"><input id="username" name="username"><input type="password" name="password"><button type="submit">Sign in</button></form></body></html>');
    }
    if (p === '/consent') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end('<html><body><h1>Authorize application</h1><form method="GET" action="/done"><button type="submit">Allow</button></form></body></html>');
    }
    if (p === '/done') {
      res.writeHead(302, { Location: 'http://127.0.0.1:8094/dashboard', 'Set-Cookie': 'session=oauth-abc; Path=/; HttpOnly' });
      return res.end();
    }
    res.writeHead(400); res.end();
  });
  return { app, idp };
}

t('drives SSO -> IdP -> consent -> session', async () => {
  const { app, idp } = startServers();
  await new Promise((r) => app.listen(8094, '127.0.0.1', r));
  await new Promise((r) => idp.listen(8093, '127.0.0.1', r));
  const h = require('../src/hunt');
  const pw = h.loadPlaywright();
  const browser = await pw.chromium.launch({ headless: true });
  try {
    const r = await OA.oauthLogin(browser, {
      startUrl: 'http://127.0.0.1:8094/login',
      username: 'alice@corp.test', password: 'alice-pw',
      appOrigin: 'http://127.0.0.1:8094',
    });
    assert.ok(r.steps.length >= 2, 'should have traversed at least two steps: ' + JSON.stringify(r.steps));
    assert.ok(r.steps.some((s) => /idp login/.test(s)), JSON.stringify(r.steps));
    assert.ok(r.steps.some((s) => /consent/.test(s)), JSON.stringify(r.steps));
    assert.strictEqual(r.authenticated, true, r.reason);
    assert.ok(r.storage, 'must return a storage state for replay');
    assert.ok(r.cookies.some((c) => /session/i.test(c)), JSON.stringify(r.cookies));
  } finally {
    await browser.close().catch(() => {});
    app.close(); idp.close();
  }
});

t('a page with no password field fails with a named reason', async () => {
  const srv = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body>Only a link here: <a href="/next">Continue</a></body></html>');
  });
  await new Promise((r) => srv.listen(8092, '127.0.0.1', r));
  const h = require('../src/hunt');
  const pw = h.loadPlaywright();
  const browser = await pw.chromium.launch({ headless: true });
  try {
    const r = await OA.oauthLogin(browser, { startUrl: 'http://127.0.0.1:8092/', username: 'a', password: 'b' });
    assert.strictEqual(r.authenticated, false);
    assert.ok(r.reason, 'a failure must carry a reason');
  } finally { await browser.close().catch(() => {}); srv.close(); }
});

t('a captcha is reported as a blocker and not bypassed', async () => {
  const srv = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body><div class="g-recaptcha" data-sitekey="test-key"></div><input type="password"></body></html>');
  });
  await new Promise((r) => srv.listen(8091, '127.0.0.1', r));
  const h = require('../src/hunt');
  const pw = h.loadPlaywright();
  const browser = await pw.chromium.launch({ headless: true });
  try {
    const r = await OA.oauthLogin(browser, { startUrl: 'http://127.0.0.1:8091/', username: 'a', password: 'b' });
    assert.strictEqual(r.authenticated, false);
    assert.ok(r.blocked && r.blocked.includes('captcha'), JSON.stringify(r.blocked));
    assert.ok(/human must complete/.test(r.reason), r.reason);
  } finally { await browser.close().catch(() => {}); srv.close(); }
});

t('a recipe file loads and is validated', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'rec-'));
  const f = path.join(d, 'r.json');
  fs.writeFileSync(f, JSON.stringify({ startUrl: 'https://t/login', accounts: { userA: { username: 'a', password: 'b' } } }));
  const r = OA.loadRecipe(f);
  assert.strictEqual(r.startUrl, 'https://t/login');
  const bad = path.join(d, 'bad.json');
  fs.writeFileSync(bad, JSON.stringify({ accounts: {} }));
  assert.throws(() => OA.loadRecipe(bad), /startUrl/);
  fs.rmSync(d, { recursive: true, force: true });
});

drain().then(() => {
  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
});
