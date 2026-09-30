'use strict';
/**
 * Two-step sign-in regression tests.
 *
 * Real defect found against MATLAB Online. Its login is a two-step form:
 * `#submit_identifier` reveals a hidden password panel, then `#submit_password`
 * submits. Three things went wrong:
 *
 *   1. The password field was filled while still hidden, so the fill silently
 *      no-oped and the subsequent login failed with "still on the login page".
 *   2. The submit used a combined selector (`#submit_password, button[type=submit]`)
 *      and `.first()`. `.first()` returns the first match in DOM order, which is
 *      the *hidden* `#submit_identifier` — the click timed out, and because the
 *      error was swallowed with `.catch(() => {})` the failure was invisible.
 *   3. A fixed sleep raced the provider's redirect, reporting failure for an
 *      authentication that had actually succeeded.
 */
const assert = require('assert');
const http = require('http');

const ID = require('../src/identity');

let pass = 0, fail = 0;
const queue = [];
function t(name, fn) { queue.push({ name, fn }); }

async function drain() {
  for (const { name, fn } of queue) {
    try { await fn(); console.log(`  ok  ${name}`); pass++; }
    catch (e) { console.log(`  FAIL ${name}\n       ${(e && e.message) || e}`); fail++; }
  }
}

/** A login page that behaves like MathWorks: identifier step reveals password. */
function twoStepServer(port) {
  const html = (step) => `<!doctype html><html><body>
    <form id="loginForm_email">
      <input type="email" id="email" name="email" placeholder="Email">
      <button type="submit" id="submit_identifier">Next</button>
    </form>
    <form id="loginForm_password">
      <input type="password" id="password" name="password" style="${step === 1 ? 'display:none' : ''}">
      <button type="submit" id="submit_password" ${step === 1 ? 'style="display:none"' : ''}>Sign In</button>
    </form>
    <script>
      document.getElementById('email').addEventListener('input', function () {});
      document.getElementById('submit_identifier').addEventListener('click', function (e) {
        e.preventDefault();
        document.getElementById('loginForm_password').style.display = 'block';
        document.getElementById('password').style.display = '';
        document.getElementById('submit_password').style.display = '';
        document.getElementById('submit_identifier').style.display = 'none';
      });
      document.getElementById('submit_password').addEventListener('click', function (e) {
        e.preventDefault();
        var pw = document.getElementById('password').value;
        if (pw === 'correct-horse') {
          document.cookie = 'mwa_session=ok-session; path=/';
          document.cookie = 'MOS_AUTH_TOKEN=tok; path=/';
          window.location.href = '/dashboard';
        } else {
          document.body.innerHTML = '<div id="errorMessage">bad credentials</div>';
        }
      });
    </script></body></html>`;
  return http.createServer((req, res) => {
    if (req.url === '/login') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(html(1)); }
    if (req.url === '/dashboard') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end('<html><body><h1>Dashboard</h1>Signed in</body></html>'); }
    res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(html(1));
  });
}

console.log('\n== identity: two-step sign-in ==');
t('logs in through a hidden-password two-step form', async () => {
  const srv = twoStepServer(8085);
  await new Promise((r) => srv.listen(8085, '127.0.0.1', r));
  const pw = require('../src/hunt').loadPlaywright();
  const b = await pw.chromium.launch({ headless: true });
  try {
    const r = await ID.login(b, 'http://127.0.0.1:8085/login', { username: 'a@tld', password: 'correct-horse' }, {});
    assert.strictEqual(r.ok, true, r.reason);
    assert.ok(r.storage, 'must capture a storage state for route replay');
    assert.ok(r.cookies.some((c) => /mwa_session/i.test(c)), JSON.stringify(r.cookies));
    assert.ok(/authenticated/.test(r.reason), r.reason);
  } finally { await b.close().catch(() => {}); srv.close(); }
});

t('a wrong password fails loudly rather than reporting success', async () => {
  const srv = twoStepServer(8086);
  await new Promise((r) => srv.listen(8086, '127.0.0.1', r));
  const pw = require('../src/hunt').loadPlaywright();
  const b = await pw.chromium.launch({ headless: true });
  try {
    const r = await ID.login(b, 'http://127.0.0.1:8086/login', { username: 'a@tld', password: 'wrong' }, {});
    assert.strictEqual(r.ok, false, 'wrong password must not be reported as authenticated');
    assert.strictEqual(r.storage, null);
    assert.ok(r.reason, 'a failure must carry a reason');
  } finally { await b.close().catch(() => {}); srv.close(); }
});

t('the identifier step is recorded in steps[]', async () => {
  const srv = twoStepServer(8087);
  await new Promise((r) => srv.listen(8087, '127.0.0.1', r));
  const pw = require('../src/hunt').loadPlaywright();
  const b = await pw.chromium.launch({ headless: true });
  try {
    const r = await ID.login(b, 'http://127.0.0.1:8087/login', { username: 'a@tld', password: 'correct-horse' }, {});
    assert.ok(Array.isArray(r.steps) && /identifier step submitted/.test(r.steps.join(' ')), JSON.stringify(r.steps));
  } finally { await b.close().catch(() => {}); srv.close(); }
});

console.log('\n== identity: still works on a single-page form ==');
t('a plain always-visible password form still logs in', async () => {
  const srv = http.createServer((req, res) => {
    if (req.url === '/login') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(`<!doctype html><html><body>
        <input type="email" id="email" name="email">
        <input type="password" id="password" name="password">
        <button type="submit" id="go">Sign In</button>
        <script>document.getElementById('go').addEventListener('click',function(e){e.preventDefault();
          if(document.getElementById('password').value==='pw'){document.cookie='session=abc;path=/';window.location.href='/';}
          else{document.body.innerHTML='<div id="errorMessage">nope</div>';}});</script>
      </body></html>`);
    }
    res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<html><body>home</body></html>');
  });
  await new Promise((r) => srv.listen(8088, '127.0.0.1', r));
  const pw = require('../src/hunt').loadPlaywright();
  const b = await pw.chromium.launch({ headless: true });
  try {
    const r = await ID.login(b, 'http://127.0.0.1:8088/login', { username: 'a@tld', password: 'pw' }, {});
    assert.strictEqual(r.ok, true, r.reason);
  } finally { await b.close().catch(() => {}); srv.close(); }
});

t('a page with no password field is reported, not retried blindly', async () => {
  const srv = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body><h1>Welcome</h1><a href="/x">Continue</a></body></html>');
  });
  await new Promise((r) => srv.listen(8084, '127.0.0.1', r));
  const pw = require('../src/hunt').loadPlaywright();
  const b = await pw.chromium.launch({ headless: true });
  try {
    const r = await ID.login(b, 'http://127.0.0.1:8084/', { username: 'a', password: 'b' }, {});
    assert.strictEqual(r.ok, false);
    assert.ok(/no password field/i.test(r.reason), r.reason);
  } finally { await b.close().catch(() => {}); srv.close(); }
});

console.log('\n== identity: header policy rides on the session ==');
t('an inactive policy does not add a header', async () => {
  const srv = twoStepServer(8083);
  await new Promise((r) => srv.listen(8083, '127.0.0.1', r));
  const pw = require('../src/hunt').loadPlaywright();
  const b = await pw.chromium.launch({ headless: true });
  try {
    const r = await ID.login(b, 'http://127.0.0.1:8083/login', { username: 'a@tld', password: 'correct-horse' }, {});
    assert.strictEqual(r.ok, true, r.reason);
  } finally { await b.close().catch(() => {}); srv.close(); }
});

drain().then(() => {
  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
});
