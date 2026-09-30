'use strict';
/**
 * Deliberately vulnerable multi-user fixture for validating the authorization
 * stage end-to-end: real login form, two accounts, sequential object IDs, and
 * a missing ownership check — i.e. the $78,000 Meta shape in miniature.
 * For local testing only. Binds to 127.0.0.1.
 */
const http = require('http');

const USERS = {
  'alice@corp.test': { pw: 'alice-pw', name: 'alice' },
  'bob@corp.test': { pw: 'bob-pw', name: 'bob' },
};

// caseId -> owner
const CASES = {};
for (let i = 100; i < 130; i++) CASES[i] = i % 2 === 0 ? 'alice' : 'bob';

function userOf(req) {
  const c = (req.headers.cookie || '').match(/session=([^;]+)/);
  if (!c) return null;
  const m = c[1].match(/^u:(alice|bob)$/);
  return m ? m[1] : null;
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://localhost');
  const p = u.pathname;
  const send = (code, body, headers = {}) => {
    res.writeHead(code, { 'Content-Type': 'text/html', ...headers });
    res.end(body);
  };

  if (p === '/login' && req.method === 'GET') {
    return send(200, `<html><body>
      <h1>Sign in</h1>
      <form action="/login" method="POST">
        <input name="email" type="email" placeholder="Email">
        <input name="password" type="password" placeholder="Password">
        <button type="submit">Login</button>
      </form>
      <a href="/cases/100">Case 100</a>
      </body></html>`);
  }

  if (p === '/login' && req.method === 'POST') {
    let body = '';
    req.on('data', (c) => { body += c; });
    return req.on('end', () => {
      const form = new URLSearchParams(body);
      const email = form.get('email'), pw = form.get('password');
      const u = USERS[email];
      if (u && u.pw === pw) return send(302, '', { Location: '/cases', 'Set-Cookie': `session=u:${u.name}; Path=/; HttpOnly` });
      return send(401, '<html><body>Invalid credentials</body></html>');
    });
  }

  const who = userOf(req);
  if (!who) return send(401, '<html><body>login required</body></html>');

  if (p === '/cases') {
    const mine = Object.entries(CASES).filter(([, o]) => o === who);
    return send(200, `<html><body><h1>Your cases</h1><ul>${mine.map(([id]) => `<li><a href="/cases/${id}">Case ${id}</a></li>`).join('')}</ul></body></html>`);
  }

  // THE BUG: no ownership check. Any authenticated user can read any case.
  const m = p.match(/^\/cases\/(\d+)$/);
  if (m) {
    const id = m[1];
    const owner = CASES[id];
    if (!owner) return send(404, '<html><body>no such case</body></html>');
    return send(200, `<html><body>
      <div class="case">
        <span class="owner_id">${owner}@corp.test</span>
        <h1>Case ${id}</h1>
        <p>Support transcript for ${owner}. PII: phone +4100000000</p>
      </div></body></html>`);
  }

  return send(404, '<html><body>nope</body></html>');
});

server.listen(8098, '127.0.0.1', () => console.log('multi-user fixture on http://127.0.0.1:8098'));
