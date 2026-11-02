'use strict';

const http = require('http');

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  const user = req.headers['x-user'] || '';
  const send = (status, body, headers = {}) => {
    res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
    res.end(typeof body === 'string' ? body : JSON.stringify(body));
  };

  if (url.pathname.startsWith('/api/orders/')) {
    const id = url.pathname.split('/').pop();
    const owner = id === '1' ? 'alice' : 'bob';
    // Deliberately vulnerable route: it returns another user's order.
    return send(200, { id, owner, total: 42 });
  }
  if (url.pathname === '/api/secure-orders/1') {
    if (user !== 'alice') return send(403, { error: 'forbidden' });
    return send(200, { id: '1', owner: 'alice', total: 42 });
  }
  if (url.pathname === '/search') {
    return send(200, `<html><body>Results for ${url.searchParams.get('q') || ''}</body></html>`, { 'Content-Type': 'text/html' });
  }
  return send(404, { error: 'not found' });
});

function start(port = 0) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

module.exports = { start };
