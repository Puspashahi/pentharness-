'use strict';

const http = require('http');

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  const user = req.headers['x-user'] || '';
  const send = (status, body, headers = {}) => {
    res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
    res.end(typeof body === 'string' ? body : JSON.stringify(body));
  };
  const readBody = () => new Promise((resolve) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => resolve(body));
  });

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
  if (url.pathname === '/api/search') {
    const term = url.searchParams.get('q') || '';
    return send(term.includes("'") || term.includes(' OR ') ? 500 : 200, { rows: term ? [{ id: 1, title: 'benchmark' }] : [] });
  }
  if (url.pathname === '/api/fetch') {
    const target = url.searchParams.get('url') || '';
    return send(target.includes(`127.0.0.1:${server.address()?.port}`) ? 200 : 403, {
      fetched: target.includes(`127.0.0.1:${server.address()?.port}`),
      marker: 'internal-benchmark',
    });
  }
  if (url.pathname === '/api/race' && req.method === 'POST') {
    server.raceState ||= { accepted: 0, active: 0 };
    server.raceState.active++;
    server.raceState.raced ||= server.raceState.active > 1;
    return setTimeout(() => {
      const accepted = server.raceState.raced;
      server.raceState.accepted += accepted ? 1 : 0;
      server.raceState.active--;
      send(accepted ? 200 : 409, { accepted, count: server.raceState.accepted });
    }, 15);
  }
  if (url.pathname === '/graphql' && req.method === 'POST') {
    return readBody().then((body) => {
      const query = JSON.parse(body || '{}');
      const requested = query.variables?.id || '2';
      return send(200, { data: { order: { id: requested, owner: requested === '1' ? 'alice' : 'bob', total: 42 } } });
    });
  }
  if (url.pathname === '/oauth/authorize') {
    const redirect = url.searchParams.get('redirect_uri') || '';
    return send(302, '', { Location: `${redirect}?code=benchmark-code&state=${url.searchParams.get('state') || ''}` });
  }
  if (url.pathname === '/oauth/token' && req.method === 'POST') {
    return readBody().then(() => send(200, { access_token: 'benchmark-token', token_type: 'bearer' }));
  }
  if (url.pathname === '/mcp/tools/call' && req.method === 'POST') {
    return readBody().then((body) => {
      const call = JSON.parse(body || '{}');
      return send(200, { tool: call.tool, owner: 'bob', result: 'sensitive-order-data' });
    });
  }
  return send(404, { error: 'not found' });
});

server.on('upgrade', (req, socket) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  if (url.pathname !== '/ws/orders') return socket.destroy();
  const body = JSON.stringify({ channel: 'orders', owner: 'bob', sensitive: true });
  socket.write(`HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Benchmark-Owner: bob\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n`);
  setImmediate(() => {
    socket.write(body);
    socket.end();
  });
});

function start(port = 0) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

module.exports = { start };
