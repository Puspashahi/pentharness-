'use strict';
/**
 * Capture-file IO shared by the identity and authorization paths.
 * Kept separate so `identity.js` and `authmatrix.js` agree on one format.
 */
const fs = require('fs');
const path = require('path');

/**
 * Read a capture file of recorded requests.
 * Accepts JSONL (one JSON object per line — what Burp/mitmproxy export and what
 * we write) or a JSON array.
 * Row: { method, url, status, length?, body?, id? }
 */
function readCapture(file, defaultIdentity) {
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); } catch { return []; }
  const trimmed = raw.trim();
  let rows = [];
  if (trimmed.startsWith('[')) {
    try { rows = JSON.parse(trimmed); } catch { rows = []; }
  } else {
    for (const line of raw.split('\n')) {
      const l = line.trim();
      if (!l || l.startsWith('#')) continue;
      try { rows.push(JSON.parse(l)); } catch { /* skip malformed line */ }
    }
  }
  return rows
    .filter((r) => r && r.url)
    .map((r) => ({
      method: (r.method || 'GET').toUpperCase(),
      url: r.url,
      status: Number(r.status || r.statusCode || 0),
      length: Number(r.length != null ? r.length : (r.body ? String(r.body).length : 0)),
      body: r.body != null ? String(r.body) : '',
      identity: r.id || defaultIdentity,
    }));
}

/** Write observations as JSONL, tagging each row with its identity. */
function writeCaptureSafe(file, rows, identity) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const out = rows.map((r) => JSON.stringify({ ...r, id: identity })).join('\n') + (rows.length ? '\n' : '');
  fs.writeFileSync(file, out);
  return { file, count: rows.length };
}

module.exports = { readCapture, writeCaptureSafe };
