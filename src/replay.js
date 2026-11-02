'use strict';

const fs = require('fs');
const { sanitizeEvidence } = require('./evidence');
const { inScope } = require('./subdomains');
const { HeaderPolicy } = require('./headerpolicy');

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function readRows(file, identity) {
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); } catch { return []; }
  const parsed = raw.trim().startsWith('[')
    ? (() => { try { return JSON.parse(raw); } catch { return []; } })()
    : raw.split(/\r?\n/).filter((line) => line.trim() && !line.trim().startsWith('#')).flatMap((line) => {
      try { return [JSON.parse(line)]; } catch { return []; }
    });
  return parsed.filter((row) => row && row.url).map((row, index) => ({
    id: row.id || identity,
    identity,
    index,
    method: String(row.method || 'GET').toUpperCase(),
    url: String(row.url),
    headers: row.headers && typeof row.headers === 'object' ? row.headers : {},
    body: row.body,
    status: row.status == null ? undefined : Number(row.status),
  }));
}

function plan(captures, opts = {}) {
  const scopes = Array.isArray(opts.scope) ? opts.scope : (opts.scope ? [opts.scope] : []);
  const policy = opts.headerPolicy || new HeaderPolicy({ headers: opts.headers, throttle: opts.throttle });
  const rows = captures.flatMap((capture) => readRows(capture.file, capture.identity));
  const requests = [];
  const blocked = [];
  for (const row of rows.slice(0, opts.maxRequests || 100)) {
    let host;
    try { host = new URL(row.url).hostname; } catch { blocked.push({ row, reason: 'invalid URL' }); continue; }
    const scope = inScope(host, scopes);
    if (!scope.ok) { blocked.push({ row, reason: scope.reason }); continue; }
    if (!policy.isAllowed(row.url)) { blocked.push({ row, reason: 'program-prohibited URL' }); continue; }
    const stateChanging = !SAFE_METHODS.has(row.method);
    requests.push({
      identity: row.identity,
      sourceIndex: row.index,
      method: row.method,
      url: row.url,
      headers: policy.merge(row.headers),
      body: row.body,
      stateChanging,
      approvalRequired: stateChanging,
      replayable: SAFE_METHODS.has(row.method) || opts.allowStateChange === true,
    });
  }
  return {
    safety: 'scope-gated, rate-limited, redaction-safe replay; state-changing requests require explicit approval',
    dryRun: opts.execute !== true,
    requests,
    blocked,
    policy: policy.toJSON(),
  };
}

async function execute(replayPlan, transport, opts = {}) {
  if (!replayPlan || !Array.isArray(replayPlan.requests)) throw new TypeError('replay plan is required');
  if (typeof transport !== 'function') throw new TypeError('transport function is required');
  const observations = [];
  const limiter = new HeaderPolicy({ throttle: opts.throttle });
  for (const request of replayPlan.requests) {
    if (!request.replayable) {
      observations.push({ ...request, skipped: true, reason: 'state-changing request requires explicit approval' });
      continue;
    }
    await limiter.take();
    const result = await transport(request);
    const response = {
      status: Number(result && result.status || 0),
      headers: result && result.headers || {},
      body: result && result.body != null ? String(result.body) : '',
    };
    observations.push({
      identity: request.identity,
      method: request.method,
      url: request.url,
      status: response.status,
      evidence: sanitizeEvidence({
        request: { method: request.method, url: request.url, headers: request.headers, body: request.body },
        response,
      }),
    });
    if (opts.onRequest) await opts.onRequest(request, response);
  }
  return {
    schemaVersion: 1,
    tool: 'pentharness-replay',
    safety: replayPlan.safety,
    observations,
    candidates: [],
  };
}

module.exports = { SAFE_METHODS, readRows, plan, execute };
