'use strict';

/**
 * Bounded race/replay runner.
 *
 * State-changing requests are blocked unless allowStateChange is explicitly
 * true. The runner is intentionally small: it measures duplicate acceptance,
 * idempotency-key behavior, response ordering, and post-run state snapshots.
 */
const crypto = require('crypto');

const digest = (body) => crypto.createHash('sha256').update(String(body || '')).digest('hex').slice(0, 16);

async function one(ctx, request) {
  const method = String(request.method || 'GET').toUpperCase();
  const res = await ctx.request.fetch(request.url, {
    method,
    headers: request.headers || {},
    data: request.body,
    timeout: request.timeout || 12000,
    failOnStatusCode: false,
  });
  const body = await res.text().catch(() => '');
  return { status: res.status(), length: body.length, digest: digest(body), body };
}

async function runRace(ctx, request, opts = {}) {
  const method = String(request.method || 'GET').toUpperCase();
  const concurrency = Math.max(2, Math.min(opts.concurrency || 2, 8));
  const rounds = Math.max(2, Math.min(opts.rounds || concurrency, 8));
  const stateChanging = !['GET', 'HEAD', 'OPTIONS'].includes(method);
  if (stateChanging && opts.allowStateChange !== true) {
    return { ok: false, skipped: true, reason: 'state-changing race requires allowStateChange=true', results: [] };
  }

  const before = typeof opts.snapshot === 'function' ? await opts.snapshot() : undefined;
  const started = Date.now();
  const results = await Promise.all(Array.from({ length: rounds }, () => one(ctx, request).catch((error) => ({
    status: 0, length: 0, digest: '', error: String(error.message || error),
  }))));
  const after = typeof opts.snapshot === 'function' ? await opts.snapshot() : undefined;
  const success = results.filter((r) => r.status >= 200 && r.status < 300);
  const unique = new Set(results.map((r) => `${r.status}:${r.digest}`));
  const stateChanged = before !== undefined && after !== undefined && JSON.stringify(before) !== JSON.stringify(after);
  const idempotencyKey = request.headers && Object.keys(request.headers).find((k) => /idempotency[-_]?key/i.test(k));

  return {
    ok: true,
    method,
    rounds,
    concurrency,
    elapsedMs: Date.now() - started,
    results: results.map(({ body, ...r }) => r),
    analysis: {
      successfulResponses: success.length,
      duplicateAcceptance: stateChanging && success.length > 1,
      responseVariants: unique.size,
      stateChanged,
      idempotencyKey: Boolean(idempotencyKey),
      hypothesis: stateChanging && success.length > 1
        ? 'multiple concurrent requests succeeded; verify whether one logical action occurred more than once'
        : null,
    },
  };
}

module.exports = { runRace, one, digest };
