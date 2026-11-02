'use strict';

const crypto = require('crypto');

const RISKY_ACTIONS = new Set([
  'state-change',
  'destructive',
  'race',
  'account',
  'email',
  'high-volume',
]);

function sign(payload, secret) {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

function createApprovalToken({ action = 'state-change', scope, expiresAt, secret }) {
  if (!RISKY_ACTIONS.has(action)) throw new Error(`unsupported approval action: ${action}`);
  if (!scope || !secret) throw new TypeError('approval scope and secret are required');
  const payload = JSON.stringify({ action, scope, expiresAt: Number(expiresAt) });
  return `${Buffer.from(payload).toString('base64url')}.${sign(payload, secret)}`;
}

function verifyApprovalToken(token, { action, scope, secret, now = Date.now() }) {
  if (!token || !secret || !RISKY_ACTIONS.has(action)) return { ok: false, reason: 'approval token is required' };
  const [encoded, signature] = String(token).split('.');
  if (!encoded || !signature) return { ok: false, reason: 'malformed approval token' };
  let payload;
  try { payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')); } catch {
    return { ok: false, reason: 'malformed approval token' };
  }
  const expected = sign(JSON.stringify(payload), secret);
  if (signature.length !== expected.length
    || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return { ok: false, reason: 'invalid approval signature' };
  if (payload.action !== action) return { ok: false, reason: `approval action mismatch: ${payload.action}` };
  if (payload.scope !== scope) return { ok: false, reason: `approval scope mismatch: ${payload.scope}` };
  if (!Number.isFinite(payload.expiresAt) || payload.expiresAt <= now) return { ok: false, reason: 'approval token expired' };
  return { ok: true, action: payload.action, scope: payload.scope, expiresAt: payload.expiresAt };
}

module.exports = { RISKY_ACTIONS, createApprovalToken, verifyApprovalToken };
