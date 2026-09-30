'use strict';
/**
 * Client-side auth-logic extraction.
 *
 * A documented example of a bug no scanner finds: an admin endpoint enforces
 * access with a custom header, and the "secret" is not a secret at all — it is a
 * SHA-256 of three values the client already has (user id, user agent,
 * username), computed in a JavaScript function shipped to the browser.
 *
 *   "Scanners search for strings like AWS_SECRET or api_key=. They do not search
 *    for authentication logic encoded in a function. Reading finds it. Scanning
 *    never does."
 *
 * So this does what a secret scanner cannot: it looks for *authorisation logic*
 * in the bundle — signature computation, role gates, and privilege fields
 * honoured from the client. These are leads, not vulnerabilities, until proven.
 */
const fs = require('fs');
const path = require('path');
const { makeLead } = require('./leads');

/**
 * Header names that carry a client-computed auth signal.
 * The char class stops at `"` so the captured name never includes a quote —
 * a greedy `[a-z0-9-]*` tail would otherwise swallow the closing delimiter and
 * the name would stop matching anything in the source.
 */
const SIGNATURE_HEADERS = /(?:^|[^a-z0-9-])(x-[a-z0-9-]*(?:signature|sign|token|auth|apikey|api-key|key|hmac|hash|checksum|nonce|timestamp|ts|verify|proof)[a-z0-9-]*)(?=["'`\s,;)\]}])/gi;

/** Function/variable names implying a client-side signature. */
const SIGNATURE_FUNCS = /\b(\w*(?:signature|signRequest|computeSign|makeToken|buildAuth|authHeader|hmac|sha256|sha1|md5|digest|checksum|verifyRequest|getToken|apiKey|secretKey|encrypt|decrypt|signPayload)\w*)\s*[=(]/g;

/** Role/permission checks performed in the browser (a hint the server may skip). */
const CLIENT_ROLE_CHECKS = [
  /\b(isAdmin|is_admin|hasRole|hasPermission|canAccess|isOwner|isEditor|isModerator|role\s*===|role\s*==|user\.role|permissions?\.(?:includes|has)|currentUser\.isSuperUser)\b/gi,
  /\bif\s*\(\s*(?:user|state|props|ctx)\??\.(?:role|isAdmin|admin|permissions|is_staff|superuser)\s*\)/gi,
];

/** Fields the client sends that the server should never trust. */
const CLIENT_PRIVILEGE = /\b(role|is_admin|isAdmin|admin|is_staff|isStaff|superuser|super_user|permissions|permission|scope|scopes|tenant_id|tenantId|org_id|orgId|owner_id|ownerId|user_id|userId|verified|is_verified|balance|credits|price|discount|plan|tier|subscription|quota)\b(?=\s*[:=])/gi;

/** Endpoints that look privileged, to cross-reference against the matrix. */
const ADMIN_ENDPOINT = /\/(?:admin|administrator|internal|private|management|manage|backoffice|staff|moderator|debug|_admin)(?:\/|$|\.)/i;

/**
 * Analyse one JS source string. Returns leads plus raw signals.
 */
function analyseJs(source, meta = {}) {
  const src = String(source || '');
  const out = { signatures: [], roles: [], privilegeFields: [], adminEndpoints: [], urls: [] };
  if (!src) return out;

  // 1. Client-computed auth headers.
  const headers = new Set();
  let m;
  SIGNATURE_HEADERS.lastIndex = 0;
  while ((m = SIGNATURE_HEADERS.exec(src))) {
    const h = m[1].toLowerCase();
    // Only interesting if the bundle also *uses* it as a header: assigned in an
    // object literal ("X-Foo": v), pushed to a headers object, or passed to
    // setRequestHeader. Matching the quoted name followed by `:` covers the
    // object-literal form, which is the common one.
    const e = h.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const used = new RegExp(`["'\`]${e}["'\`]\\s*:`, 'i').test(src)          // { "X-Foo": v }
      || new RegExp(`["'\`]${e}["'\`]\\s*[,}\\])]`, 'i').test(src)          // headers.push("X-Foo")
      || new RegExp(`headers?\\s*[\\[.].{0,40}${e}`, 'i').test(src)
      || new RegExp(`setRequestHeader\\([^)]*${e}`, 'i').test(src);
    if (used) headers.add(h);
  }
  for (const h of headers) {
    const fn = src.match(new RegExp(`[^\\n]{0,80}${h.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[^\\n]{0,80}`, 'i'));
    out.signatures.push({ header: h, context: fn ? fn[0].trim().slice(0, 160) : '' });
  }

  // 2. Signature/hashing functions.
  const funcs = new Set();
  SIGNATURE_FUNCS.lastIndex = 0;
  while ((m = SIGNATURE_FUNCS.exec(src))) funcs.add(m[1]);

  // 3. Client-side role checks.
  const roles = new Set();
  for (const rx of CLIENT_ROLE_CHECKS) {
    rx.lastIndex = 0;
    while ((m = rx.exec(src))) roles.add(m[0].trim().slice(0, 60));
  }
  out.roles = [...roles].slice(0, 10);
  out.signatureFuncs = [...funcs].slice(0, 10);

  // 4. Privilege fields assigned in the client.
  const priv = new Set();
  CLIENT_PRIVILEGE.lastIndex = 0;
  while ((m = CLIENT_PRIVILEGE.exec(src))) priv.add(m[1]);
  out.privilegeFields = [...priv].slice(0, 20);

  // 5. Admin-looking endpoints, to prioritise in the matrix.
  const eps = new Set();
  const urlRx = /["'`](\/[a-zA-Z0-9_\-./]*(?:admin|internal|private|manage|staff|moderator|debug)[a-zA-Z0-9_\-./]*)["'`]/gi;
  while ((m = urlRx.exec(src))) eps.add(m[1]);
  out.adminEndpoints = [...eps].slice(0, 20);

  // 6. Absolute URLs (internal hostnames are a recon gift).
  const urls = new Set();
  const absRx = /https?:\/\/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[^"'`\s)]*/g;
  while ((m = absRx.exec(src))) {
    if (!/\b(localhost|127\.0\.0\.1|example\.com|w3\.org|schema\.org|github\.com|googleapis|gstatic|jquery|bootstrap|cdnjs|jsdelivr|unpkg|fontawesome)/i.test(m[1])) {
      urls.add(m[0]);
    }
  }
  out.urls = [...urls].slice(0, 25);
  out.meta = meta;
  return out;
}

/** Turn JS analysis into leads. These are investigative starting points. */
function leadsFromAnalysis(analysis, baseUrl) {
  const leads = [];
  const src = analysis.meta && analysis.meta.source ? analysis.meta.source : 'bundle';

  for (const s of analysis.signatures) {
    leads.push(makeLead({
      cls: 'authz',
      title: `Client-computed auth header '${s.header}' in ${src}`,
      url: baseUrl,
      source: 'jslogic',
      severity_hint: 'medium',
      evidence: `${s.header} is set by client code. If the server derives this from values the client already knows (user id, UA, timestamp), the check is forgeable. Context: ${s.context}`,
      chain_hints: ['authz', 'authn'],
      proof_needed: [
        'identify the exact values hashed/signed',
        'reproduce the signature independently',
        'show the privileged endpoint accepting the forged header as a non-admin',
      ],
    }));
  }

  if (analysis.signatureFuncs && analysis.signatureFuncs.length) {
    leads.push(makeLead({
      cls: 'authz',
      title: `Client-side signature/token function in ${src}: ${analysis.signatureFuncs.slice(0, 3).join(', ')}`,
      url: baseUrl,
      source: 'jslogic',
      severity_hint: 'low',
      evidence: `Functions matching signature/token/hashing patterns: ${analysis.signatureFuncs.join(', ')}`,
      proof_needed: ['read the function', 'recompute the value with attacker-controlled inputs', 'replay the request without a valid session'],
    }));
  }

  for (const r of analysis.roles) {
    leads.push(makeLead({
      cls: 'authz',
      title: `Client-side role/permission gate in ${src}: ${r.slice(0, 50)}`,
      url: baseUrl,
      source: 'jslogic',
      severity_hint: 'low',
      evidence: `Role logic present in client code: ${r}. A UI gate is not a server gate — test the endpoint directly with a low-privilege session.`,
      proof_needed: ['locate the endpoint the gate protects', 'call it as a low-privilege user', 'show the action succeeds'],
    }));
  }

  if (analysis.privilegeFields.length) {
    leads.push(makeLead({
      cls: 'authz',
      title: `Mass-assignment candidates in ${src}: ${analysis.privilegeFields.slice(0, 6).join(', ')}`,
      url: baseUrl,
      source: 'jslogic',
      severity_hint: 'medium',
      evidence: `Client sends these fields: ${analysis.privilegeFields.join(', ')}. Add unlisted ones (is_admin, role, tenant_id) to a normal request and see what sticks.`,
      proof_needed: ['baseline request without the field', 'request with the privilege field added', 'diff response and server-side effect'],
    }));
  }

  return leads;
}

/** Walk a local directory of bundles, or accept a single file. */
function scanPath(target) {
  const files = [];
  const st = fs.existsSync(target) ? fs.statSync(target) : null;
  if (!st) return { analyses: [], leads: [] };
  if (st.isFile()) files.push(target);
  else {
    const walk = (d, depth) => {
      if (depth > 4) return;
      let entries = [];
      try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
      for (const e of entries) {
        const p = path.join(d, e.name);
        if (e.isDirectory()) walk(p, depth + 1);
        else if (/\.(js|mjs|cjs)$/i.test(e.name) && !/\.min\.js$/i.test(e.name) && !/node_modules/.test(p)) files.push(p);
      }
    };
    walk(target, 0);
  }
  const analyses = [];
  const leads = [];
  for (const f of files.slice(0, 200)) {
    let src = '';
    try { src = fs.readFileSync(f, 'utf8'); } catch { continue; }
    if (src.length > 4 * 1024 * 1024) continue;   // skip source maps / bundles
    const a = analyseJs(src, { source: path.basename(f), path: f });
    analyses.push(a);
    leads.push(...leadsFromAnalysis(a));
  }
  return { analyses, leads, files: files.length };
}

module.exports = { analyseJs, leadsFromAnalysis, scanPath, SIGNATURE_HEADERS, CLIENT_ROLE_CHECKS, CLIENT_PRIVILEGE, ADMIN_ENDPOINT };
