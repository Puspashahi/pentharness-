'use strict';
/**
 * Authorization matrix — dual-identity session diffing.
 *
 * Every serious broken-access-control guide converges on the same primitive:   "the primitive that actually finds BAC is the same: replay a request under
 *    a second identity and diff the response."  (Autorize / AuthMatrix do this)
 *
 * And the market justifies the effort:
 *   - IDOR/BOLA is the single highest-yield class on current bounty platforms
 *   - "automated scanners catch less than 5% of IDOR bugs because they cannot
 *     understand business logic or authorization intent"
 *   - IDOR/access control is *rising* while commodity XSS/SQLi decline
 *
 * The artifact produced is the authorization matrix: roles across, endpoints
 * down, intended access marked, actual access measured. "One broken cell in
 * that cross-tenant column is usually the biggest finding on the engagement."
 *
 * This module does the diffing and the accounting. It does not decide whether a
 * 200 is "allowed" — that is the developer's intent, which only a human or the
 * program scope defines. It reports the *delta* between identities, which is
 * objective.
 */
const fs = require('fs');
const { makeLead, sha } = require('./leads');

/** The four lenses, plus the two matrices every endpoint should face. */
const LENSES = [
  { id: 'anon', label: 'anonymous (no session)', expect: 'deny unless public' },
  { id: 'lowpriv', label: 'other user, target is A resource', expect: 'deny' },
  { id: 'cross-tenant', label: 'user in another org/tenant', expect: 'deny' },
  { id: 'field', label: 'extra privilege fields injected', expect: 'ignored' },
];

const METHOD_MATRIX = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

/**
 * The confused-deputy mutation set.
 *
 * Field guidance: "The real bug is not always in the direct ID swap. It is in
 * what happens when the application receives a value the developer never
 * anticipated... Your ID as null. Your ID as undefined. The victim's ID dropped
 * into a field that was never supposed to hold any user ID at all. Stop trying
 * to bypass one check. Start trying to make the application unsure which check
 * to run."
 */
const CONFUSED_DEPUTY = [
  { id: 'null', kind: 'type-confusion', apply: (v) => 'null', why: 'absent-value handling: does the code branch differently for null than for 0/""?' },
  { id: 'undefined', kind: 'type-confusion', apply: () => 'undefined', why: 'JS undefined literal reaches a JSON parser' },
  { id: 'empty', kind: 'type-confusion', apply: () => '', why: 'empty value may skip an `if (id)` guard' },
  { id: 'zero', kind: 'type-confusion', apply: () => '0', why: 'falsy zero can bypass truthiness checks' },
  { id: 'negative', kind: 'type-confusion', apply: (v) => '-1', why: 'negative index may wrap or select the last row' },
  { id: 'huge', kind: 'type-confusion', apply: () => '999999999', why: 'overflow / cast behaviour' },
  { id: 'array-wrap', kind: 'type-confusion', apply: (v) => JSON.stringify([v]), why: 'scalar expected, array supplied — classic ORM coercion bug' },
  { id: 'object-wrap', kind: 'type-confusion', apply: (v) => JSON.stringify({ id: v }), why: 'mass-assignment shape confusion' },
  { id: 'bool-string', kind: 'type-confusion', apply: () => 'true', why: 'PHP-style truthy string coercion' },
  { id: 'duplicate', kind: 'parser', note: 'append the same param twice; last-wins vs first-wins is a real authz split', why: 'parameter pollution across parsers' },
  { id: 'array-param', kind: 'parser', note: 'id[]=1&id[]=2 — batch semantics bypass per-object checks', why: 'bulk endpoint where only the first id is authorised' },
  { id: 'case', kind: 'parser', note: 'Id= / ID= — case-sensitive authz keys', why: 'authorisation key compared case-sensitively' },
];

/** Privilege fields injected by the `field` lens. */
const PRIVILEGE_FIELDS = ['role', 'is_admin', 'admin', 'is_staff', 'superuser', 'permissions', 'scope', 'level', 'tenant_id', 'org_id', 'user_id', 'owner_id', 'verified', 'is_verified', 'balance', 'credits', 'price', 'discount', 'plan', 'tier', 'status'];

/** Older API versions often lack checks added to newer ones. */
function versionDowngrades(path) {
  const out = [];
  const re = /\/v(\d+)(\/|$)/i;
  const m = String(path).match(re);
  if (!m) return out;
  const v = parseInt(m[1], 10);
  for (let i = v - 1; i >= 1 && i >= v - 3; i--) out.push(String(path).replace(re, `/v${i}/`));
  return out;
}

/** Alternate resource paths that are frequently left ungated. */
function altPaths(path) {
  const out = [];
  const p = String(path);
  for (const pre of ['/internal', '/private', '/admin', '/api/internal', '/api/private', '/api/admin', '/_internal', '/debug']) {
    if (!p.startsWith(pre)) out.push(pre + p);
  }
  if (/\/api\//.test(p)) out.push(p.replace('/api/', '/'));
  return out;
}

/**
 * Compare two responses from different identities. Returns an objective verdict.
 */
function diffResponses(a, b) {
  if (!a || !b) return { differs: false, reason: 'missing response' };
  if (a.status !== b.status) return { differs: true, reason: `status ${a.status} vs ${b.status}`, severityBoost: true };
  const la = a.length ?? (a.body ? a.body.length : 0);
  const lb = b.length ?? (b.body ? b.body.length : 0);
  if (la !== lb) return { differs: true, reason: `body length ${la} vs ${lb}`, severityBoost: true };
  if (a.body && b.body && a.body !== b.body) {
    return { differs: true, reason: `identical length, different body (${la} bytes)`, severityBoost: true, suspicion: 'content differs' };
  }
  return { differs: false, reason: `identical (${a.status}, ${la} bytes)` };
}

/** Cheap similarity so we can tell "same page, one field changed" from "different page". */
function similarity(a, b) {
  const ta = new Set(String(a || '').split(/\s+/).filter((x) => x.length > 2));
  const tb = new Set(String(b || '').split(/\s+/).filter((x) => x.length > 2));
  if (!ta.size || !tb.size) return 0;
  let inter = 0;
  for (const t of ta) if (tb.has(t)) inter++;
  return inter / (ta.size + tb.size - inter);
}

/**
 * AuthorizationMatrix — accumulates measured access per (endpoint, identity).
 */
class AuthorizationMatrix {
  constructor(target) {
    this.target = target;
    this.cells = new Map();   // `${method} ${path} :: ${lens}` -> cell
    this.identities = new Set(['anon']);
    this.coverage = { endpoints: 0, lensesTested: 0, methodsTested: 0 };
  }

  addIdentity(id) {
    if (id) this.identities.add(id);
  }

  record({ method = 'GET', path, lens, identity, status, length, body, expected = 'deny', note }) {
    const key = `${method} ${path} :: ${lens}`;
    let c = this.cells.get(key);
    if (!c) {
      c = { method, path, lens, expected, observations: [], breaches: [] };
      this.cells.set(key, c);
    }
    c.observations.push({ identity, status, length, note });
    return c;
  }

  /**
   * Compare the same endpoint across identities. A cell where a non-owner
   * identity received the same-or-better treatment than the owner is the
   * definition of a broken access control cell.
   */
  evaluate() {
    const findings = [];
    // group by (method, path)
    const groups = new Map();
    for (const [key, c] of this.cells) {
      const gk = `${c.method} ${c.path}`;
      if (!groups.has(gk)) groups.set(gk, []);
      groups.get(gk).push(c);
    }
    for (const [gk, cells] of groups) {
      for (const c of cells) {
        if (c.expected !== 'deny') continue;      // only gate-expected endpoints matter
        const granted = c.observations.filter((o) => o.status >= 200 && o.status < 300);
        if (!granted.length) continue;

        // Public-vs-broken: an endpoint is only a *breach* if some identity was
        // denied while another was granted on the same endpoint. If nobody was
        // denied, it is a public endpoint that was merely mislabelled as
        // gate-expected — a scoping question, not an authorization flaw.
        const denied = c.observations.filter((o) => o.status === 401 || o.status === 403);
        if (!denied.length) continue;
        // Require a genuine identity differential: at least one denied identity
        // distinct from a granted one.
        const deniedIdentities = new Set(denied.map((o) => o.identity));
        const differential = granted.some((g) => !deniedIdentities.has(g.identity));
        if (!differential) continue;

        for (const g of granted) {
          const lead = makeLead({
            cls: 'authz',
            title: `Access control: ${g.identity} received ${g.status} on a gate-expected ${c.method} ${c.path}`,
            url: this.abs(c.path),
            param: c.lens,
            source: 'authmatrix',
            severity_hint: 'high',
            evidence: `lens=${c.lens} (${c.lens}) identity=${g.identity} status=${g.status} len=${g.length ?? '?'}; expected deny, but ${deniedIdentities.size} identity/ies were denied on the same endpoint.`,
            identity: g.identity,
            chain_hints: ['business'],
            proof_needed: [
              'same request as the owner returns 200',
              'the denying identity receives 401/403 on the same path',
              "response body contains the other identity's data, not an empty shell",
            ],
          });
          findings.push(lead);
        }
      }
    }
    this.coverage.endpoints = groups.size;
    this.coverage.lensesTested = this.cells.size;
    return findings;
  }

  abs(path) {
    if (/^https?:/.test(path)) return path;
    return `${this.target.replace(/\/$/, '')}${path.startsWith('/') ? path : '/' + path}`;
  }

  /** Render the matrix itself — the artifact hunters build by hand. */
  toTable() {
    const rows = [];
    for (const [key, c] of this.cells) {
      rows.push({
        endpoint: `${c.method} ${c.path}`,
        lens: c.lens,
        expected: c.expected,
        observed: c.observations.map((o) => `${o.identity}:${o.status}`).join(' '),
      });
    }
    return rows;
  }

  toJSON() {
    return {
      target: this.target,
      identities: [...this.identities],
      coverage: this.coverage,
      cells: [...this.cells.entries()].map(([k, v]) => [k, v]),
    };
  }

  static fromJSON(o) {
    const m = new AuthorizationMatrix(o.target);
    for (const id of o.identities || []) m.addIdentity(id);
    for (const [k, v] of o.cells || []) m.cells.set(k, v);
    m.coverage = o.coverage || m.coverage;
    return m;
  }
}

/**
 * Build the test plan for an endpoint: which lenses, which methods, which
 * mutations. This is the "four lenses + method matrix" workflow, encoded.
 */
function planFor(endpoint) {
  const { path, method = 'GET', params = [], isWrite = false } = endpoint;
  const plan = { lenses: LENSES.map((l) => l.id), methods: [method], mutations: CONFUSED_DEPUTY.map((m) => m.id), altPaths: altPaths(path), downgrades: versionDowngrades(path), privilegeFields: PRIVILEGE_FIELDS };
  if (!isWrite) plan.methods = METHOD_MATRIX;   // read endpoints: try the full matrix
  if (params.length) plan.mutations = [...new Set([...plan.mutations, ...params.flatMap((p) => (p === 'id' || /_id$/.test(p) ? ['object-swap', 'array-param'] : []))])];
  return plan;
}

/**
 * Detect endpoints that leak other identities' object identifiers.
 *
 * The documented amplification: developers switch sequential IDs to UUIDs and
 * believe IDOR is solved. It isn't — the IDs still leak through search,
 * autocomplete, share dialogs, group rosters, activity feeds, audit logs,
 * exports, and any endpoint taking a name/email and returning metadata. A leak
 * plus an IDOR is a complete exploit chain and materially raises severity.
 *
 * @param {string} body response body
 * @param {string} identity the identity that fetched it
 * @returns {{count:number, samples:string[], kinds:string[]}|null}
 */
function identifierLeak(body, identity) {
  const b = String(body || '');
  if (b.length < 40) return null;
  const kinds = new Set();
  const samples = [];

  // UUIDs / GUIDs
  const uuid = b.match(/\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi);
  if (uuid && uuid.length) { kinds.add('uuid'); samples.push(...uuid.slice(0, 3)); }
  // opaque high-entropy hex tokens (32+ chars) — common as object refs
  const hex = b.match(/\b[0-9a-f]{32,64}\b/gi);
  if (hex && hex.length) { kinds.add('hex-token'); samples.push(...hex.slice(0, 3)); }
  // other users' ids alongside identity markers
  if (/(user_id|owner_id|account_id|member_id|tenant_id|created_by|author_id)/i.test(b) && (uuid || hex)) {
    kinds.add('owned-object-reference');
  }
  if (/\b(email|username|user_name|login)\b/i.test(b) && (uuid || hex)) {
    kinds.add('identity-plus-object');
  }
  if (!kinds.size) return null;
  return { count: (uuid ? uuid.length : 0) + (hex ? hex.length : 0), samples: [...new Set(samples)].slice(0, 5), kinds: [...kinds], identity };
}

/**
 * Read a capture file of recorded requests into comparison-ready observations.
 * Accepts JSONL (one JSON object per line, the format Burp/mitmproxy exports
 * and the format we ask operators to save) or a JSON array.
 *
 * Each row: { method, url, status, length?, body?, id? }
 */
function readCapture(file, defaultIdentity) {
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); } catch { return []; }
  let rows = [];
  const trimmed = raw.trim();
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

/**
 * Extract identity markers a payload claims to belong to.
 * Used to decide whether a 200 handed to identity B actually contains
 * identity A's data — the objective core of an IDOR proof.
 */
function ownershipMarkers(body) {
  const b = String(body || '');
  const out = { ids: new Set(), emails: new Set() };
  for (const m of b.matchAll(/\b(owner_id|user_id|account_id|tenant_id|created_by|author_id)\s*[=:]\s*["']?([A-Za-z0-9@._-]{3,})/gi)) {
    out.ids.add(m[2]);
  }
  for (const m of b.matchAll(/\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g)) out.emails.add(m[1]);
  return out;
}

/**
 * Is this a cross-identity disclosure?
 *
 * `victimBody` is what identity A (the owner) receives; `probeBody` is what
 * identity B receives for the same object. `probeIdentity` is B's label.
 *
 * Proven when B's payload carries A's identity markers AND those markers are
 * not B's own — otherwise a user reading their own record would be reported as
 * an attack, which is the fastest way to make a security tool ignored.
 */
function isCrossIdentityDisclosure(victimBody, probeBody, probeIdentity, probeOwnMarkers) {
  const v = ownershipMarkers(victimBody);
  const p = ownershipMarkers(probeBody);
  if (!v.ids.size && !v.emails.size) return { proven: false, reason: 'owner payload carries no identity marker to compare' };
  if (!p.ids.size && !p.emails.size) return { proven: false, reason: 'probe payload carries no identity marker' };
  const shared = [...v.ids].filter((x) => p.ids.has(x)).concat([...v.emails].filter((x) => p.emails.has(x)));
  if (!shared.length) return { proven: false, reason: "probe payload does not contain the owner's identity markers" };

  // If we know the probe's own markers and they cover every shared marker, the
  // probe is simply reading its own object. Not a disclosure.
  if (probeOwnMarkers && (probeOwnMarkers.ids.size || probeOwnMarkers.emails.size)) {
    const sharedIds = [...v.ids].filter((x) => p.ids.has(x));
    const sharedMail = [...v.emails].filter((x) => p.emails.has(x));
    const allAreProbeOwn = sharedIds.every((x) => probeOwnMarkers.ids.has(x)) && sharedMail.every((x) => probeOwnMarkers.emails.has(x));
    if (allAreProbeOwn) {
      return { proven: false, reason: 'probe received its own object; the shared markers are the probe identity\'s own' };
    }
  }
  return { proven: true, reason: `probe payload carries the owner's identity marker (${shared.join(', ')})`, markers: shared };
}

module.exports = { AuthorizationMatrix, LENSES, METHOD_MATRIX, CONFUSED_DEPUTY, PRIVILEGE_FIELDS, diffResponses, similarity, planFor, versionDowngrades, altPaths, identifierLeak, readCapture, ownershipMarkers, isCrossIdentityDisclosure, sha };
