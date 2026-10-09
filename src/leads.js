'use strict';
/**
 * Lead store — the central abstraction of the harness.
 *
 * A "lead" is NOT a finding. It is a signal worth reasoning about.
 * Tenzai's formulation: a JSON response containing an agent schema is not a
 * vulnerability, it is a *lead*. Most scanners conflate the two, which is why
 * they produce a flood of unactionable output and why ~15% of an elite
 * researcher's HackerOne submissions still come back "not applicable".
 *
 * This store keeps leads as first-class, addressable records so the model
 * reasons over a prioritised queue instead of a wall of tool text. Nothing
 * becomes a finding here — that gate lives in gate.js and requires proof.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex').slice(0, 16);

/** Priority drives the attention queue. Ordered by how much reasoning is needed. */
const PRIORITY = {
  authz: 95,      // access control primitives chain the most
  authn: 90,
  injection: 88,
  ssrf: 86,
  deser: 85,
  xss: 70,
  traversal: 75,
  secrets: 80,
  config: 55,     // headers, cookies
  recon: 40,      // tech/endpoint inventory
  ai: 92,         // agent metadata, tool inventories
  business: 90,
};

const CLASS_MAP = [
  [/idor|broken access|bacl?|insecure direct object/i, 'authz'],
  [/csrf|missing.*token|anti-?csrf/i, 'authz'],
  [/auth.*bypass|weak.*password|default.*cred|brute|login|jwt|oauth|session/i, 'authn'],
  [/sql ?injection|sqli|nosql/i, 'injection'],
  [/command injection|rce|code injection|deserial|pickle|unserial/i, 'injection'],
  [/ssrf|server.?side request|fetch.*url|url.*fetch/i, 'ssrf'],
  [/xss|cross.?site script/i, 'xss'],
  [/traversal|lfi|path.*includ|directory travers|\.\.\//i, 'traversal'],
  [/secret|api.?key|token|password|credential|leak/i, 'secrets'],
  [/header|csp|cors|cookie|certificate|tls|mixed.?content/i, 'config'],
  [/agent|prompt|llm|model|mcp|tool.?call|guardrail/i, 'ai'],
  [/business|workflow|state machine|invite|referral|quota/i, 'business'],
  [/endpoint|host|domain|port|tech|service|technology|header|recon/i, 'recon'],
];

function classify(text) {
  const t = String(text || '');
  for (const [rx, cls] of CLASS_MAP) if (rx.test(t)) return cls;
  return 'recon';
}

function priorityOf(lead) {
  return lead.priority ?? PRIORITY[lead.cls] ?? 40;
}

/**
 * Create a normalised lead.
 * @param {object} o raw signal
 * @returns {object} lead
 */
function makeLead(o) {
  const cls = o.cls || classify([o.title, o.category, o.evidence, o.source].join(' '));
  const url = o.url || o.matched || o.host || '';
  // Derive the parameter from the URL when the tool did not label it. Almost
  // every scanner only reports a matched URL, and the parameter name is the
  // primary correlation key for injection/authz chaining.
  const param = o.param || o.parameter
    || (typeof o.matcher === 'string' ? extractParam(o.matcher) : undefined)
    || extractParam(url);
  const lead = {
    id: o.id || sha(`${cls}|${url}|${o.title}`),
    cls,
    title: o.title || o.name || o.class || 'untitled lead',
    url,
    param,
    source: o.source || 'unknown',
    severity_hint: o.severity_hint || o.severity || 'info',
    confidence: o.confidence ?? 'unverified',
    evidence: truncate(o.evidence || '', 1200),
    // Correlation keys — the chain builder groups on these.
    asset: assetOf(url, o.asset),
    identity: o.identity || 'anonymous',
    actor: o.actor,
    state: o.state,
    // Proof requirements: what must be demonstrated before this can be reported.
    // Normalised to an array — callers pass arrays in some places and a bare
    // string in others (hunt.js, prober.js), and gate.js maps over this. A string
    // here crashed the queue build with "proof_needed.map is not a function",
    // taking the whole attention queue down with it.
    proof_needed: (Array.isArray(o.proof_needed)
      ? o.proof_needed
      : o.proof_needed
        ? [String(o.proof_needed)]
        : defaultProof(cls)
    ).filter((x) => x != null && String(x).trim()),
    tsv: new Date().toISOString(),
    tags: Array.isArray(o.tags) ? o.tags : [],
    chain_hints: o.chain_hints || [],
  };
  lead.priority = priorityOf(lead);
  return lead;
}

function extractParam(u) {
  const s = String(u || '');
  // Only look at the query string, not the path.
  const qi = s.indexOf('?');
  if (qi < 0) return undefined;
  const query = s.slice(qi + 1).split('#')[0];
  const names = [];
  for (const pair of query.split('&')) {
    const m = pair.match(/^([a-zA-Z_][a-zA-Z0-9_.%-]{0,60})=/);
    if (m) names.push(decodeURIComponent(m[1]));
  }
  if (!names.length) return undefined;
  // Prefer a parameter that looks like the interesting one over a plain
  // object id, which is usually just the resource selector.
  const interesting = names.find((n) => !/^(id|ids|p|page|no|offset|limit|per_page|page_size)$/i.test(n));
  return interesting || names[0];
}

function assetOf(url, explicit) {
  if (explicit) return explicit;
  if (!url) return 'unknown';
  try {
    const u = new URL(url.startsWith('http') ? url : `https://${url}`);
    return u.host;
  } catch {
    return String(url).split('/')[0] || 'unknown';
  }
}

function defaultProof(cls) {
  switch (cls) {
    case 'injection': return ['differential response vs baseline', 'error/boolean/time signature'];
    case 'authz': return ['second identity reproduces the access', 'privileged action shown'];
    case 'authn': return ['unauthenticated or cross-tenant access proven'];
    case 'ssrf': return ['server-side fetch proven (OOB callback or internal response)'];
    case 'xss': return ['payload executes in the target origin (DOM proof)'];
    case 'traversal': return ['out-of-scope file content returned'];
    case 'secrets': return ['key validated as live OR proven in-repo exposure'];
    case 'ai': return ['tool/schema/credential path reached and abused'];
    case 'business': return ['state transition or invariant violated end-to-end'];
    case 'config': return ['header/flag actually absent on the live response'];
    default: return ['manual confirmation'];
  }
}

const truncate = (s, n) => (s && s.length > n ? s.slice(0, n) + '…' : s);

/** In-memory store with stable ordering and de-duplication. */
class LeadStore {
  constructor() {
    this.leads = new Map();
  }

  add(raw) {
    const lead = raw instanceof Object && raw.cls && raw.evidence !== undefined && raw.tsv
      ? raw
      : makeLead(raw);
    const prev = this.leads.get(lead.id);
    if (prev) {
      // Reinforcement: same lead seen again raises confidence, never severity.
      prev.observations = (prev.observations || 1) + 1;
      if (prev.confidence === 'unverified' && lead.confidence === 'confirmed') prev.confidence = 'confirmed';
      prev.seen_count = (prev.seen_count || 1) + 1;
      return prev;
    }
    lead.observations = 1;
    lead.seen_count = 1;
    this.leads.set(lead.id, lead);
    return lead;
  }

  all() {
    return [...this.leads.values()].sort((a, b) => b.priority - a.priority || a.id.localeCompare(b.id));
  }

  byClass(cls) {
    return this.all().filter((l) => l.cls === cls);
  }

  byAsset(asset) {
    return this.all().filter((l) => l.asset === asset);
  }

  /** Leads most likely to chain: privileged classes with identity or asset overlap. */
  chainable() {
    return this.all().filter((l) => ['authz', 'authn', 'injection', 'ai', 'ssrf', 'business'].includes(l.cls));
  }

  get size() {
    return this.leads.size;
  }

  toJSON() {
    return this.all();
  }

  static fromJSON(arr) {
    const s = new LeadStore();
    for (const l of arr || []) s.leads.set(l.id, l);
    return s;
  }
}

module.exports = { LeadStore, makeLead, classify, priorityOf, PRIORITY, CLASS_MAP, sha, defaultProof, truncate };
