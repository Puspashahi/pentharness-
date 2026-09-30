'use strict';
/**
 * Target knowledge base — persistent, compounding memory.
 *
 * Tenzai: "If the first agent iteration learns where agent configurations
 * live, the next iteration does not start by rediscovering them."
 *
 * This is the mechanism. It is a *target profile* that survives across runs,
 * so reconnaissance is paid for once. It is NOT a transcript: it holds only
 * durable, re-usable facts (tech, endpoints, params, auth shape, AI surface,
 * negative results) — plus explicit negative evidence, so the agent does not
 * re-test what is already known not to work.
 */
const fs = require('fs');
const path = require('path');

class TargetKB {
  constructor(target) {
    this.target = target;
    this.tech = new Set();
    this.endpoints = new Map();     // url -> {first_seen, last_seen, params:Set, forms:n, has_auth}
    this.params = new Set();        // param names seen anywhere
    this.auth = { observed: false, scheme: new Set(), cookie_names: new Set(), login_endpoints: [] };
    this.ai_surface = { agent_endpoints: [], tool_inventories: [], instruction_leaks: [], guardrails: [] };
    this.rate_limited = new Set();  // endpoints that throttled us
    this.negatives = [];            // tested-and-refuted, with reason
    this.prior_chains = [];         // chains confirmed in earlier runs
    this.history = [];              // run summaries
    this.created = new Date().toISOString();
    this.updated = this.created;
  }

  // ---- ingestion -------------------------------------------------------
  learnTech(items) {
    for (const t of items || []) if (t) this.tech.add(String(t).toLowerCase());
    return this;
  }

  learnEndpoint(url, meta = {}) {
    if (!url) return this;
    let e = this.endpoints.get(url);
    if (!e) {
      e = { first_seen: new Date().toISOString(), params: [], forms: 0, has_auth: false };
      this.endpoints.set(url, e);
    }
    e.last_seen = new Date().toISOString();
    if (meta.param) {
      if (!e.params.includes(meta.param)) e.params.push(meta.param);
      this.params.add(meta.param);
    }
    if (meta.forms) e.forms += meta.forms;
    if (meta.has_auth) e.has_auth = true;
    return this;
  }

  learnAuth(a = {}) {
    if (a.observed) this.auth.observed = true;
    for (const s of a.scheme || []) this.auth.scheme.add(s);
    for (const c of a.cookies || []) this.auth.cookie_names.add(c);
    if (a.login_endpoint && !this.auth.login_endpoints.includes(a.login_endpoint)) {
      this.auth.login_endpoints.push(a.login_endpoint);
    }
    return this;
  }

  learnAI(kind, url) {
    if (!url) return this;
    const buckets = {
      agent: 'agent_endpoints', tool: 'tool_inventories',
      instruction: 'instruction_leaks', guardrail: 'guardrails',
    };
    const b = buckets[kind];
    if (b && !this.ai_surface[b].includes(url)) this.ai_surface[b].push(url);
    return this;
  }

  markRateLimited(url) {
    if (url) this.rate_limited.add(url);
    return this;
  }

  /** Record a refuted hypothesis so it is not retried. */
  addNegative(kind, target, reason) {
    this.negatives.push({ kind, target, reason, tsv: new Date().toISOString() });
    return this;
  }

  wasTested(kind, target) {
    return this.negatives.some((n) => n.kind === kind && n.target === target);
  }

  addChain(chain) {
    this.prior_chains.push({ ...chain, tsv: new Date().toISOString() });
    return this;
  }

  endRun(summary) {
    this.history.push({ ...summary, tsv: new Date().toISOString() });
    this.updated = new Date().toISOString();
    return this;
  }

  // ---- queries used to plan work ---------------------------------------
  untestedParams(candidateParams) {
    return candidateParams.filter((p) => !this.params.has(p));
  }

  /** Injection surface: endpoints that have params, excluding known rate-limited. */
  injectionSurface() {
    const out = [];
    for (const [url, e] of this.endpoints) {
      if (e.params.length && !this.rate_limited.has(url)) out.push({ url, params: e.params });
    }
    return out;
  }

  aiSurfaceEntries() {
    const out = [];
    for (const u of this.ai_surface.agent_endpoints) out.push({ kind: 'agent', url: u });
    for (const u of this.ai_surface.tool_inventories) out.push({ kind: 'tool', url: u });
    for (const u of this.ai_surface.instruction_leaks) out.push({ kind: 'instruction', url: u });
    for (const u of this.ai_surface.guardrails) out.push({ kind: 'guardrail', url: u });
    return out;
  }

  // ---- persistence -----------------------------------------------------
  toJSON() {
    return {
      target: this.target,
      created: this.created,
      updated: this.updated,
      tech: [...this.tech],
      endpoints: [...this.endpoints.entries()].map(([url, e]) => [url, { ...e, params: e.params }]),
      params: [...this.params],
      auth: { observed: this.auth.observed, scheme: [...this.auth.scheme], cookie_names: [...this.auth.cookie_names], login_endpoints: this.auth.login_endpoints },
      ai_surface: this.ai_surface,
      rate_limited: [...this.rate_limited],
      negatives: this.negatives.slice(-200),
      prior_chains: this.prior_chains,
      history: this.history.slice(-50),
    };
  }

  static fromJSON(o) {
    const kb = new TargetKB(o.target);
    if (!o) return kb;
    kb.created = o.created || kb.created;
    kb.updated = o.updated || kb.updated;
    (o.tech || []).forEach((t) => kb.tech.add(t));
    (o.endpoints || []).forEach(([url, e]) => kb.endpoints.set(url, { ...e, params: e.params || [] }));
    (o.params || []).forEach((p) => kb.params.add(p));
    if (o.auth) {
      kb.auth.observed = !!o.auth.observed;
      (o.auth.scheme || []).forEach((s) => kb.auth.scheme.add(s));
      (o.auth.cookie_names || []).forEach((c) => kb.auth.cookie_names.add(c));
      kb.auth.login_endpoints = o.auth.login_endpoints || [];
    }
    if (o.ai_surface) kb.ai_surface = o.ai_surface;
    (o.rate_limited || []).forEach((u) => kb.rate_limited.add(u));
    kb.negatives = o.negatives || [];
    kb.prior_chains = o.prior_chains || [];
    kb.history = o.history || [];
    return kb;
  }

  save(file) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(this.toJSON(), null, 2));
    return file;
  }

  static load(file) {
    if (!fs.existsSync(file)) return null;
    try {
      return TargetKB.fromJSON(JSON.parse(fs.readFileSync(file, 'utf8')));
    } catch {
      return null;
    }
  }
}

module.exports = { TargetKB };
