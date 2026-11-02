'use strict';

const { inScope } = require('./subdomains');
const { HeaderPolicy } = require('./headerpolicy');
const { ResourceBudget } = require('./resource-budget');
const { SAFE_METHODS } = require('./replay-methods');

class RequestBroker {
  constructor({ config = {}, policy, budget, transport, now = () => new Date().toISOString() } = {}) {
    if (typeof transport !== 'function') throw new TypeError('request broker transport is required');
    this.config = config;
    this.policy = policy || new HeaderPolicy({ headers: config.headers, throttle: config.throttle });
    this.budget = budget instanceof ResourceBudget ? budget : new ResourceBudget(config);
    this.transport = transport;
    this.now = now;
    this.audit = [];
  }

  async request(request) {
    const method = String(request.method || 'GET').toUpperCase();
    let url;
    try { url = new URL(request.url); } catch {
      return this.block(request, 'invalid URL');
    }
    const scope = inScope(url.hostname, this.config.scope || []);
    if (!scope.ok) return this.block(request, scope.reason);
    if (!this.policy.isAllowed(url.href)) return this.block(request, 'program-prohibited URL');
    const stateChanging = !SAFE_METHODS.has(method);
    if (stateChanging && (!request.approval || request.approval.approved !== true)) {
      return this.block(request, 'state-changing request requires a valid approval token');
    }
    await this.policy.take();
    const release = this.budget.acquire(Buffer.byteLength(String(request.body || '')));
    this.record(request, 'allow', scope.reason);
    try {
      return await this.transport({ ...request, method, url: url.href, headers: this.policy.merge(request.headers) });
    } finally {
      release();
    }
  }

  block(request, reason) {
    this.record(request, 'block', reason);
    return { blocked: true, reason };
  }

  record(request, decision, reason) {
    this.audit.push({
      at: this.now(),
      method: String(request.method || 'GET').toUpperCase(),
      url: String(request.url || ''),
      phase: request.phase || 'replay',
      authorizationBasis: request.authorizationBasis || (request.stateChanging ? 'approval-token' : 'scope'),
      decision,
      reason,
    });
  }

  toJSON() {
    return { audit: this.audit.slice(), budget: this.budget.toJSON() };
  }
}

module.exports = { RequestBroker };
