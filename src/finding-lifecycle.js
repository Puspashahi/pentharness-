'use strict';

const crypto = require('crypto');

const STATUSES = new Set([
  'lead',
  'candidate',
  'proven',
  'refuted',
  'accepted',
  'suppressed',
  'duplicate',
  'stale',
  'needs-review',
]);

const TRANSITIONS = {
  lead: new Set(['candidate', 'refuted', 'suppressed', 'stale', 'needs-review']),
  candidate: new Set(['proven', 'refuted', 'suppressed', 'duplicate', 'stale', 'needs-review']),
  proven: new Set(['accepted', 'refuted', 'suppressed', 'duplicate', 'stale', 'needs-review']),
  'needs-review': new Set(['candidate', 'proven', 'refuted', 'suppressed', 'duplicate', 'stale']),
  accepted: new Set(['stale', 'needs-review']),
  refuted: new Set(['needs-review']),
  suppressed: new Set(['needs-review']),
  duplicate: new Set(['needs-review']),
  stale: new Set(['needs-review', 'candidate']),
};

function idFor(finding) {
  return finding.id || crypto.createHash('sha256')
    .update(JSON.stringify({ title: finding.title, target: finding.target || finding.url, category: finding.category || finding.cls }))
    .digest('hex').slice(0, 16);
}

function assertStatus(status) {
  if (!STATUSES.has(status)) throw new Error(`invalid finding status: ${status}`);
}

class FindingLifecycle {
  constructor(finding = {}, status = 'lead') {
    assertStatus(status);
    this.finding = { ...finding, id: idFor(finding) };
    this.status = status;
    this.history = [{
      status,
      reason: 'initial lifecycle state',
      detail: {},
      at: new Date().toISOString(),
    }];
  }

  transition(status, reason, detail = {}) {
    assertStatus(status);
    if (!String(reason || '').trim()) throw new TypeError('lifecycle transition reason is required');
    if (status !== this.status && !TRANSITIONS[this.status].has(status)) {
      throw new Error(`invalid finding transition: ${this.status}->${status}`);
    }
    this.status = status;
    this.history.push({ status, reason: String(reason), detail, at: new Date().toISOString() });
    return this;
  }

  toJSON() {
    return { ...this.finding, status: this.status, history: this.history.slice() };
  }
}

function fromJSON(value) {
  if (!value || typeof value !== 'object') throw new TypeError('finding lifecycle record is required');
  const lifecycle = new FindingLifecycle(value, value.status || 'lead');
  if (!Array.isArray(value.history) || !value.history.length) throw new Error('finding lifecycle history is required');
  lifecycle.history = value.history.map((entry) => {
    assertStatus(entry.status);
    if (!entry.at || !entry.reason) throw new Error('finding lifecycle history entries require status, reason, and at');
    return { status: entry.status, reason: String(entry.reason), detail: entry.detail || {}, at: entry.at };
  });
  lifecycle.status = value.status;
  return lifecycle;
}

module.exports = { STATUSES, TRANSITIONS, FindingLifecycle, fromJSON };
