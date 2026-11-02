'use strict';

/**
 * Metamorphic security testing.
 *
 * When an exact expected response is unknown, a relation between two
 * controlled observations can still be tested. This module only reports a
 * candidate when the relation is explicit and the violation is stable across
 * repeated samples.
 */
const D = require('./differential');

const RELATIONS = {
  'presentation-invariance': {
    description: 'presentation-only changes must not alter ownership or security decisions',
    required: ['baseline', 'variant'],
  },
  'read-order-invariance': {
    description: 'reordering independent read-only operations must preserve semantic results',
    required: ['baseline', 'variant'],
  },
  'permission-revocation': {
    description: 'removing permission must change a previously allowed response to denied',
    required: ['before', 'after'],
  },
  'logout-invalidation': {
    description: 'a session must not retain access after logout',
    required: ['before', 'after'],
  },
};

function responseShape(row) {
  return D.semanticShape(row || {});
}

function stableSamples(rows, minimum = 2) {
  const list = Array.isArray(rows) ? rows : [rows];
  if (list.length < minimum) return { stable: false, reason: `requires ${minimum} repeated samples` };
  const shapes = list.map(responseShape);
  const first = JSON.stringify(shapes[0]);
  const stable = shapes.every((shape) => JSON.stringify(shape) === first);
  return { stable, reason: stable ? 'repeated semantic shape is stable' : 'repeated samples disagree', samples: shapes };
}

function statuses(rows) {
  return (Array.isArray(rows) ? rows : [rows]).map((r) => Number(r && r.status || 0));
}

function evaluateCase(test, opts = {}) {
  const relation = RELATIONS[test.relation];
  if (!relation) return { id: test.id, verdict: 'invalid', reason: `unknown relation: ${test.relation}` };
  const minSamples = Math.max(2, Number(opts.minSamples || test.minSamples || 2));
  const result = { id: test.id, relation: test.relation, verdict: 'hold', description: relation.description };
  for (const key of relation.required) {
    if (!test[key]) return { ...result, verdict: 'invalid', reason: `missing ${key} observations` };
  }
  const leftKey = test.relation === 'permission-revocation' || test.relation === 'logout-invalidation' ? 'before' : 'baseline';
  const rightKey = test.relation === 'permission-revocation' || test.relation === 'logout-invalidation' ? 'after' : 'variant';
  const left = stableSamples(test[leftKey], minSamples);
  const right = stableSamples(test[rightKey], minSamples);
  if (!left.stable || !right.stable) return { ...result, verdict: 'hold', reason: `${left.reason}; ${right.reason}` };
  const a = Array.isArray(test[leftKey]) ? test[leftKey][0] : test[leftKey];
  const b = Array.isArray(test[rightKey]) ? test[rightKey][0] : test[rightKey];
  const diff = D.compare(a, b);
  const leftStatuses = statuses(test[leftKey]);
  const rightStatuses = statuses(test[rightKey]);
  let violated = false;
  let reason = '';
  if (test.relation === 'presentation-invariance' || test.relation === 'read-order-invariance') {
    const securityChanges = diff.changes.filter((c) => c.kind === 'ownership-field' || c.kind === 'security-field' || c.kind === 'status-class');
    violated = securityChanges.length > 0;
    reason = violated ? `security-relevant behavior changed: ${securityChanges.map((c) => c.kind).join(', ')}` : 'security-relevant behavior remained invariant';
  } else {
    const beforeAllowed = leftStatuses.some((s) => s >= 200 && s < 300);
    const afterDenied = rightStatuses.every((s) => s === 401 || s === 403);
    violated = beforeAllowed && !afterDenied;
    reason = violated ? 'access remained available after the security-state transition' : 'access was denied after the security-state transition';
  }
  return {
    ...result,
    verdict: violated ? 'candidate' : 'refuted',
    reason,
    stable: true,
    evidence: { baseline: left.samples[0], variant: right.samples[0], changes: diff.changes },
    proof_needed: violated ? [
      'replay the exact relation with the same identity and request',
      'verify the input change is the only security-relevant mutation',
      'confirm the behavior is reproducible in a fresh session',
    ] : [],
  };
}

function evaluate(cases = [], opts = {}) {
  const results = cases.map((test) => evaluateCase(test, opts));
  return {
    results,
    candidates: results.filter((r) => r.verdict === 'candidate'),
    contradictions: results.filter((r) => r.verdict === 'hold' || r.verdict === 'invalid'),
  };
}

module.exports = { RELATIONS, responseShape, stableSamples, evaluateCase, evaluate };
