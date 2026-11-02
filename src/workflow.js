'use strict';

/**
 * Stateful workflow reasoning.
 *
 * This module never decides that a workflow is vulnerable. It models observed
 * transitions, generates bounded mutations, and reports invariant violations
 * that a proof step must reproduce.
 */
const crypto = require('crypto');

const sha = (v) => crypto.createHash('sha256').update(String(v)).digest('hex').slice(0, 16);

function normalizeStep(step, index = 0) {
  const s = step || {};
  return {
    id: String(s.id || s.name || `step-${index + 1}`),
    method: String(s.method || 'GET').toUpperCase(),
    url: String(s.url || ''),
    body: s.body,
    headers: s.headers || {},
    stateBefore: s.stateBefore,
    stateAfter: s.stateAfter,
    effect: s.effect || 'read',
    reversible: s.reversible !== false,
  };
}

function normalizeWorkflow(input = {}) {
  const steps = Array.isArray(input) ? input : input.steps;
  return {
    id: input.id || sha((steps || []).map((s) => `${s.method} ${s.url}`).join('\n')),
    name: input.name || 'observed workflow',
    steps: (steps || []).map(normalizeStep),
    states: input.states || {},
    invariants: Array.isArray(input.invariants) ? input.invariants : [],
  };
}

function discoverTransitions(observations = []) {
  const transitions = [];
  let previous;
  for (const raw of observations) {
    const step = normalizeStep(raw, transitions.length);
    if (previous && step.stateBefore == null) step.stateBefore = previous.stateAfter;
    transitions.push(step);
    previous = step;
  }
  return transitions;
}

function mutate(workflow, opts = {}) {
  const w = normalizeWorkflow(workflow);
  const max = Math.max(1, Math.min(opts.maxMutations || 32, 200));
  const out = [];
  const add = (kind, steps, reason) => {
    if (out.length >= max) return;
    const ids = steps.map((s) => s.id).join(',');
    const key = `${kind}:${ids}`;
    if (out.some((x) => x.key === key)) return;
    out.push({ key, kind, reason, steps });
  };

  for (let i = 0; i < w.steps.length && out.length < max; i++) {
    const s = w.steps[i];
    if (i > 0) add('skip', w.steps.filter((_, n) => n !== i), `skip ${s.id} to test server-side sequence enforcement`);
    add('duplicate', w.steps.flatMap((x, n) => n === i ? [x, x] : [x]), `repeat ${s.id} to test idempotency and replay handling`);
    if (i + 1 < w.steps.length) {
      const swapped = w.steps.slice();
      [swapped[i], swapped[i + 1]] = [swapped[i + 1], swapped[i]];
      add('reorder', swapped, `swap ${s.id} with ${w.steps[i + 1].id} to test transition ordering`);
    }
  }
  return out;
}

function validateTransition(step, response, state = {}) {
  const status = Number(response && response.status || 0);
  const expected = state[step.stateAfter] || {};
  const violations = [];
  if (expected.statuses && !expected.statuses.includes(status)) {
    violations.push(`status ${status} is outside expected ${expected.statuses.join(',')}`);
  }
  if (step.effect !== 'read' && status >= 200 && status < 300 && step.reversible === false) {
    violations.push('non-reversible state-changing step requires explicit proof review');
  }
  return { ok: violations.length === 0, violations };
}

function analyzeSequence(workflow, responses = []) {
  const w = normalizeWorkflow(workflow);
  const hypotheses = [];
  const state = w.states || {};
  for (let i = 0; i < w.steps.length; i++) {
    const result = validateTransition(w.steps[i], responses[i] || {}, state);
    for (const violation of result.violations) {
      hypotheses.push({
        kind: 'state-transition',
        step: w.steps[i].id,
        title: `Workflow invariant violation at ${w.steps[i].id}`,
        evidence: violation,
        proof_needed: ['repeat the sequence in a sandbox account', 'capture before/after state', 'confirm the transition is not intended'],
      });
    }
  }
  return { workflow: w, hypotheses, mutations: mutate(w) };
}

module.exports = { normalizeStep, normalizeWorkflow, discoverTransitions, mutate, validateTransition, analyzeSequence };
