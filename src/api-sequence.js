'use strict';

/**
 * Stateful API sequence planning from OpenAPI-like documents and observations.
 * The planner creates safe read-first sequences; callers must opt in before
 * executing writes.
 */

function parseSpec(spec) {
  if (typeof spec === 'string') {
    try { return JSON.parse(spec); } catch { return {}; }
  }
  return spec && typeof spec === 'object' ? spec : {};
}

function operations(spec) {
  const s = parseSpec(spec);
  const out = [];
  for (const [path, item] of Object.entries(s.paths || {})) {
    for (const [method, op] of Object.entries(item || {})) {
      if (!/^(get|post|put|patch|delete|head|options)$/i.test(method)) continue;
      out.push({
        id: op.operationId || `${method.toUpperCase()} ${path}`,
        method: method.toUpperCase(),
        path,
        tags: op.tags || [],
        parameters: op.parameters || [],
        requestBody: op.requestBody,
        responses: op.responses || {},
        stateChanging: !/^(get|head|options)$/i.test(method),
      });
    }
  }
  return out;
}

function resourceName(pathname) {
  return String(pathname).split('/').filter(Boolean)
    .filter((x) => !/^\{[^}]+\}$/.test(x))
    .pop() || 'resource';
}

function plan(spec, opts = {}) {
  const ops = operations(spec);
  const reads = ops.filter((o) => !o.stateChanging);
  const writes = ops.filter((o) => o.stateChanging);
  const sequences = [];
  for (const read of reads.slice(0, opts.maxReads || 20)) {
    sequences.push({ kind: 'read', steps: [read], reason: 'establish baseline resource behavior' });
  }
  for (const write of writes.slice(0, opts.maxWrites || 20)) {
    const resource = resourceName(write.path);
    const related = reads.find((r) => resourceName(r.path) === resource);
    sequences.push({
      kind: related ? 'lifecycle' : 'write-review',
      steps: related ? [related, write] : [write],
      reason: related ? `compare ${resource} read-after-write state` : 'review state-changing operation with explicit sandbox approval',
    });
  }
  return { operations: ops, sequences };
}

module.exports = { parseSpec, operations, resourceName, plan };
