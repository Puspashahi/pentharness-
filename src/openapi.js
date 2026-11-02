'use strict';

const crypto = require('crypto');
const sequence = require('./api-sequence');

function examples(schema) {
  if (!schema || typeof schema !== 'object') return undefined;
  if (schema.example !== undefined) return schema.example;
  if (schema.examples && typeof schema.examples === 'object') {
    const first = Object.values(schema.examples)[0];
    return first && typeof first === 'object' && 'value' in first ? first.value : first;
  }
  if (schema.default !== undefined) return schema.default;
  if (schema.type === 'object' || schema.properties) {
    const out = {};
    for (const [key, value] of Object.entries(schema.properties || {})) {
      const sample = examples(value);
      if (sample !== undefined) out[key] = sample;
    }
    return Object.keys(out).length ? out : undefined;
  }
  if (schema.type === 'array') {
    const item = examples(schema.items);
    return item === undefined ? undefined : [item];
  }
  return schema.enum && schema.enum.length ? schema.enum[0] : undefined;
}

function parameterTemplate(parameter) {
  const p = parameter || {};
  const schema = p.schema || p;
  const value = examples(schema);
  return {
    name: p.name,
    in: p.in || 'query',
    required: Boolean(p.required),
    value: value === undefined ? `<${p.name || 'value'}>` : value,
  };
}

function requestTemplate(operation, baseUrl) {
  const pathParams = (operation.parameters || []).map(parameterTemplate);
  const bodySchema = operation.requestBody && operation.requestBody.content
    ? Object.values(operation.requestBody.content)[0]
    : null;
  const body = bodySchema ? examples(bodySchema.schema || bodySchema) : undefined;
  let pathname = operation.path;
  for (const p of pathParams.filter((x) => x.in === 'path')) pathname = pathname.replace(`{${p.name}}`, encodeURIComponent(String(p.value)));
  const query = pathParams.filter((x) => x.in === 'query');
  const qs = query.length ? `?${query.map((p) => `${encodeURIComponent(p.name)}=${encodeURIComponent(String(p.value))}`).join('&')}` : '';
  return {
    method: operation.method,
    url: `${String(baseUrl || '').replace(/\/$/, '')}${pathname}${qs}`,
    headers: body === undefined ? {} : { 'Content-Type': Object.keys(operation.requestBody.content)[0] || 'application/json' },
    body,
    parameters: pathParams,
  };
}

function risk(operation) {
  if (!operation.stateChanging) return 'read-only';
  if (operation.method === 'DELETE') return 'destructive';
  return 'state-changing';
}

function plan(spec, opts = {}) {
  const parsed = sequence.parseSpec(spec);
  const baseUrl = opts.baseUrl || (parsed.servers && parsed.servers[0] && parsed.servers[0].url) || '';
  const raw = sequence.plan(parsed, opts);
  const operations = raw.operations.map((operation) => ({
    ...operation,
    risk: risk(operation),
    request: requestTemplate(operation, baseUrl),
  }));
  const byId = new Map(operations.map((operation) => [operation.id, operation]));
  const sequences = raw.sequences.map((item, index) => ({
    id: `sequence-${index + 1}`,
    ...item,
    safeToReplay: item.steps.every((step) => !step.stateChanging),
    approvalRequired: item.steps.some((step) => step.stateChanging),
    steps: item.steps.map((step) => byId.get(step.id) || step),
  }));
  return {
    format: parsed.openapi || parsed.swagger || 'unknown',
    title: parsed.info && parsed.info.title,
    baseUrl,
    safety: 'planning-only; no network requests; state-changing steps require explicit approval',
    operations,
    sequences,
  };
}

function provenance(value) {
  const canonical = JSON.stringify(value, Object.keys(value || {}).sort());
  return {
    algorithm: 'sha256',
    digest: crypto.createHash('sha256').update(canonical).digest('hex'),
  };
}

module.exports = { examples, parameterTemplate, requestTemplate, risk, plan, provenance };
