'use strict';

/**
 * Semantic response differentialing.
 *
 * Status/length changes alone are noisy. This module compares normalized
 * response shapes, security-relevant fields, and ownership markers while
 * retaining enough detail for a human or validator to reproduce the claim.
 */
const crypto = require('crypto');

const digest = (v) => crypto.createHash('sha256').update(String(v || '')).digest('hex').slice(0, 16);
const SECRET_KEY = /password|passwd|token|secret|authorization|cookie|api[_-]?key|session/i;
const OWNER_KEY = /owner|user|account|tenant|org|email|created_by|author/i;

function parseBody(body) {
  if (body && typeof body === 'object') return body;
  try { return JSON.parse(String(body || '')); } catch { return null; }
}

function flatten(value, prefix = '', out = {}) {
  if (value === null || typeof value !== 'object') {
    out[prefix] = value;
    return out;
  }
  if (Array.isArray(value)) {
    out[`${prefix}[]`] = value.length;
    value.slice(0, 50).forEach((v, i) => flatten(v, `${prefix}[${i}]`, out));
    return out;
  }
  for (const [k, v] of Object.entries(value).slice(0, 200)) {
    const key = prefix ? `${prefix}.${k}` : k;
    flatten(v, key, out);
  }
  return out;
}

function semanticShape(response = {}) {
  const body = parseBody(response.body);
  const fields = body ? flatten(body) : {};
  const securityFields = Object.fromEntries(Object.entries(fields)
    .filter(([k]) => SECRET_KEY.test(k) || OWNER_KEY.test(k))
    .map(([k, v]) => [k, SECRET_KEY.test(k) ? '<redacted>' : v]));
  return {
    statusClass: Math.floor(Number(response.status || 0) / 100),
    contentType: String(response.contentType || '').split(';')[0].toLowerCase(),
    fieldCount: Object.keys(fields).length,
    securityFields,
    bodyDigest: digest(typeof response.body === 'string' ? response.body : JSON.stringify(response.body)),
  };
}

function compare(a, b) {
  const left = semanticShape(a);
  const right = semanticShape(b);
  const changes = [];
  if (left.statusClass !== right.statusClass) changes.push({ kind: 'status-class', from: left.statusClass, to: right.statusClass });
  if (left.contentType !== right.contentType) changes.push({ kind: 'content-type', from: left.contentType, to: right.contentType });
  if (left.fieldCount !== right.fieldCount) changes.push({ kind: 'field-count', from: left.fieldCount, to: right.fieldCount });
  const keys = new Set([...Object.keys(left.securityFields), ...Object.keys(right.securityFields)]);
  for (const key of keys) {
    if (JSON.stringify(left.securityFields[key]) !== JSON.stringify(right.securityFields[key])) {
      changes.push({ kind: OWNER_KEY.test(key) ? 'ownership-field' : 'security-field', key });
    }
  }
  return { differs: changes.length > 0, changes, left, right };
}

function matrix(rows = []) {
  const out = [];
  for (let i = 0; i < rows.length; i++) {
    for (let j = i + 1; j < rows.length; j++) {
      const d = compare(rows[i].response, rows[j].response);
      out.push({ left: rows[i].label, right: rows[j].label, ...d });
    }
  }
  return out;
}

module.exports = { parseBody, flatten, semanticShape, compare, matrix, digest };
