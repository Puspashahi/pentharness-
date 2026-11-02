'use strict';

const crypto = require('crypto');

const SCHEMA_VERSION = 1;

function digest(value) {
  const canonical = JSON.stringify(value, Object.keys(value || {}).sort());
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

function normalize(report, source = 'unknown') {
  const input = report && typeof report === 'object' ? report : {};
  return {
    schemaVersion: SCHEMA_VERSION,
    tool: String(input.tool || source),
    safety: String(input.safety || 'evidence requires runtime proof'),
    provenance: input.provenance && input.provenance.digest
      ? input.provenance
      : { algorithm: 'sha256', digest: digest(input) },
    ...input,
  };
}

function validate(report) {
  const errors = [];
  if (!report || typeof report !== 'object' || Array.isArray(report)) return ['report must be an object'];
  if (report.schemaVersion !== SCHEMA_VERSION) errors.push('schemaVersion must be 1');
  if (typeof report.tool !== 'string' || !report.tool) errors.push('tool must be a non-empty string');
  if (typeof report.safety !== 'string' || !report.safety) errors.push('safety must be a non-empty string');
  if (report.provenance) {
    if (report.provenance.algorithm !== 'sha256') errors.push('provenance.algorithm must be sha256');
    if (!/^[a-f0-9]{64}$/.test(String(report.provenance.digest || ''))) errors.push('provenance.digest must be a SHA-256 hex digest');
  }
  for (const key of ['candidates', 'findings', 'observations', 'results']) {
    if (report[key] !== undefined && !Array.isArray(report[key])) errors.push(`${key} must be an array`);
  }
  return errors;
}

module.exports = { SCHEMA_VERSION, digest, normalize, validate };
