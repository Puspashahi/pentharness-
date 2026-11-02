'use strict';

/**
 * High-signal secret discovery for local source, bundles, and tool output.
 *
 * Matches are leads only. Values are never returned or written to evidence.
 * A reportable secret still needs live validation or proof of unintended
 * exposure through the normal proof gate.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { makeLead } = require('./leads');

const PLACEHOLDER = /^(?:changeme|change_me|your[_ -]?(?:api[_ -]?key|token|secret)|example|sample|test|dummy|null|undefined|replace[_ -]?me|redacted|<[^>]+>|\$\{[^}]+\}|process\.env\.)$/i;
const SECRET_PATTERNS = [
  ['aws-access-key', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/gi, 0.98],
  ['aws-secret-key', /(?:aws_secret_access_key|secret_access_key)\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']/gi, 0.96],
  ['google-api-key', /\bAIza[0-9A-Za-z_-]{35}\b/g, 0.98],
  ['github-token', /\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}\b/g, 0.98],
  ['slack-token', /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, 0.97],
  ['stripe-key', /\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{10,}\b/g, 0.97],
  ['sendgrid-key', /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g, 0.97],
  ['twilio-key', /\bSK[0-9a-f]{32}\b/gi, 0.93],
  ['npm-token', /\bnpm_[A-Za-z0-9]{30,}\b/g, 0.97],
  ['discord-token', /\b[A-Za-z\d_-]{20,28}\.[\w-]{5,8}\.[\w-]{20,40}\b/g, 0.82],
  ['private-key', /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/g, 0.99],
  ['jwt', /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, 0.9],
  ['bearer-token', /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}/gi, 0.88],
  ['generic-secret-assignment', /\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|secret[_-]?key|token|password|passwd|authorization)\b\s*[:=]\s*["']([^"'\r\n]{16,})["']/gi, 0.7],
];

function hash(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex').slice(0, 12);
}

function entropy(value) {
  const s = String(value);
  if (!s.length) return 0;
  const counts = new Map();
  for (const c of s) counts.set(c, (counts.get(c) || 0) + 1);
  return [...counts.values()].reduce((h, n) => h - (n / s.length) * Math.log2(n / s.length), 0);
}

function isPlaceholder(value) {
  const v = String(value).trim();
  return PLACEHOLDER.test(v) || /^x+$/i.test(v) || /^0+$/.test(v);
}

function lineAt(source, index) {
  return String(source).slice(0, index).split('\n').length;
}

function scanText(source, meta = {}) {
  const text = String(source || '');
  const findings = [];
  const seen = new Set();
  for (const [kind, rx, baseConfidence] of SECRET_PATTERNS) {
    rx.lastIndex = 0;
    let m;
    while ((m = rx.exec(text))) {
      const value = m[1] || m[0];
      if (isPlaceholder(value)) continue;
      const confidence = kind === 'generic-secret-assignment'
        ? (entropy(value) >= 3.2 ? baseConfidence : 0.45)
        : baseConfidence;
      if (confidence < 0.6) continue;
      const key = `${kind}:${hash(value)}:${lineAt(text, m.index)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        kind,
        confidence,
        line: lineAt(text, m.index),
        fingerprint: hash(value),
        source: meta.source || meta.path || 'input',
        path: meta.path,
        evidence: `${kind} pattern matched at line ${lineAt(text, m.index)}; value redacted`,
      });
    }
  }
  return findings;
}

function walkFiles(target, opts = {}) {
  const maxFiles = opts.maxFiles || 1000;
  const maxBytes = opts.maxBytes || 4 * 1024 * 1024;
  const skip = /(?:^|[/\\])(?:\.git|node_modules|vendor|dist|build|coverage)(?:[/\\]|$)/;
  const out = [];
  const visit = (p, depth) => {
    if (out.length >= maxFiles || depth > (opts.maxDepth ?? 6)) return;
    let st;
    try { st = fs.statSync(p); } catch { return; }
    if (st.isFile()) {
      if (st.size <= maxBytes && !skip.test(p)) out.push(p);
      return;
    }
    if (!st.isDirectory() || skip.test(p)) return;
    let entries;
    try { entries = fs.readdirSync(p, { withFileTypes: true }); } catch { return; }
    for (const e of entries) visit(path.join(p, e.name), depth + 1);
  };
  visit(path.resolve(target), 0);
  return out;
}

function scanPath(target, opts = {}) {
  const findings = [];
  const files = walkFiles(target, opts);
  for (const file of files) {
    let source;
    try { source = fs.readFileSync(file, 'utf8'); } catch { continue; }
    findings.push(...scanText(source, { path: file, source: path.relative(process.cwd(), file) }));
  }
  return { files: files.length, findings, leads: findings.map((f) => makeLead({
    cls: 'secrets',
    title: `Secret candidate: ${f.kind}`,
    url: f.path || '',
    source: 'secret-scan',
    severity_hint: f.confidence >= 0.9 ? 'high' : 'medium',
    confidence: 'unverified',
    evidence: f.evidence,
    tags: ['secret', f.kind],
    proof_needed: ['confirm the value is not a placeholder', 'validate safely with the provider or authorized target', 'rotate/revoke if confirmed exposed'],
  })) };
}

module.exports = { SECRET_PATTERNS, scanText, scanPath, walkFiles, entropy, isPlaceholder, hash };
