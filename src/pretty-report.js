'use strict';

/**
 * Human-readable output for local analysis. The wording is deliberately
 * conservative: pattern matches are never presented as confirmed findings.
 */

function level(finding = {}) {
  const confidence = Number(finding.confidence || 0);
  if (finding.proven === true || finding.validated === true) return 'CONFIRMED';
  if (confidence >= 0.9) return 'CANDIDATE';
  return 'REVIEW';
}

function reason(finding = {}) {
  return finding.evidence || finding.reason || 'pattern matched; exploitability not demonstrated';
}

function nextStep(finding = {}) {
  if (Array.isArray(finding.proof_needed) && finding.proof_needed.length) return finding.proof_needed[0];
  if (finding.kind && /secret/i.test(finding.kind)) return 'verify the value is live and authorized before reporting';
  return 'reproduce the behavior with a controlled baseline';
}

function renderLocal(report = {}) {
  const lines = [];
  lines.push('pentharness local analysis');
  lines.push(`Target: ${report.target || '-'}`);
  lines.push(`Safety: ${report.safety || 'local-only; no network requests'}`);
  lines.push('');
  lines.push('Verdict policy:');
  lines.push('  CONFIRMED = independently validated (not produced by static scanning alone)');
  lines.push('  CANDIDATE  = strong pattern, still needs authorized proof');
  lines.push('  REVIEW     = weak/static signal; do not report');
  lines.push('  SUPPRESSED = placeholder/noise filtered before output');
  lines.push('');

  const groups = [
    ['Secrets', report.secrets && report.secrets.findings],
    ['JavaScript leads', report.javascript && report.javascript.leads],
    ['gRPC leads', (report.grpc && report.grpc.results || []).flatMap((x) => x.findings || [])],
  ];
  let total = 0;
  for (const [name, findings] of groups) {
    const list = Array.isArray(findings) ? findings : [];
    lines.push(`${name}: ${list.length}`);
    for (const f of list.slice(0, 100)) {
      total++;
      lines.push(`  [${level(f)}] ${f.title || f.kind || 'signal'}`);
      lines.push(`    Why: ${reason(f)}`);
      lines.push(`    Next: ${nextStep(f)}`);
    }
    if (!list.length) lines.push('  none');
    lines.push('');
  }
  lines.push(`Total displayed signals: ${total}`);
  lines.push('Important: a pattern match is not a vulnerability. Only proof-gated findings belong in a report.');
  return lines.join('\n') + '\n';
}

module.exports = { level, reason, nextStep, renderLocal };
