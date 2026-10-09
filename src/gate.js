'use strict';
/**
 * Proof gate — what separates a lead from a reportable finding.
 *
 * Shannon: "Only validated, exploitable vulnerabilities are recorded, with
 * reproducible PoCs... **No Exploit, No Report.**"
 *
 * Tenzai: the agent had to learn "what is considered by design behavior and
 * what is a real vulnerability" — on HackerOne, a meaningful slice of their
 * submissions came back not-applicable, and they treat that as a signal to
 * improve the agent rather than to argue with the triager.
 *
 * So this gate is deliberately conservative. It does not decide truth — a
 * model/human does — but it refuses to let anything reach a report without
 * (a) proof, (b) an impact statement, and (c) a by-design argument answered.
 */

/**
 * Reasons a lead is *refuted* — these are terminal and mirror real triager
 * objections. Anything merely *missing* is a `hold` (fixable with more work),
 * never a `drop`. Conflating the two is what makes automated triage discard
 * real bugs.
 */
const DISMISSALS = [
  { id: 'reflection-only',
    when: (f) => {
      if (!f.proof) return false;
      const p = String(f.proof);
      if (!/reflect/i.test(p)) return false;
      // "not executed", "no execution", "unconfirmed" all mean the payload did
      // NOT run. A bare /execut/i test would read those as confirmation.
      const negated = /not\s+execut|no\s+execut|unexecut|without\s+execut|not\s+confirm|no\s+confirm|unconfirm|not\s+prov/i.test(p);
      const confirmed = /execut|ran\s+in|alert\(|onerror|popup|dialog|confirm/i.test(p);
      return negated || !confirmed;
    },
    reason: 'Input is reflected but no execution demonstrated. Triagers reject this as unproven.' },
  { id: 'differential-noise', when: (f) => f.proof && /identical|byte-for-byte|no difference/i.test(f.proof),
    reason: 'Responses are identical to baseline. No behavioural difference to report.' },
  { id: 'by-design-asserted', when: (f) => /^by[- ]design\b|is by design$|intended behaviour[,.]?$/i.test(String(f.by_design || '').trim()),
    reason: 'Bare by-design assertion with no counter-argument. Argue it or drop it.' },
  { id: 'impact-refuted', when: (f) => f.impact && /^(none|no impact|n\/a|nothing)\b/i.test(String(f.impact).trim()),
    reason: 'Impact explicitly assessed as none. Not reportable.' },
];

/**
 * Evaluate a candidate finding.
 * @returns {{verdict:'report'|'hold'|'drop', reasons:string[], missing:string[]}}
 */
function evaluate(f = {}) {
  const reasons = [];   // refutations: terminal, lead is discarded
  const notes = [];     // advisories: lead needs work but stays in the queue
  const missing = [];   // absent requirements: lead stays on hold

  // 1. Proof. A claim without evidence of the actual effect cannot ship.
  if (!f.proof || String(f.proof).trim().length < 10) {
    missing.push('proof: needs a captured transcript/response demonstrating the effect');
  }

  // 2. Reproduction. Someone else must be able to re-run it.
  if (!f.reproduction) {
    missing.push('reproduction: needs exact steps or a .http transcript');
  }

  // 3. Impact. Tenzai had to build impact onto the business automatically.
  if (!f.impact || String(f.impact).trim().length < 10) {
    missing.push('impact: needs a concrete consequence, not "could lead to"');
  }
  // 4. By-design challenge. Answer the objection before the triager raises it.
  if (!f.by_design) {
    missing.push('by_design: state why this is not intended behaviour');
  }

  // 5. Deltas vs baseline are the difference between a bug and a hunch.
  //    This is an advisory, not a refutation: the lead still needs work, so it
  //    must stay in the queue rather than be discarded.
  if (f.proof && !/baseline|control|unmodified|vs |compare/i.test(f.proof) && /injection|authz|ssrf|xss/.test(f.cls || '')) {
    notes.push('Proof does not reference a baseline/control comparison for an exploitation class.');
  }

  // 6. Automated dismissals.
  for (const d of DISMISSALS) {
    let hit = false;
    try { hit = !!d.when(f); } catch { hit = false; }
    if (hit) reasons.push(`${d.id}: ${d.reason}`);
  }

  if (reasons.length) {
    return { verdict: 'drop', reasons, notes, missing };
  }
  if (missing.length) {
    return { verdict: 'hold', reasons, notes, missing };
  }
  return { verdict: 'report', reasons, notes, missing };
}

/**
 * Build the triage question an LLM/human must answer for a lead.
 * This is the bounded attention queue: one decision per lead, not a wall.
 */
function triagePrompt(lead) {
  const needed = Array.isArray(lead.proof_needed)
    ? lead.proof_needed
    : lead.proof_needed
      ? [String(lead.proof_needed)]
      : [];
  const proofNeeded = needed.map((p) => `  - ${p}`).join('\n');
  return [
    `LEAD ${lead.id} [${lead.cls}] (${lead.source})`,
    `title:    ${lead.title}`,
    `url:      ${lead.url || '-'}`,
    `param:    ${lead.param || '-'}`,
    `asset:    ${lead.asset}  identity: ${lead.identity || '-'}`,
    `evidence: ${lead.evidence || '(none captured)'}`,
    '',
    'Decide, with evidence:',
    '  1. Is the effect real (not just reflection/noise)?',
    '  2. What is the concrete business impact?',
    '  3. Is this by-design? What is the argument against that?',
    '  4. What is the minimal reproduction a stranger can run?',
    proofNeeded ? `\nproof required to close this lead:\n${proofNeeded}` : '',
  ].join('\n');
}

/** Turn a lead + model verdicts into the reportable findings.json shape. */
function toFinding(lead, answers = {}) {
  const merged = {
    cls: lead.cls,
    severity: answers.severity || lead.severity_hint || 'medium',
    title: answers.title || lead.title,
    url: lead.url,
    param: lead.param,
    proof: answers.proof || lead.evidence,
    impact: answers.impact,
    by_design: answers.by_design,
    reproduction: answers.reproduction,
  };
  const verdict = evaluate(merged);
  if (verdict.verdict !== 'report') return { ok: false, verdict, lead };
  return {
    ok: true,
    verdict,
    finding: {
      type: 'finding',
      id: lead.id,
      title: merged.title,
      severity: merged.severity,
      target: lead.url,
      category: lead.cls,
      description: merged.impact,
      evidence: merged.proof,
      tool_used: lead.source,
      cwe: answers.cwe,
      parameter: lead.param,
      reproduction: merged.reproduction,
      chain_of: lead.chain_of,
    },
  };
}

module.exports = { evaluate, triagePrompt, toFinding, DISMISSALS };
