'use strict';
/**
 * Suppression ledger — separating "filtered noise" from "suppressed real issue".
 *
 * HackerOne learned this the hard way running a frontier model on their own
 * code: they now "separately track findings the model flagged and then talked
 * itself out of. That lets us distinguish a validation layer that's filtering
 * noise from one that's suppressing real issues."
 *
 * That is the whole point. A gate that silently discards leads is indistinguishable
 * from a broken gate. Every dismissal is recorded with its reason, and the
 * ledger is emitted alongside the report so a human can audit what was thrown
 * away and why.
 */

const SUPPRESS_REASONS = {
  'reflection-only': 'Payload reflected, no execution demonstrated.',
  'differential-noise': 'Response identical to baseline.',
  'by-design-asserted': 'Bare by-design assertion with no counter-argument.',
  'impact-refuted': 'Impact assessed as none.',
  'coverage-incomplete': 'Scan did not cover enough surface to claim absence.',
  'third-party': 'Belongs to third-party infrastructure, not the assessed target.',
  'known-design': 'Framework behaviour that is correct by construction.',
  'duplicate': 'Already present in the findings set.',
};

class SuppressionLedger {
  constructor() {
    this.entries = [];
  }

  /**
   * @param {object} lead the lead being suppressed
   * @param {string} reason key from SUPPRESS_REASONS
   * @param {object} detail extra context for audit
   */
  suppress(lead, reason, detail = {}) {
    this.entries.push({
      id: lead && lead.id,
      title: lead && (lead.title || lead.lead),
      cls: lead && (lead.cls || lead.lead_cls),
      url: lead && lead.url,
      source: lead && lead.source,
      reason,
      explanation: SUPPRESS_REASONS[reason] || reason,
      severity_hint: lead && (lead.severity_hint || lead.severity),
      evidence: (lead && lead.evidence ? String(lead.evidence) : '').slice(0, 400),
      detail,
      tsv: new Date().toISOString(),
    });
    return this;
  }

  byReason() {
    const m = {};
    for (const e of this.entries) m[e.reason] = (m[e.reason] || 0) + 1;
    return m;
  }

  /**
   * Leads suppressed *despite* carrying a tool-asserted high/critical severity.
   * These deserve a second look — they may be real and the gate too strict.
   */
  worthReviewing() {
    return this.entries.filter((e) => ['high', 'critical'].includes(String(e.severity_hint || '').toLowerCase()));
  }

  statement() {
    if (!this.entries.length) return 'Nothing was suppressed this run.';
    const by = this.byReason();
    const parts = Object.entries(by).map(([k, v]) => `${v} ${k}`).join(', ');
    const review = this.worthReviewing();
    const tail = review.length
      ? ` ${review.length} suppressed lead(s) asserted high/critical by a tool and warrant a human look.`
      : '';
    return `Suppressed ${this.entries.length} lead(s): ${parts}.${tail}`;
  }

  toJSON() { return this.entries; }
}

module.exports = { SuppressionLedger, SUPPRESS_REASONS };
