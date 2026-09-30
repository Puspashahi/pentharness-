'use strict';
/**
 * Coverage gate.
 *
 * HackerOne, running a frontier model against their own codebase, hit this and
 * built an explicit mechanism for it:
 *
 *   "a run that examined only part of a codebase can produce findings that look
 *    just as complete as those from a run that covered all of it, so the
 *    harness now fails runs that didn't review enough of the surface before
 *    reporting."
 *
 * A partial scan that reads as complete is worse than no scan, because it
 * produces false confidence. This module makes coverage explicit and refuses to
 * sign off a report that did not measure it.
 */

/** Minimum surface that must be touched before a report can claim completeness. */
const DEFAULT_THRESHOLDS = {
  minPages: 5,             // distinct pages exercised
  minEndpoints: 3,         // known endpoints in the KB
  minLenses: 2,            // authorization lenses applied
  minIdentities: 2,        // identities compared (an authz claim needs a 2nd identity)
  requireScanPhase: true,  // recon alone is never a complete assessment
};

class CoverageLedger {
  constructor(thresholds = {}) {
    this.t = { ...DEFAULT_THRESHOLDS, ...thresholds };
    this.covered = { pages: new Set(), endpoints: new Set(), lenses: new Set(), identities: new Set(), params: new Set() };
    this.phases = new Set();
    this.aborted = null;
  }

  phase(p) { this.phases.add(p); }
  page(url) { if (url) this.covered.pages.add(url); }
  endpoint(url) { if (url) this.covered.endpoints.add(url); }
  param(p) { if (p) this.covered.params.add(p); }
  lens(l) { if (l) this.covered.lenses.add(l); }
  identity(i) { this.covered.identities.add(i || 'anon'); }
  abort(reason) { this.aborted = reason; }

  get counts() {
    return {
      pages: this.covered.pages.size,
      endpoints: this.covered.endpoints.size,
      params: this.covered.params.size,
      lenses: this.covered.lenses.size,
      identities: this.covered.identities.size,
    };
  }

  /**
   * @returns {{complete:boolean, gaps:string[], counts:object, aborted:string|null}}
   */
  assess() {
    const c = this.counts;
    const gaps = [];
    if (c.pages < this.t.minPages) gaps.push(`pages: ${c.pages}/${this.t.minPages}`);
    if (c.endpoints < this.t.minEndpoints) gaps.push(`endpoints: ${c.endpoints}/${this.t.minEndpoints}`);
    if (this.t.requireScanPhase && !this.phases.has('scan')) gaps.push('no scan phase ran (recon only)');
    if (c.lenses > 0 && c.lenses < this.t.minLenses) gaps.push(`authz lenses: ${c.lenses}/${this.t.minLenses}`);
    // A single-identity authz claim is a guess, not a finding.
    if (c.identities < this.t.minIdentities) gaps.push(`identities compared: ${c.identities}/${this.t.minIdentities} — single-identity runs cannot prove authorization flaws`);
    return { complete: gaps.length === 0 && !this.aborted, gaps, counts: c, aborted: this.aborted };
  }

  /** Human-readable verdict for the report header. */
  statement() {
    const a = this.assess();
    const c = a.counts;
    const head = `Coverage: ${c.pages} page(s), ${c.endpoints} endpoint(s), ${c.params} param(s), ${c.lenses} lens(es), ${c.identities} identit(y/ies).`;
    if (a.aborted) return `${head} INCOMPLETE — scan aborted: ${a.aborted}`;
    if (a.complete) return `${head} Complete for the measured surface.`;
    return `${head} INCOMPLETE — missing: ${a.gaps.join('; ')}. Treat results as partial, not as an absence of findings.`;
  }

  toJSON() {
    return { thresholds: this.t, counts: this.counts, phases: [...this.phases], aborted: this.aborted };
  }
}

module.exports = { CoverageLedger, DEFAULT_THRESHOLDS };
