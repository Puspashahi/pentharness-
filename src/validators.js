'use strict';
/**
 * Deterministic validators + progressive oracle + adversarial refutation.
 *
 * This is the layer every serious autonomous system converges on, and it is
 * deliberately NOT written by an AI:
 *
 *   Google PageBreak: "we made a conscious decision to prioritize deterministic
 *   validation... The core of this deterministic approach lies in its suite of
 *   specialized, non-AI-written validators. When the agent identifies a
 *   potential flaw, it passes the hypothesis to a validator which then executes
 *   a real payload to confirm the exploit." Result: 500+ XSS across first-party
 *   Google apps, near-zero false positives, and "we do not send these unverified
 *   candidates to product teams".
 *
 *   Wiz Atlas: "Each candidate is contested rather than accepted... A finding
 *   survives only if it withstands an adversary actively attempting to refute
 *   it... This adversarial stage is the biggest lever we have on keeping the
 *   false-positive rate down."
 *
 *   CVE2PoC: progressive multi-layer verification that "escalates to more
 *   expensive semantic reasoning only when necessary" — and 16x fewer tokens
 *   than a single-shot baseline.
 *
 * The AI's job is to hypothesise. This file's job is to refuse to believe it
 * until something observable happened.
 */

const crypto = require('crypto');

const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex').slice(0, 16);
const rand = (n = 8) => crypto.randomBytes(n).toString('hex');

/** Per-run nonce so a proof can never be confused with a cached/planted result. */
const NONCE = rand(6);

/* ------------------------------------------------------------------ *
 * LAYER 1 — MECHANICAL
 * Cheap, deterministic, no semantics. Exit codes, status deltas, timing.
 * ------------------------------------------------------------------ */

const L1 = {
  statusDelta(a, b) {
    if (!a || !b) return { pass: false, why: 'missing response' };
    if (a.status !== b.status) return { pass: true, strength: 0.6, why: `status ${b.status} vs baseline ${a.status}` };
    return { pass: false, why: `status identical (${a.status})` };
  },

  timingDelta(baseline, injected, thresholdMs = 1500) {
    if (!baseline || !injected) return { pass: false, why: 'missing timing sample' };
    const delta = injected - baseline;
    if (delta >= thresholdMs) {
      // A multi-second delay is the signature of a server-side wait, not
      // network jitter. Calibrated so the canonical 3s SLEEP/WAITFOR/pg_sleep
      // probe lands firmly in "strong" territory rather than a hair under the
      // bar — that miscalibration silently downgraded every blind SQLi.
      const strength = delta >= 2500 ? 0.95 : Math.min(0.9, 0.6 + delta / 10000);
      return { pass: true, strength, why: `injected ${injected}ms vs baseline ${baseline}ms (delta ${delta}ms)` };
    }
    return { pass: false, why: `delta ${delta}ms below ${thresholdMs}ms threshold` };
  },

  bodyLengthDelta(baseline, injected, ratio = 0.02) {
    if (baseline == null || injected == null) return { pass: false, why: 'missing body' };
    const d = Math.abs(injected - baseline);
    if (baseline === 0) return { pass: d > 0, strength: 0.5, why: `0 -> ${injected} bytes` };
    const r = d / baseline;
    if (r >= ratio) return { pass: true, strength: Math.min(1, r), why: `length ${baseline} -> ${injected} (${(r * 100).toFixed(1)}% change)` };
    return { pass: false, why: `length change ${(r * 100).toFixed(1)}% below ${(ratio * 100).toFixed(0)}% threshold` };
  },

  /** A response is only evidence if it is distinguishable from the baseline. */
  notIdentical(baselineBody, injectedBody) {
    if (baselineBody == null || injectedBody == null) return { pass: false, why: 'missing body' };
    if (baselineBody === injectedBody) return { pass: false, why: 'response byte-identical to baseline' };
    return { pass: true, strength: 0.5, why: 'response differs from baseline' };
  },

  /** Require repeated measurements to agree before treating a differential as
   * evidence. One slow request or one dynamic response is noise. */
  stableSamples(values, tolerance = 0) {
    if (!Array.isArray(values) || values.length < 2) {
      return { pass: false, why: 'needs at least two samples' };
    }
    const nums = values.map(Number).filter(Number.isFinite);
    if (nums.length !== values.length) return { pass: false, why: 'samples are not numeric' };
    const min = Math.min(...nums);
    const max = Math.max(...nums);
    if (max - min > tolerance) {
      return { pass: false, why: `sample spread ${max - min} exceeds tolerance ${tolerance}` };
    }
    return { pass: true, why: `${nums.length} samples agree within ${tolerance}` };
  },

  /** Compare repeated response lengths, not one arbitrary pair. */
  stableDifferential(baseline, injected, minDelta = 0) {
    const b = this.stableSamples(baseline, 0);
    const i = this.stableSamples(injected, 0);
    if (!b.pass || !i.pass) return { pass: false, why: b.pass ? i.why : b.why };
    const baselineValue = Number(baseline[0]);
    const injectedValue = Number(injected[0]);
    const delta = Math.abs(injectedValue - baselineValue);
    if (delta <= minDelta) return { pass: false, why: `stable delta ${delta} does not exceed ${minDelta}` };
    return { pass: true, why: `stable response lengths ${baselineValue} vs ${injectedValue}` };
  },
};

/* ------------------------------------------------------------------ *
 * LAYER 2 — MARKER / SIGNATURE
 * Look for a success marker the target cannot produce by accident.
 * ------------------------------------------------------------------ */

const L2 = {
  /** A nonce we planted coming back proves the value reached a code path. */
  canaryRoundTrip(body, canary = NONCE) {
    if (!body) return { pass: false, why: 'no body' };
    if (String(body).includes(canary)) return { pass: true, strength: 0.9, why: `planted canary ${canary} present in response` };
    return { pass: false, why: 'canary absent' };
  },

  /** Real database error text. Deliberately narrow: these strings are not
   *  produced by a server merely echoing input — but broad enough to catch the
   *  dialect variants real drivers emit (SQLite/JDBC, PDO, python-sqlite, …).
   *  A miss here is a false negative on a genuine, provable SQLi. */
  dbError(body) {
    const sigs = [
      /SQLSTATE\[(\w+)\]/i,
      /mysql_fetch_(array|assoc|row)/i,
      /ORA-\d{5}/i,
      /pg_(query|exec)\(\)/i,
      /SQLite3?::(query|exec)/i,
      /Unclosed quotation mark after the character string/i,
      /You have an error in your SQL syntax/i,
      /syntax error at or near/i,
      /SQL syntax error/i,                                   // sqlite / JDBC wording
      /near\s+"[^"]*":\s*SQL\b/i,                             // near "x": SQL syntax error
      /(?:SQLite|JDBC|MySQL|PostgreSQL)\/?\w*\s*(?:Driver|Exception|Error)/i,
      /OperationalError|ProgrammingError|DatabaseError|IntegrityError/i,  // python drivers
      /Uncaught\s+(?:PDO|SQLException|QueryFailedException)/i,            // php
      /java\.sql\.SQLSyntaxErrorException/i,
      /\bORA-\d{5}\b/,
      /pg_error\(/i,
    ];
    for (const s of sigs) {
      const m = String(body || '').match(s);
      if (m) return { pass: true, strength: 0.95, why: `database error signature: "${m[0]}"` };
    }
    return { pass: false, why: 'no database error signature' };
  },

  /** Out-of-band callback: the only conclusive SSRF/blind-injection proof. */
  oobCallback(observed, expectedToken) {
    if (observed && observed.includes && observed.includes(expectedToken)) {
      return { pass: true, strength: 1.0, why: `out-of-band callback received for token ${expectedToken}` };
    }
    return { pass: false, why: 'no out-of-band callback received' };
  },

  /** File content that only exists outside the webroot. */
  canaryFileRead(body, sentinel) {
    if (!body) return { pass: false, why: 'no body' };
    if (String(body).includes(sentinel)) return { pass: true, strength: 1.0, why: `out-of-root file content present (sentinel ${sentinel})` };
    return { pass: false, why: 'sentinel not found in response' };
  },

  /** Script actually executed in the target origin (browser-confirmed). */
  scriptExecuted(observed) {
    if (observed && observed.executed) {
      return { pass: true, strength: 1.0, why: `payload executed in origin (${observed.origin || 'unknown'})` };
    }
    return { pass: false, why: 'no execution observed in target origin' };
  },
};

/* ------------------------------------------------------------------ *
 * LAYER 3 — ADJUDICATION
 * Only for genuinely ambiguous cases. Never the default path.
 * ------------------------------------------------------------------ */

/**
 * Structural checks a semantic adjudicator (human or model) should weigh.
 * Returns the questions, not the answer — the point is to force the ambiguity
 * to be resolved explicitly rather than silently rounded up to "vulnerable".
 */
const L3 = {
  questions(evidence) {
    const qs = [
      'Is the observed behaviour reachable from an unauthenticated or low-privilege entry point?',
      'Does the response contain data the requester was not entitled to see, or code that ran in their origin?',
      'Is the identical behaviour reproducible against a known-good baseline, measured in the same run?',
      'Is this documented or intended behaviour rather than a defect?',
    ];
    if (evidence && evidence.cls === 'injection') {
      qs.push('Does the injected value reach a query/template/command, or is it stored and re-used later (second order)?');
    }
    if (evidence && evidence.cls === 'authz') {
      qs.push('Is the object genuinely private, or is it intentionally shared with all authenticated users?');
    }
    return qs;
  },
};

/* ------------------------------------------------------------------ *
 * PER-CLASS VALIDATORS
 * Each returns { verdict, confidence, evidence, why } using the layers above.
 * No validator may return `proven` on evidence it did not observe.
 * ------------------------------------------------------------------ */

const VALIDATORS = {
  /**
   * SQL injection — differential, not pattern matching.
   * Requires an observed baseline captured in the same run.
   */
  injection(ev = {}) {
    const { baseline, booleanTrue, booleanFalse, errorBody, timing } = ev;
    const runs = [];

    if (timing && Array.isArray(timing.baselines) && Array.isArray(timing.injectedSamples)) {
      const stable = L1.stableSamples(timing.baselines, timing.jitterMs || 250);
      const stableInjected = L1.stableSamples(timing.injectedSamples, timing.jitterMs || 250);
      if (stable.pass && stableInjected.pass) {
        const r = L1.timingDelta(timing.baselines[0], timing.injectedSamples[0], ev.thresholdMs || 1500);
        runs.push({ layer: 1, kind: 'timing', ...r, stability: `${stable.why}; ${stableInjected.why}` });
      } else {
        runs.push({ layer: 1, kind: 'timing', pass: false, strength: 0, why: `unstable timing: ${stable.pass ? stableInjected.why : stable.why}` });
      }
    } else if (timing && timing.baseline != null && timing.injected != null) {
      runs.push({ layer: 1, kind: 'timing', pass: false, strength: 0, why: 'single timing pair is insufficient; capture repeated baseline and injected samples' });
    }
    if (errorBody != null) {
      const r = L2.dbError(errorBody);
      runs.push({ layer: 2, kind: 'db-error', ...r });
      // A reflected payload is not an error. Confirm the signature is not just
      // our own input echoed back (the false positive that started all this).
      if (r.pass && baseline != null) {
        const echoed = L1.notIdentical(baseline.body, errorBody);
        if (!echoed.pass) {
          r.pass = false;
          r.why = 'error signature only present in a response otherwise identical to baseline';
        }
      }
    }
    if (booleanTrue != null && booleanFalse != null) {
      const trueSamples = Array.isArray(booleanTrue.samples) ? booleanTrue.samples : [];
      const falseSamples = Array.isArray(booleanFalse.samples) ? booleanFalse.samples : [];
      const stable = L1.stableDifferential(trueSamples, falseSamples, ev.minLengthDelta || 32);
      const statusDiffers = booleanTrue.status != null && booleanFalse.status != null &&
        booleanTrue.status !== booleanFalse.status;
      const differs = stable.pass || (statusDiffers && booleanTrue.status >= 500);
      runs.push({
        layer: 1, kind: 'boolean', pass: differs, strength: differs ? 0.85 : 0,
        why: differs
          ? (stable.pass ? stable.why : `true status=${booleanTrue.status} vs false status=${booleanFalse.status}`)
          : 'single/dynamic response difference is insufficient; capture stable repeated samples',
      });
    }

    const passed = runs.filter((r) => r.pass);
    if (!passed.length) {
      return { verdict: 'refuted', confidence: 0.9, why: 'no differential observed against baseline', evidence: runs };
    }
    // Two independent signals, or one high-strength signal, or it stays a hypothesis.
    const strong = passed.some((r) => r.strength >= 0.9);
    const confidence = strong ? 0.95 : passed.length >= 2 ? 0.85 : 0.55;
    return {
      verdict: strong || passed.length >= 2 ? 'proven' : 'hypothesis',
      confidence,
      why: passed.map((r) => r.why).join('; '),
      evidence: runs,
    };
  },

  /**
   * XSS — reflection is not execution. Requires browser observation, or an
   * explicit admission that we only saw reflection.
   */
  xss(ev = {}) {
    const runs = [];
    if (ev.execution) {
      const r = L2.scriptExecuted(ev.execution);
      runs.push({ layer: 2, kind: 'execution', ...r });
    }
    if (ev.reflected != null) {
      const r = L1.notIdentical(ev.baseline, ev.reflected);
      runs.push({ layer: 1, kind: 'reflection', ...r, why: r.pass ? 'payload reflected in response' : r.why });
    }
    const executed = runs.some((r) => r.kind === 'execution' && r.pass);
    if (executed) return { verdict: 'proven', confidence: 0.98, why: 'script executed in the target origin', evidence: runs };
    const reflected = runs.some((r) => r.kind === 'reflection' && r.pass);
    if (reflected) {
      return { verdict: 'refuted', confidence: 0.8, why: 'payload reflected but no execution observed; triagers reject this', evidence: runs };
    }
    return { verdict: 'refuted', confidence: 0.5, why: 'no reflection, no execution', evidence: runs };
  },

  /** Path traversal — needs content that only exists off-webroot, or OOB. */
  traversal(ev = {}) {
    const runs = [];
    if (ev.oob) {
      const r = L2.oobCallback(ev.oob, ev.token || NONCE);
      runs.push({ layer: 2, kind: 'oob', ...r });
    }
    if (ev.body != null) {
      const r = L2.canaryFileRead(ev.body, ev.sentinel || NONCE);
      runs.push({ layer: 2, kind: 'file-content', ...r });
    }
    const passed = runs.filter((r) => r.pass);
    if (!passed.length) {
      return { verdict: 'refuted', confidence: 0.85, why: 'no off-webroot content or callback observed', evidence: runs };
    }
    return { verdict: 'proven', confidence: 0.95, why: passed[0].why, evidence: runs };
  },

  /** SSRF — the only conclusive proof is the target making the request. */
  ssrf(ev = {}) {
    const runs = [];
    if (ev.oob) {
      const r = L2.oobCallback(ev.oob, ev.token || NONCE);
      runs.push({ layer: 2, kind: 'oob', ...r });
    }
    if (ev.internalStatus != null) {
      const r = L1.statusDelta({ status: 200 }, { status: ev.internalStatus });
      runs.push({ layer: 1, kind: 'internal-response', ...r, why: r.pass ? `internal endpoint answered: status ${ev.internalStatus}` : r.why });
    }
    if (ev.internalBody) {
      const r = L2.canaryRoundTrip(ev.internalBody, ev.token || NONCE);
      runs.push({ layer: 2, kind: 'internal-content', ...r });
    }
    const passed = runs.filter((r) => r.pass);
    if (!passed.length) {
      return { verdict: 'refuted', confidence: 0.85, why: 'no callback and no internal response; URL may merely be reflected', evidence: runs };
    }
    return { verdict: 'proven', confidence: 0.95, why: passed.map((r) => r.why).join('; '), evidence: runs };
  },

  /** Authorization — cross-identity disclosure with ownership proof. */
  authz(ev = {}) {
    if (ev.disclosure && ev.disclosure.proven) {
      return { verdict: 'proven', confidence: 0.95, why: ev.disclosure.reason, evidence: [{ layer: 2, kind: 'ownership', pass: true, why: ev.disclosure.reason }] };
    }
    if (ev.disclosure && !ev.disclosure.proven) {
      return { verdict: 'refuted', confidence: 0.8, why: ev.disclosure.reason, evidence: [] };
    }
    return { verdict: 'hypothesis', confidence: 0.3, why: 'no second identity compared', evidence: [] };
  },

  /** Configuration — observable directly, but only on the live response. */
  config(ev = {}) {
    if (ev.absent && ev.absent.length) {
      return { verdict: 'proven', confidence: 0.9, why: `absent on live response: ${ev.absent.join(', ')}`, evidence: [] };
    }
    return { verdict: 'refuted', confidence: 0.9, why: 'headers/flags observed present', evidence: [] };
  },
};

/* ------------------------------------------------------------------ *
 * ADVERSARIAL REFUTATION
 * Atlas: "A finding survives only if it withstands an adversary actively
 * attempting to refute it." Each attack is a way the observation could be an
 * artefact rather than a vulnerability.
 * ------------------------------------------------------------------ */

const REFUTATIONS = {
  injection: [
    { id: 'payload-echo', describe: 'the "error" is our own payload reflected back', test: (ev) => ev.errorIsEcho === true },
    { id: 'no-differential', describe: 'injected and baseline responses are equivalent', test: (ev) => ev.injectedEqualsBaseline === true },
    { id: 'cached', describe: 'the difference came from a cache, not the query', test: (ev) => ev.cacheBypassUnchanged === true },
  ],
  xss: [
    { id: 'reflection-only', describe: 'reflected but never executed', test: (ev) => ev.executed === false && ev.reflected === true },
    { id: 'wrong-origin', describe: 'execution occurred in our own harness, not the target origin', test: (ev) => ev.execution && ev.execution.origin && ev.execution.origin !== ev.targetOrigin },
  ],
  authz: [
    { id: 'intentionally-shared', describe: 'the object is intended to be visible to all authenticated users', test: (ev) => ev.documentedShared === true },
    { id: 'own-record', describe: 'the identity read its own object', test: (ev) => ev.disclosure && ev.disclosure.proven === false },
    { id: 'public-endpoint', describe: 'the endpoint is public by design', test: (ev) => ev.publicByDesign === true },
  ],
  ssrf: [
    { id: 'url-reflected', describe: 'the URL is echoed but no request was made', test: (ev) => ev.serverMadeRequest === false },
  ],
  traversal: [
    { id: 'public-file', describe: 'the file is inside the webroot and publicly readable anyway', test: (ev) => ev.withinWebroot === true },
    { id: 'error-echo', describe: 'the traversal string is echoed, not resolved', test: (ev) => ev.resolved === false },
  ],
};

/**
 * Run every applicable refutation. A finding survives only if none land.
 * @returns {{survives:boolean, attacks_run:number, refuted_by:string[], why:string}}
 */
function refute(cls, ev = {}) {
  const attacks = REFUTATIONS[cls] || [];
  const refutedBy = [];
  for (const a of attacks) {
    let hit = false;
    try { hit = !!a.test(ev); } catch { hit = false; }
    if (hit) refutedBy.push(`${a.id}: ${a.describe}`);
  }
  return {
    survives: refutedBy.length === 0,
    attacks_run: attacks.length,
    refuted_by: refutedBy,
    why: refutedBy.length
      ? `refuted by ${refutedBy.length}/${attacks.length} attack(s): ${refutedBy.join('; ')}`
      : `survived ${attacks.length}/${attacks.length} refutation attempt(s)`,
  };
}

/* ------------------------------------------------------------------ *
 * PROVENANCE-AWARE VERDICT
 * Combines: class validator + adversary + provenance. Provenance is what
 * makes the difference between a reportable finding and a guess.
 * ------------------------------------------------------------------ */

function judge(cls, ev = {}) {
  const v = (VALIDATORS[cls] || (() => ({ verdict: 'hypothesis', confidence: 0.2, why: `no validator for ${cls}`, evidence: [] })))(ev);
  const r = refute(cls, ev);

  if (!r.survives) {
    return { verdict: 'refuted', confidence: Math.max(v.confidence, 0.8), why: r.why, validator: v, refutation: r, ship: false };
  }
  if (v.verdict === 'proven') {
    return { verdict: 'proven', confidence: v.confidence, why: `${v.why} — ${r.why}`, validator: v, refutation: r, ship: true, questions: L3.questions(ev) };
  }
  if (v.verdict === 'hypothesis') {
    return { verdict: 'hypothesis', confidence: v.confidence, why: `${v.why} — ${r.why}`, validator: v, refutation: r, ship: false, questions: L3.questions(ev) };
  }
  return { verdict: 'refuted', confidence: v.confidence, why: v.why, validator: v, refutation: r, ship: false };
}

/* ------------------------------------------------------------------ *
 * FAILURE TAXONOMY  (CVE2PoC)
 * Route the repair to the loop that can actually fix it: a syntax error and
 * a wrong attack strategy are different problems.
 * ------------------------------------------------------------------ */

const FAILURE_CLASSES = {
  syntax_error: { dimension: 'tactical', fix: 'regenerate payload, keep the strategy' },
  timeout: { dimension: 'tactical', fix: 'adjust the payload or the budget, keep the strategy' },
  blocked_or_filtered: { dimension: 'tactical', fix: 'mutate the payload encoding and retry' },
  no_differential: { dimension: 'strategic', fix: 'the strategy is wrong — re-plan the attack, do not retry this payload' },
  wrong_parameter: { dimension: 'strategic', fix: 'the parameter is not the sink — re-derive the injection point' },
  auth_required: { dimension: 'strategic', fix: 'obtain a session, then re-run' },
  endpoint_not_reachable: { dimension: 'strategic', fix: 'the path is wrong or gated — re-map the surface' },
  needs_two_identities: { dimension: 'strategic', fix: 'capture a second session, then re-run' },
};

function diagnose(symptom) {
  const s = String(symptom || '').toLowerCase();
  for (const [k, v] of Object.entries(FAILURE_CLASSES)) {
    if (s.includes(k.replace(/_/g, ' ')) || s.includes(k)) return { class: k, ...v };
  }
  if (/timed? ?out|timeout/.test(s)) return { class: 'timeout', ...FAILURE_CLASSES.timeout };
  if (/econn|not reachable|404|502/.test(s)) return { class: 'endpoint_not_reachable', ...FAILURE_CLASSES.endpoint_not_reachable };
  if (/waf|forbidden|blocked/.test(s)) return { class: 'blocked_or_filtered', ...FAILURE_CLASSES.blocked_or_filtered };
  return { class: 'no_differential', ...FAILURE_CLASSES.no_differential };
}

module.exports = { L1, L2, L3, VALIDATORS, REFUTATIONS, refute, judge, diagnose, FAILURE_CLASSES, NONCE, rand, sha };
