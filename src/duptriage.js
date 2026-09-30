'use strict';
/**
 * Duplicate and prior-art triage.
 *
 * Programs reject duplicates, and duplicates are usually indistinguishable from
 * genuine findings without prior art. The researcher who knows that
 * "IDOR on sequential invoice IDs" was reported in 2021 submits it anyway;
 * the one who does not waste a slot. The reverse failure is worse: a genuinely
 * novel chained finding gets dismissed because a similar single-hop bug exists.
 *
 * So this is not a similarity score. It asks three separate questions, because
 * they have different answers:
 *
 *   1. Is this the same root cause at the same place?  -> duplicate
 *   2. Is the root cause known but our impact is different?  -> not a duplicate
 *   3. Does this chain steps together that were never chained before?  -> likely novel
 *
 * Programs reward (2) and (3). Treating them as duplicates is how researchers
 * leave money on the table.
 */


/** Normalise a finding into comparable shape. */
function fingerprint(f) {
  return {
    cls: String(f.cls || f.class || '').toLowerCase(),
    param: (f.param || '').toLowerCase(),
    endpoint: normalisePath(f.url || f.endpoint || ''),
    method: String(f.method || 'GET').toUpperCase(),
    identities: (f.identities || []).slice().sort(),
    steps: (f.steps || []).map((s) => String(s).toLowerCase()).sort(),
    impact: String(f.impact || '').toLowerCase(),
  };
}

/** Strip host, ids, and numbers so /invoices/1 and /invoices/2 compare equal. */
function normalisePath(u) {
  return String(u)
    .replace(/^https?:\/\/[^/]+/, '')
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, ':id')
    .replace(/\/\d+(?=\/|$)/g, '/:id')
    .replace(/\?.*$/, '')
    .replace(/\/+$/, '') || '/';
}

/**
 * Jaccard-style similarity over the fields that define a bug's identity.
 *
 * Weighting detail that matters: a field that is *empty on both sides* must not
 * contribute weight. Comparing `param: ''` to `param: ''` is not evidence that
 * two findings are alike — it is an absence of information. Scoring it as a
 * match diluted genuine duplicates below the duplicate threshold, which is the
 * one failure this module exists to prevent.
 */
function similarity(a, b) {
  const fa = fingerprint(a), fb = fingerprint(b);
  let total = 0, got = 0;

  // Class and endpoint always carry weight: they are what defines a bug's place.
  const same = (x, y, w) => { total += w; if (x === y) got += w; };
  same(fa.cls, fb.cls, 3);
  same(fa.endpoint, fb.endpoint, 3);
  same(fa.method, fb.method, 1);

  // Optional fields only count when at least one side has a value.
  const either = (x, y, w, eq) => {
    if (!x && !y) return;                 // no information either side
    total += w;
    if (eq) got += w;
  };
  either(fa.param, fb.param, 1, fa.param === fb.param);
  either(fa.impact, fb.impact, 1, fa.impact === fb.impact);

  // Identity-set overlap (the access-control dimension).
  if (fa.identities.length && fb.identities.length) {
    total += 2;
    const inter = fa.identities.filter((x) => fb.identities.includes(x)).length;
    const union = new Set([...fa.identities, ...fb.identities]).size;
    got += 2 * (union ? inter / union : 0);
  }

  // Chain overlap.
  if (fa.steps.length && fb.steps.length) {
    total += 2;
    const inter = fa.steps.filter((x) => fb.steps.includes(x)).length;
    const union = new Set([...fa.steps, ...fb.steps]).size;
    got += 2 * (union ? inter / union : 0);
  }
  return total ? got / total : 0;
}

/**
 * Classify a candidate against the prior-art corpus.
 *
 * @param candidate  the finding being considered for submission
 * @param corpus     known/previous findings
 * @param opts       { noveltyBoost: reward chains (default true) }
 */
function triage(candidate, corpus = [], opts = {}) {
  const scored = (corpus || []).map((known) => {
    const sim = similarity(candidate, known);
    return { known, sim, id: known.id, title: known.title || known.summary || known.id };
  }).sort((a, b) => b.sim - a.sim);

  const nearest = scored[0] || null;
  const fc = fingerprint(candidate);

  if (!nearest) {
    return { verdict: 'novel', confidence: 0.5, nearest: null, reasons: ['no prior art in the corpus — treated as novel but unverified'], action: 'submit' };
  }

  const fk = fingerprint(nearest.known);
  const sameClass = fc.cls === fk.cls;
  const samePlace = fc.endpoint === fk.endpoint && fc.method === fk.method;
  const sameChain = fc.steps.length > 0 && JSON.stringify(fc.steps) === JSON.stringify(fk.steps);

  // Case 1: same root cause, same place, same class -> duplicate.
  if (nearest.sim >= 0.85 && sameClass && samePlace) {
    return {
      verdict: 'duplicate',
      confidence: Math.min(0.95, nearest.sim),
      nearest,
      reasons: [
        `same vulnerability class (${fc.cls}) at the same endpoint (${fc.endpoint})`,
        `similarity ${nearest.sim.toFixed(2)} against ${nearest.title}`,
      ],
      action: 'do-not-submit',
    };
  }

  // Case 2: known root cause, but our impact or preconditions differ -> not a dupe.
  if (nearest.sim >= 0.5 && sameClass && !samePlace) {
    return {
      verdict: 'known-class-new-location',
      confidence: 0.6,
      nearest,
      reasons: [
        `the class (${fc.cls}) is known, but this is a different endpoint (${fc.endpoint} vs ${fk.endpoint})`,
        'programs usually accept a new instance only when the exploitation method or impact differs materially',
      ],
      action: 'submit-with-distinct-impact',
      mustShow: [
        'why this instance is not reproducible by the same request as the prior report',
        'what the impact is here that was not demonstrated there',
      ],
    };
  }

  // Case 3: chained finding -> likely novel, and chaining is what pays.
  if (opts.noveltyBoost !== false && fc.steps.length >= 2 && !sameChain) {
    return {
      verdict: 'novel-chain',
      confidence: 0.7,
      nearest,
      reasons: [
        `chains ${fc.steps.length} steps (${fc.steps.join(' -> ')})`,
        nearest.sim < 0.85
          ? `no prior report chains these steps together (nearest similarity ${nearest.sim.toFixed(2)})`
          : 'the chain composition appears new even though individual steps are known',
      ],
      action: 'submit-as-chain',
      mustShow: ['the linkage between steps, explicitly', 'why each step alone would not be rated highly'],
    };
  }

  if (nearest.sim >= 0.7) {
    return {
      verdict: 'probably-duplicate',
      confidence: nearest.sim,
      nearest,
      reasons: [`similarity ${nearest.sim.toFixed(2)} against ${nearest.title}`],
      action: 'rewrite-to-differentiate',
    };
  }

  return {
    verdict: 'novel',
    confidence: 0.6,
    nearest,
    reasons: [`nearest prior art is only ${nearest.sim.toFixed(2)} similar (${nearest.title})`],
    action: 'submit',
  };
}

/**
 * Deduplicate a batch against itself, keeping the strongest representative of
 * each cluster. Prevents three reports of one bug entering the queue.
 */
function dedupeBatch(findings = []) {
  const kept = [];
  const dropped = [];
  for (const f of (findings || [])) {
    let dup = null;
    for (const k of kept) {
      if (similarity(f, k) >= 0.85 && fingerprint(f).cls === fingerprint(k).cls) { dup = k; break; }
    }
    if (dup) dropped.push({ finding: f, duplicateOf: dup.id || dup.title });
    else kept.push(f);
  }
  return { kept, dropped };
}

module.exports = { fingerprint, normalisePath, similarity, triage, dedupeBatch };
