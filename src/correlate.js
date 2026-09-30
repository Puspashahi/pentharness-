'use strict';
/**
 * Chain correlator — turns independent leads into attack paths.
 *
 * Tenzai: "When the agent finds multiple primitives that share an attacker
 * identity, target asset, and a timeline, the platform stitches them into a
 * single attack-chain finding. That chain finding is not a paste of the
 * underlying issues — it is the narrative of how the attacker uses the
 * different vulnerabilities one after the other."
 *
 * So a chain requires *composability*, not co-existence. Two findings on
 * different hosts are not a chain. Two findings where the output of one is the
 * input to another ARE. This module encodes the composability rules.
 */

/** Ordered primitives: each stage must enable the next. */
const STAGE_ORDER = ['recon', 'secrets', 'xss', 'traversal', 'config', 'injection', 'authn', 'authz', 'ai', 'ssrf', 'business'];

const STAGE_RANK = Object.fromEntries(STAGE_ORDER.map((s, i) => [s, i]));

/** Which classes, when combined, yield a materially worse outcome. */
const AMPLIFIERS = {
  // leaked identifier + missing authz = enumerate the whole object space
  secrets: ['authz', 'injection', 'ai'],
  // authz write primitive + AI tool surface = code execution
  authz: ['ai', 'business', 'injection'],
  // XSS steals the session that unlocks admin actions
  xss: ['authn', 'authz', 'business'],
  // injection reads credentials that unlock the AI tooling
  injection: ['authz', 'ai', 'business', 'secrets'],
  // SSRF reaches internal services the browser cannot
  ssrf: ['ai', 'injection', 'secrets', 'business'],
  // traversal gives you the source, which explains everything else
  traversal: ['secrets', 'injection', 'config', 'authz'],
  // guardrail bypass unlocks the tool path
  ai: ['business', 'authz'],
  authn: ['authz', 'ai', 'business'],
  business: ['authz'],
  config: [],
  // recon: identifier-listing endpoints are what turn an unexploitable-looking
  // "unguessable UUID" IDOR into a full data breach. Field guidance: "if a GUID
  // is used and you think it limits the bug's severity, find an endpoint that
  // leaks or lists those GUIDs. That leak + the IDOR forms a complete exploit
  // chain and significantly improves the severity rating."
  recon: ['secrets', 'injection', 'authz', 'ai', 'ssrf', 'traversal'],
};

/**
 * Do these two leads compose? Composition needs a shared execution context
 * (same asset, or a credential/identifier flowing between them) and a
 * privilege or reach gain.
 */
function composes(a, b) {
  if (a.id === b.id) return null;
  // must share an execution context
  const sameAsset = a.asset && a.asset === b.asset;
  const sameParam = a.param && a.param === b.param;
  const sameIdentity = a.identity && a.identity === b.identity;
  if (!sameAsset && !sameParam && !sameIdentity) return null;

  // must be in a usable order (a enables b, not the reverse)
  const ra = STAGE_RANK[a.cls] ?? 0;
  const rb = STAGE_RANK[b.cls] ?? 0;
  if (ra >= rb) return null;

  // the earlier stage must be an amplifier for the later one
  if (!(AMPLIFIERS[a.cls] || []).includes(b.cls)) return null;

  return {
    context: sameAsset ? 'same-asset' : sameIdentity ? 'same-identity' : 'same-parameter',
    narrative: narrative(a, b),
  };
}

function narrative(a, b) {
  const map = {
    secrets: `Obtain a leaked credential or identifier, then`,
    authz: `Exploit the missing object-level check, then`,
    authn: `Ride the weak authentication, then`,
    injection: `Use the injection primitive, then`,
    xss: `Execute script in a victim's session, then`,
    traversal: `Read the source via traversal, then`,
    ssrf: `Pivot server-side, then`,
    ai: `Use the exposed agent tool path, then`,
    business: `Abuse the workflow, then`,
    config: `Leverage the weak configuration, then`,
    recon: `Enumerate, then`,
  };
  const first = (map[a.cls] || `Use ${a.cls}, then`).toLowerCase();
  return `${first} ${b.title.toLowerCase()}`;
}

/**
 * Build candidate chains from a lead store.
 * Chains of length 2 are candidate pairs; length 3+ are full narratives.
 */
function correlate(store, opts = {}) {
  const minLen = opts.minLen || 2;
  const maxChains = opts.maxChains || 25;
  // Recon noise ("discovered endpoint", "200 GET") must never open a chain.
  // A chain is a story about privilege or reach, not a list of pages visited.
  const isNoiseHead = (l) => l.cls === 'recon' && !l.chain_hints.length;
  const leads = store.all();
  const chains = [];
  const seenTails = new Set();

  // Strongest amplifiers first, so a credential-leak -> authz chain wins over
  // a weak pair that happens to share a host.
  const ordered = [...leads].sort((x, y) => {
    const nx = isNoiseHead(x) ? 1 : 0, ny = isNoiseHead(y) ? 1 : 0;
    if (nx !== ny) return nx - ny;
    const ax = x.cls === 'secrets' || x.cls === 'injection' ? 1 : 0;
    const ay = y.cls === 'secrets' || y.cls === 'injection' ? 1 : 0;
    if (ax !== ay) return ay - ax;
    return y.priority - x.priority;
  });

  for (let i = 0; i < ordered.length && chains.length < maxChains; i++) {
    const head = ordered[i];
    if (isNoiseHead(head)) continue;             // never start a chain here
    for (let j = 0; j < ordered.length; j++) {
      if (i === j) continue;
      const tail = ordered[j];
      if (isNoiseHead(tail)) continue;           // nor end on it
      const link = composes(head, tail);
      if (!link) continue;
      // extend greedily
      const path = [head, tail];
      let cur = tail;
      for (let k = 0; k < ordered.length && path.length < 4; k++) {
        const next = ordered[k];
        if (path.some((p) => p.id === next.id) || isNoiseHead(next)) continue;
        const l2 = composes(cur, next);
        if (!l2) continue;
        path.push(next);
        cur = next;
      }
      if (path.length < minLen) continue;
      const key = path.map((p) => p.id).join('>');
      if (chains.some((c) => c.key === key)) continue;
      // One lead can legitimately be the tail of several chains, but cap it so
      // one noisy primitive cannot dominate the entire queue.
      if (seenTails.has(tail.id) && chains.length > 3) continue;
      seenTails.add(tail.id);
      chains.push({
        key,
        length: path.length,
        stages: path.map((p) => p.cls),
        asset: path.find((p) => p.asset)?.asset,
        identity: path.find((p) => p.identity)?.identity,
        impact: impactOf(path),
        severity: severityOf(path),
        narrative: buildNarrative(path),
        steps: path.map((p) => ({ lead: p.id, cls: p.cls, title: p.title, url: p.url, param: p.param, proof_needed: p.proof_needed })),
      });
      if (chains.length >= maxChains) break;
    }
  }

  // Deduplicate to the strongest chain per (head,tail) class signature, so the
  // report shows distinct attack paths rather than permutations.
  const uniq = new Map();
  for (const c of chains) {
    const sig = c.stages.join('>');
    const prev = uniq.get(sig);
    if (!prev || c.impact > prev.impact) uniq.set(sig, c);
  }

  const out = [...uniq.values()];
  out.sort((a, b) => b.length - a.length || sevRank(a.severity) - sevRank(b.severity) || b.impact - a.impact);
  return out;
}

function buildNarrative(path) {
  const parts = path.map((p) => p.title);
  if (parts.length === 2) return `${parts[0]} -> ${parts[1]}`;
  return `${parts.slice(0, -1).join(' -> ')} -> ${parts[parts.length - 1]}`;
}

/** Chain impact scales with length and how privileged the tail is. */
function impactOf(path) {
  let s = path.length * 10;
  if (path.some((p) => p.cls === 'ai')) s += 25;
  if (path.some((p) => p.cls === 'injection')) s += 20;
  if (path.some((p) => p.cls === 'authz')) s += 20;
  if (path.some((p) => p.cls === 'ssrf')) s += 15;
  if (path.some((p) => p.cls === 'secrets')) s += 10;
  return Math.min(100, s);
}

function severityOf(path) {
  const tail = path[path.length - 1];
  const hasExec = path.some((p) => ['injection', 'ai'].includes(p.cls));
  if (hasExec && path.length >= 2) return 'critical';
  if (path.some((p) => p.cls === 'authz' || p.cls === 'authn')) return 'high';
  if (path.some((p) => ['ssrf', 'secrets', 'traversal'].includes(p.cls))) return 'medium';
  return 'low';
}

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const sevRank = (s) => SEV_RANK[s] ?? 9;

module.exports = { correlate, composes, AMPLIFIERS, STAGE_ORDER, severityOf, impactOf, sevRank };
