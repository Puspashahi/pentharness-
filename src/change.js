'use strict';
/**
 * Change detection between runs.
 *
 * This is the difference between thorough and fast. Most findings live on
 * surface that has just appeared: a subdomain deployed yesterday, an endpoint
 * that started accepting requests this morning, an admin panel that used to
 * 403. A researcher who spots that in the first hour of it being live is
 * usually the only one who will. Re-scanning the same target in six months and
 * seeing the same list teaches nothing.
 *
 * So every run records a snapshot, and the next run diffs against it. The
 * output is not "here is the target" but "here is what changed since you were
 * last here, and here is what you have never tested".
 *
 * Two categories matter and they are not the same:
 *
 *   NEW       — appeared since the previous run. Prime hunting material.
 *   UNTESTED  — never probed in any run. Coverage gaps, which are the quiet way
 *               a harness convinces you a target is clean.
 *
 * Everything else is `seen`, so a stable target produces a short report rather
 * than re-listing thousands of known endpoints.
 */

const fs = require('fs');
const path = require('path');

const VERSION = 1;

/** Read the most recent snapshot for a target, if any. */
function loadLast(dir, target) {
  const p = path.join(dir, 'snapshots', `${slug(target)}.json`);
  if (!fs.existsSync(p)) return null;
  try {
    const j = JSON.parse(fs.readFileSync(p, 'utf8'));
    return j && j.version === VERSION ? j : null;
  } catch { return null; }
}

/**
 * Take a snapshot of the current surface.
 *
 * Only things that are cheap to compare and meaningful to notice go in: hosts,
 * endpoints, parameters, known findings. Response bodies are deliberately not
 * hashed here — a CSRF token changes on every request and would make every run
 * look like a total rewrite.
 */
function take(target, kb, opts = {}) {
  const endpoints = new Set();
  const hosts = new Set();
  const params = new Set();

  const eps = kb && kb.endpoints ? [...kb.endpoints.keys()] : [];
  for (const k of eps) {
    let u = k;
    try { u = JSON.parse(k)[0]; } catch { /* plain string key */ }
    if (typeof u !== 'string') continue;
    endpoints.add(norm(u));
    try { hosts.add(new URL(u).hostname); } catch { /* relative */ }
    const e = kb.endpoints.get(k);
    for (const p of (e && e.params) || []) if (p) params.add(String(p));
  }
  for (const p of (kb && kb.params ? [...kb.params] : [])) if (p) params.add(String(p));
  for (const h of (opts.extraHosts || [])) hosts.add(String(h).toLowerCase());

  return {
    version: VERSION,
    target,
    ts: new Date().toISOString(),
    endpoints: [...endpoints].sort(),
    hosts: [...hosts].sort(),
    params: [...params].sort(),
    findings: (opts.findings || []).map((f) => ({
      id: f.id || f.title, title: f.title || f.id, severity: f.severity,
    })),
    // Persisted so the next run can tell "never probed" from "probed and clean".
    testedEndpoints: [...new Set(opts.testedEndpoints || [])].map(norm).sort(),
  };
}

/**
 * Diff this run against the last.
 *
 * `untested` is the important one. An endpoint that exists in the snapshot but
 * has never been exercised is not a clean result — it is a gap, and it is the
 * kind of gap that turns into a finding later.
 */
function diff(current, previous) {
  const cur = {
    endpoints: new Set(current.endpoints || []),
    hosts: new Set(current.hosts || []),
    params: new Set(current.params || []),
  };
  const findingsNow = new Set((current.findings || []).map((f) => f.id));

  if (!previous) {
    return {
      firstRun: true,
      newHosts: [...cur.hosts], newEndpoints: [...cur.endpoints], newParams: [...cur.params],
      goneHosts: [], goneEndpoints: [],
      untested: [...cur.endpoints],
      tested: [], resolvedFindings: [],
      summary: `baseline recorded: ${cur.hosts.size} host(s), ${cur.endpoints.size} endpoint(s). The next run will report what changed.`,
    };
  }

  const prev = {
    endpoints: new Set(previous.endpoints || []),
    hosts: new Set(previous.hosts || []),
    params: new Set(previous.params || []),
  };
  const findingsBefore = new Set((previous.findings || []).map((f) => f.id));
  const titlesBefore = new Set((previous.findings || []).map((f) => String(f.title || '').toLowerCase()));

  const newHosts = [...cur.hosts].filter((h) => !prev.hosts.has(h));
  const newEndpoints = [...cur.endpoints].filter((e) => !prev.endpoints.has(e));
  const newParams = [...cur.params].filter((p) => !prev.params.has(p));
  const goneHosts = [...prev.hosts].filter((h) => !cur.hosts.has(h));
  const goneEndpoints = [...prev.endpoints].filter((e) => !cur.endpoints.has(e));

  // An endpoint counts as tested if EITHER this run or a previous one exercised
  // it. Only a run that has actually probed something can clear a gap, and using
  // this run's set alone made every endpoint look untested on a partial run.
  const tested = new Set([...(current.testedEndpoints || []), ...(previous.testedEndpoints || [])].map(norm));
  const untested = [...cur.endpoints].filter((e) => !tested.has(e));
  const titlesNow = new Set((current.findings || []).map((f) => String(f.title || '').toLowerCase()));
  // A finding counts as resolved only when neither its id nor its title
  // reappears. Ids are generated per run, so comparing ids alone made every
  // finding look "resolved and replaced" on every single run.
  const resolvedFindings = [...findingsBefore].filter((id) => {
    if (findingsNow.has(id)) return false;
    const prevRec = (previous.findings || []).find((f) => f.id === id);
    const t = String((prevRec && prevRec.title) || '').toLowerCase();
    return !(t && titlesNow.has(t));
  });

  return {
    firstRun: false,
    since: previous.ts,
    newHosts: newHosts.sort(),
    newEndpoints: newEndpoints.sort(),
    newParams: newParams.sort(),
    goneHosts: goneHosts.sort(),
    goneEndpoints: goneEndpoints.sort(),
    untested: untested.sort(),
    resolvedFindings,
    summary: buildSummary({ newHosts, newEndpoints, newParams, goneHosts, goneEndpoints, untested, resolvedFindings }),
  };
}

/** Human-readable one-liner. Keeps a stable target quiet. */
function buildSummary(d) {
  const parts = [];
  if (d.newHosts.length) parts.push(`${d.newHosts.length} new host(s)`);
  if (d.newEndpoints.length) parts.push(`${d.newEndpoints.length} new endpoint(s)`);
  if (d.newParams.length) parts.push(`${d.newParams.length} new parameter(s)`);
  if (d.goneHosts.length) parts.push(`${d.goneHosts.length} host(s) gone`);
  if (d.untested.length) parts.push(`${d.untested.length} endpoint(s) never probed`);
  if (d.resolvedFindings.length) parts.push(`${d.resolvedFindings.length} previous finding(s) no longer reproduce`);
  return parts.length ? parts.join(', ') : 'no change since the last run';
}

/**
 * Rate what changed. A new staging host is worth an hour; a new marketing page
 * is worth nothing. Without this the diff is noise and gets ignored.
 */
function prioritise(d, opts = {}) {
  const out = [];
  for (const h of d.newHosts || []) {
    const why = classifyHost(h);
    out.push({ kind: 'host', value: h, score: why.score, why: why.why });
  }
  for (const e of d.newEndpoints || []) {
    const why = classifyEndpoint(e);
    out.push({ kind: 'endpoint', value: e, score: why.score, why: why.why });
  }
  for (const p of d.newParams || []) {
    const interesting = /^(id|user|uid|order|invoice|file|doc|token|key|admin|role|email|account|tenant|org|project|q|query|url|redirect|next|return|callback)/i.test(p);
    out.push({ kind: 'param', value: p, score: interesting ? 6 : 2, why: interesting ? 'parameter name suggests user or object data' : 'new parameter' });
  }
  out.sort((a, b) => b.score - a.score);
  return opts.limit ? out.slice(0, opts.limit) : out;
}

const HOST_RULES = [
  [/\b(dev|stage|staging|uat|qa|test|sandbox|preprod)\b/i, 12, 'new non-production environment'],
  [/\b(admin|manage|panel|cpanel|internal|intranet|vpn|jump|bastion)\b/i, 12, 'new administrative or internal host'],
  [/\b(api|graphql|gateway|rest|internal-api)\b/i, 9, 'new API surface'],
  [/\b(git|jenkins|ci|cd|build|jira|sonar|nexus|registry|vault|kube|k8s)\b/i, 10, 'new infrastructure or source system'],
  [/\b(backup|old|legacy|deprecated|archive|temp|tmp)\b/i, 10, 'new possibly-forgotten host'],
  [/\d{1,3}(?:\.\d{1,3}){3}/, 8, 'new IP-based host'],
  [/\b(www|blog|shop|store|help|support|docs)\b/i, 1, 'low-signal public host'],
];

const EP_RULES = [
  [/\/(admin|debug|internal|test|backup|dev|staging|config|\.env|\.git|swagger|openapi|graphql|actuator|phpinfo|console)/i, 12, 'endpoint path suggests an exposed or debug surface'],
  [/\/(api|graphql|rest|rpc|v\d)\//i, 8, 'new API endpoint'],
  [/(login|auth|oauth|sso|session|token|password|reset)/i, 8, 'authentication endpoint'],
  [/(download|export|upload|file|report|dump|backup)/i, 9, 'data transfer endpoint'],
];

function classifyHost(h) {
  for (const [rx, score, why] of HOST_RULES) if (rx.test(h)) return { score, why };
  return { score: 4, why: 'new host' };
}
function classifyEndpoint(e) {
  for (const [rx, score, why] of EP_RULES) if (rx.test(e)) return { score, why };
  return { score: 3, why: 'new endpoint' };
}

/** Persist the snapshot for next time. */
function save(dir, snap) {
  const d = path.join(dir, 'snapshots');
  fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(d, `${slug(snap.target)}.json`), JSON.stringify(snap, null, 2));
  // Keep a short history so "when did this appear" is answerable.
  const histPath = path.join(d, 'history.jsonl');
  fs.appendFileSync(histPath, JSON.stringify({ ts: snap.ts, target: snap.target, hosts: snap.hosts.length, endpoints: snap.endpoints.length }) + '\n');
}

function norm(u) {
  return String(u).replace(/^https?:\/\//, '').replace(/\/$/, '') || '/';
}
function slug(t) { return String(t).replace(/^https?:\/\//, '').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 80); }

/** What changed since a given timestamp, across snapshot history. */
function sinceLastRun(dir, target, isoTs) {
  const p = path.join(dir, 'snapshots', `${slug(target)}.json`);
  if (!fs.existsSync(p)) return null;
  const j = JSON.parse(fs.readFileSync(p, 'utf8'));
  return j.ts === isoTs ? j : null;
}

module.exports = { take, diff, prioritise, save, loadLast, buildSummary, sinceLastRun, classifyHost, classifyEndpoint, VERSION };
