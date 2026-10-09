'use strict';
/**
 * Discovery bootstrap.
 *
 * The harness's exploitation layer is strong but it is fed, not self-starting:
 * `predict` ranks parameters, `prober` executes payloads, `validators` decide,
 * `gate` ships. All of them read the knowledge base. When the base is empty the
 * run is honest — 0 parameters, nothing to execute, INCOMPLETE — and correct,
 * because nothing was proven. It is still an assessment that looked at nothing.
 *
 * The base is empty in exactly two situations, and neither is the crawler's
 * fault:
 *
 *   1. The index page advertises no routes. A SPA shell, an API-only
 *      deployment, or any app whose links are built client-side leaves the
 *      crawler with one page and no endpoints. arjun needs an input-taking URL
 *      to fuzz, so it returns nothing here too.
 *   2. Endpoints accept parameters the application never sends. An undocumented
 *      query parameter is invisible to any observation-driven approach,
 *      including a real browser, because nothing ever emits it.
 *
 * So this module does the two things nothing else does: enumerate paths by
 * dictionary, and confirm parameters by differential response rather than by
 * guessing. It then hands the result to the knowledge base and stops. It sends
 * no attack payloads and never judges a vulnerability — the existing prober,
 * validators and gate remain the only things that decide what is real.
 *
 * Parameter confirmation is differential on purpose. Seeding every name in the
 * list as "found" would make the coverage ledger claim surface it never
 * verified, and would hand the prober hundreds of sinks to prove refutations
 * against. A parameter is recorded only when adding it changes status, length
 * or body relative to a baseline captured in this same run.
 */
const { execFile } = require('child_process');
const fs = require('fs');

const DEFAULT_WORDLIST = '/home/batist/tools/SecLists/Discovery/Web-Content/raft-medium-directories.txt';

/**
 * Parameter names to confirm. Ordered so the ones most likely to be real sinks
 * on a given path are tried first; the tail is a cheap sweep for the rest.
 * Single letters are included because short handler names are common and the
 * differential check is what keeps them honest.
 */
const PARAM_CANDIDATES = [
  'q', 'query', 'search', 'name', 'id', 'uid', 'user', 'user_id', 'num', 'n',
  'page', 'sort', 'order', 'from', 'to', 'include', 'lang', 'view', 'action',
  'template', 'data', 'json', 'xml', 'cmd', 'command', 'exec', 'file', 'path',
  'filename', 'url', 'uri', 'host', 'domain', 'redirect', 'next', 'callback',
  'email', 'message', 'comment', 'text', 'content', 'body', 'token', 'key',
  'img', 'image', 'src', 'dest', 'fetch', 'proxy', 'target', 'site',
  'u', 'f', 'p', 'v', 'd', 'r', 'g', 'out', 'loc', 'location', 'page_id',
];

/** A value that is inert for a template engine, an ORM and a shell alike. */
const PROBE_VALUE = 'zq7probe';

function buildUrl(base, path) {
  try {
    return new URL(String(path).replace(/^\/+/, '/'), base).toString();
  } catch {
    return null;
  }
}

function run(cmd, args, timeoutMs) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024 }, (err, stdout) => {
      resolve({ err, stdout: stdout || '' });
    });
  });
}

/** Fetch with a hard timeout; never throws. */
async function probe(url, timeoutMs = 10000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal, redirect: 'manual' });
    const body = await res.text().catch(() => '');
    return { status: res.status, len: body.length, body };
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

function differs(a, b) {
  if (!a || !b) return false;
  return a.status !== b.status || a.len !== b.len || a.body !== b.body;
}

/**
 * Learn what "not found" looks like on this target before trusting any filter.
 *
 * A fixed `-fc 404` is wrong more often than it is right. An auth-gated
 * application answers 401 for every path that does not exist, so a 404-only
 * filter admits the entire wordlist as discoveries; a permissive catch-all does
 * the same. Either way the knowledge base fills with hundreds of paths that were
 * never real, which then inflates the coverage ledger and reports surface the
 * run never examined.
 *
 * The fingerprint is taken from paths that are certain not to exist, so it
 * captures whatever the application uses to mean "no" — 404, 401, 403, a soft
 * 200 with a "not found" body — and a real endpoint is anything that differs.
 */
async function calibrate(target, o) {
  const base = target.replace(/\/$/, '');
  const probes = [
    `zzq7nx${Math.random().toString(36).slice(2, 10)}`,
    `zzq7nx${Math.random().toString(36).slice(2, 10)}.html`,
    `zzq7nx/${Math.random().toString(36).slice(2, 10)}`,
  ];
  const seen = [];
  for (const p of probes) {
    const r = await probe(`${base}/${p}`, o.timeoutMs || 10000);
    if (r) seen.push(`${r.status}:${r.len}`);
  }
  const counts = new Map();
  for (const f of seen) counts.set(f, (counts.get(f) || 0) + 1);
  let fp = null;
  let best = 0;
  for (const [f, n] of counts) if (n > best) { best = n; fp = f; }
  return { fingerprint: fp, agrees: seen.length > 0 && best >= 2 };
}

/**
 * Dictionary enumeration via ffuf, with a calibrated plain-URL fallback so the
 * phase still runs on a box without ffuf rather than silently reporting nothing.
 */
async function enumeratePaths(target, o, log) {
  const wordlist = o.wordlist || DEFAULT_WORDLIST;
  if (!fs.existsSync(wordlist)) {
    log('discover', `wordlist not found at ${wordlist}; skipping path enumeration`);
    return [];
  }

  const cal = await calibrate(target, o);
  if (cal.agrees) log('discover', `calibrated: "not found" answers ${cal.fingerprint} on this target`);
  else log('discover', 'calibration inconclusive — keeping only clear differentials');

  const dropIf = (status, len) => cal.agrees && `${status}:${len}` === cal.fingerprint;

  if (await hasFfuF()) {
    const out = `/tmp/pentharness-ffuf-${Date.now()}.json`;
    const args = [
      '-s', '-u', `${target.replace(/\/$/, '')}/FUZZ`,
      '-w', wordlist,
      '-mc', 'all',
      '-ac',
      '-t', String(o.threads || 40), '-rate', String(o.rate || 200),
      '-of', 'json', '-o', out, '-noninteractive',
    ];
    if (cal.agrees) {
      const [st, ln] = cal.fingerprint.split(':');
      args.push('-fc', st, '-fl', ln);
    }
    log('discover', `ffuf enumerating paths${cal.agrees ? ` (filtering ${cal.fingerprint})` : ''}`);
    const { err } = await run('ffuf', args, o.ffufTimeoutMs || 10 * 60 * 1000);
    if (!err) {
      try {
        const parsed = JSON.parse(fs.readFileSync(out, 'utf8'));
        fs.unlinkSync(out);
        return (parsed.results || [])
          .filter((r) => !dropIf(r.status, r.length))
          .map((r) => r.url)
          .slice(0, o.maxPaths || 400);
      } catch { /* fall through to the manual sweep */ }
    }
  }

  log('discover', 'ffuf unavailable — falling back to a bounded manual sweep');
  const words = fs.readFileSync(wordlist, 'utf8').split('\n')
    .map((w) => w.trim()).filter((w) => w && !w.startsWith('#'));
  const sample = o.manualSample ? words.slice(0, o.manualSample) : words.filter((_, i) => i % 40 === 0).slice(0, o.maxPaths || 400);

  const found = [];
  const base = target.replace(/\/$/, '');
  const CONCURRENCY = o.concurrency || 12;
  let i = 0;
  await Promise.all(Array.from({ length: CONCURRENCY }, async () => {
    while (i < sample.length) {
      const w = sample[i++];
      const url = `${base}/${w}`;
      const r = await probe(url, 8000);
      if (!r) continue;
      if (dropIf(r.status, r.len)) continue;
      found.push(url);
    }
  }));
  return found;
}

let ffufChecked = null;
async function hasFfuF() {
  if (ffufChecked === null) {
    ffufChecked = await new Promise((resolve) => {
      execFile('sh', ['-c', 'command -v ffuf'], (err) => resolve(!err));
    });
  }
  return ffufChecked;
}

/**
 * Confirm which candidate parameters a path actually honours.
 * @returns {string[]} parameter names whose addition changed the response
 */
async function confirmParams(url, o, log) {
  const baseline = await probe(url, o.timeoutMs);
  if (!baseline || baseline.status >= 500) return [];
  // On an auth-gated target every path answers 401 identically, so probing
  // parameters here tests nothing and costs a request per candidate per path.
  // Parameter discovery belongs after authentication, in the authenticated run.
  if (baseline.status === 401 || baseline.status === 403) return [];

  const hint = new URL(url).pathname;
  const names = [
    ...PARAM_CANDIDATES.filter((n) => new RegExp(n, 'i').test(hint)),
    ...PARAM_CANDIDATES.filter((n) => !new RegExp(n, 'i').test(hint)),
  ].slice(0, o.maxParamsPerPath || 24);

  const found = [];
  const CONCURRENCY = o.concurrency || 8;
  let i = 0;
  await Promise.all(Array.from({ length: CONCURRENCY }, async () => {
    while (i < names.length) {
      const n = names[i++];
      const sep = url.includes('?') ? '&' : '?';
      const r = await probe(`${url}${sep}${encodeURIComponent(n)}=${encodeURIComponent(PROBE_VALUE)}`, o.timeoutMs);
      if (differs(baseline, r)) found.push(n);
    }
  }));
  return found;
}

/**
 * Seed the knowledge base.
 * @param {object} o
 * @param {string} o.target base URL
 * @param {object} o.kb TargetKB
 * @param {string[]} [o.knownPaths] already-learned paths, still parameter-probed
 * @param {function} [o.log]
 * @returns {Promise<{paths:number, params:number, endpoints:string[]}>}
 */
async function bootstrap(o = {}) {
  const { target, kb, log = () => {} } = o;
  if (!target || !kb) return { paths: 0, params: 0, endpoints: [] };

  const discovered = await enumeratePaths(target, o, log);
  log('discover', `path enumeration returned ${discovered.length} candidate path(s)`);

  const known = (o.knownPaths || []).filter((p) => {
    try { return new URL(p).origin === new URL(target).origin; } catch { return false; }
  });
  const all = [...new Set([...known, ...discovered])].slice(0, o.maxPaths || 400);
  log('discover', `probing parameters on ${all.length} path(s)`);

  let paramCount = 0;
  const endpoints = [];
  const CONCURRENCY = o.concurrency || 6;
  let i = 0;

  await Promise.all(Array.from({ length: CONCURRENCY }, async () => {
    while (i < all.length) {
      const url = all[i++];
      kb.learnEndpoint(url);
      endpoints.push(url);
      if (o.skipParams) continue;
      const names = await confirmParams(url, o, log);
      for (const n of names) {
        kb.learnEndpoint(url, { param: n });
        paramCount++;
      }
      if (names.length) log('discover', `${new URL(url).pathname}: confirmed ${names.length} parameter(s) -> ${names.slice(0, 6).join(', ')}`);
    }
  }));

  return { paths: all.length, params: paramCount, endpoints };
}

module.exports = { bootstrap, confirmParams, enumeratePaths, PARAM_CANDIDATES, DEFAULT_WORDLIST };