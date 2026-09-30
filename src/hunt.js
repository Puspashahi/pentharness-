'use strict';
/**
 * hunt — one command, target in, validated findings out.
 *
 * The whole point of the harness is that the operator should not have to know
 * which phase to run. This orchestrates the full loop and, critically, keeps
 * the ordering that the research says matters:
 *
 *   map → predict → execute → observe → prove → contest → chain → gate
 *
 * Two rules encoded here, both from the sources:
 *
 *  - "The agent explicitly maps the attack surface before diving in" (Kitten).
 *    Agents that start hunting before mapping skip steps and chase the goal.
 *  - "No agent reasons well across an entire repository" (Quarkslab). Work is
 *    sliced to one parameter/hypothesis at a time, and the queue is bounded.
 *
 * Everything that can be automated is automated. Nothing asks for permission
 * mid-run, and nothing narrates.
 */

const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');
const exec = promisify(execFile);

const { TargetKB } = require('./knowledge');
const { LeadStore } = require('./leads');
const { correlate } = require('./correlate');
const { evaluate, toFinding } = require('./gate');
const { CoverageLedger } = require('./coverage');
const { SuppressionLedger } = require('./suppress');
const predict = require('./predict');
const prober = require('./prober');
const oob = require('./oob');
const V = require('./validators');
const N = require('./normalize');
const { runAuthzStage } = require('./authz-stage');
const { HeaderPolicy } = require('./headerpolicy');
const { scanPostMessage } = require('./postmessage');
const { runProtocolStage } = require('./protocol-stage');

const slug = (t) => String(t).replace(/^https?:\/\//, '').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 80);

function which(b) {
  for (const d of (process.env.PATH || '').split(':')) {
    if (!d) continue;
    const p = path.join(d, b);
    try { fs.statSync(p); fs.accessSync(p, fs.constants.X_OK); return p; } catch { /* keep looking */ }
  }
  return null;
}

async function run(bin, args, timeout) {
  const real = which(bin) || bin;
  const child = exec(real, args, { timeout, maxBuffer: 64 * 1024 * 1024 });
  if (child.child && child.child.stdin) { child.child.on('error', () => {}); child.child.stdin.end(); }
  try {
    const { stdout, stderr } = await child;
    return { ok: true, stdout, stderr };
  } catch (e) {
    return { ok: false, partial: !!e.killed && !!(e.stdout || '').length, stdout: e.stdout || '', stderr: String(e.stderr || e.message || '') };
  }
}

/**
 * @param {object} o
 *   target, stateDir, concurrency, maxEndpoints, oobServer, identities,
 *   answers, timeoutMs, skipScan
 */
async function hunt(o) {
  const t0 = Date.now();
  const dir = o.stateDir;
  fs.mkdirSync(dir, { recursive: true });
  const kb = TargetKB.load(path.join(dir, 'knowledge.json')) || new TargetKB(o.target);
  const store = LeadStore.fromJSON(readJson(path.join(dir, 'leads.json'), []));
  const coverage = new CoverageLedger();
  const ledger = new SuppressionLedger();
  const steps = [];
  const log = (s, detail) => { steps.push({ step: s, detail }); };

  // ---- 1. MAP (never hunt before mapping) ----
  coverage.phase('recon');
  if (!o.skipScan) {
    const hp = o.headerPolicy || new HeaderPolicy();
  hpRef = hp;
    const hx = await run(which('httpx-pd') || 'httpx', ['-u', o.target, '-json', '-silent', '-no-color', '-td', '-tech-detect', ...hp.flagsFor('httpx-pd')], o.timeoutMs);
    // Record a page only when a live HTTP response was actually observed.
    // Crawler-discovered paths are "endpoints" (shapes we know about), not
    // "pages" (things we exercised) — conflating the two would let the
    // coverage gate pass on discovery alone and read as a complete assessment.
    for (const l of N.ingest('httpx', hx.stdout)) {
      store.add(l);
      coverage.endpoint(l.url);
      const status = /status=(\d{3})/.exec(l.evidence || '')?.[1];
      if (status && Number(status) > 0 && Number(status) < 500) coverage.page(l.url);
    }
    if (hx.stdout.trim()) log('map', `httpx: ${N.ingest('httpx', hx.stdout).length} host`);

    const kat = await run('katana', ['-u', o.target, '-jsonl', '-silent', '-d', '2', '-jc', ...hp.flagsFor('katana')], o.timeoutMs);
    const raw = N.ingest('spider', kat.stdout);
    const shapes = N.dedupeCrawl(raw, { maxPaths: 80 });
    for (const l of shapes.leads) { store.add(l); kb.learnEndpoint(l.url); coverage.endpoint(l.url); }
    if (raw.length) log('map', `katana: ${raw.length} url -> ${shapes.uniqueShapes} shapes, kept ${shapes.leads.length}`);
  }

  // ---- 2. PREDICT (slice the surface into ranked hypotheses) ----
  // Link parameters discovered on leads to the endpoints that carry them, so
  // the prober knows *where* to send each payload. Without this the prober has
  // parameters but no targets and silently probes nothing.
  for (const l of store.all()) {
    if (l.param && l.url) kb.learnEndpoint(l.url, { param: l.param });
  }
  const params = [...new Set(store.all().map((l) => l.param).filter(Boolean))];
  for (const e of kb.endpoints.values()) for (const p of e.params || []) params.push(p);
  const ranked = predict.rank([...new Set(params)]);
  log('predict', `${ranked.length} parameter(s) ranked; top: ${ranked.slice(0, 4).map((r) => `${r.param}(${r.classes.join('/')})`).join(', ') || 'none'}`);
  for (const r of ranked) coverage.param(r.param);

  // ---- 3-4. EXECUTE + OBSERVE ----
  coverage.phase('scan');
  let sharedCtx = null;   // reused by the protocol stage
  let probeOut = { evidence: [], leads: [], notes: [] };
  if (ranked.length && !o.skipProbe) {
    // The HTTP prober needs only a request context. Prefer Playwright's (keeps
    // TLS/browser parity with the crawler), but fall back to a plain fetch-based
    // context so probing never depends on the browser being present.
    let browser = null;
    const pw = loadPlaywright();
    if (pw) {
      try {
        // `pw` is the module; the browser type is `pw.chromium`.
        browser = await pw.chromium.launch({ headless: !o.headful });
        sharedCtx = await browser.newContext({ ignoreHTTPSErrors: true, extraHTTPHeaders: hp.playwright() });
        sharedCtx.__fromBrowser = true;
      } catch (e) {
        log('execute', `browser unavailable (${String(e.message || e).slice(0, 60)}); using HTTP-only probing`);
        browser = null;
      }
    }
    if (!sharedCtx) sharedCtx = makeHttpContext();
    const ctx = sharedCtx;
    try {
      probeOut = await prober.probeAll(ctx, kb, {
        concurrency: o.concurrency || 6,
        maxEndpoints: o.maxEndpoints || 25,
        oobServer: o.oobServer,
      });
      for (const l of probeOut.leads) store.add(l);
      for (const e of probeOut.evidence) if (e.ship) { coverage.endpoint(e.url); coverage.page(e.url); }
      log('execute', `probed ${probeOut.evidence.length} hypothesis/hypotheses; ${probeOut.evidence.filter((e) => e.ship).length} proven`);
    } finally {
      // Close the browser, and drop the context that came from it. Handing a
      // closed context to the protocol stage made every graphql/jwt/cache probe
      // fail with "Target page, context or browser has been closed" — a silent
      // capability loss, since each probe reported an error instead of a result.
      if (browser) await browser.close().catch(() => {});
      if (sharedCtx && sharedCtx.__fromBrowser) sharedCtx = null;
    }
  } else if (!ranked.length) {
    log('execute', 'skipped — no parameters known yet');
  }

  // ---- 5-6. PROVE + CONTEST (already done inside probeAll, surfaced here) ----
  const proven = probeOut.evidence.filter((e) => e.ship);
  const refuted = probeOut.evidence.filter((e) => e.verdict === 'refuted');
  const hypotheses = probeOut.evidence.filter((e) => e.verdict === 'hypothesis');
  log('prove', `proven ${proven.length}, refuted ${refuted.length}, hypothesis ${hypotheses.length}`);

  // ---- identity + authorization + enumeration (automated) ----
  if (o.accounts && Object.keys(o.accounts).length >= 2) {
    coverage.phase('authz');
    for (const id of Object.keys(o.accounts)) coverage.identity(id);
    const stage = await runAuthzStage(loadPlaywright(), {
      target: o.target, loginUrl: o.loginUrl, accounts: o.accounts, stateDir: dir,
      headful: o.headful, maxEnumTargets: o.maxEnum, enumSamples: o.enumSamples,
      mode: o.authMode, oauth: o.authMode === 'oauth', selectors: o.selectors, routes: o.routes, headerPolicy: o.headerPolicy,
    });
    for (const l of stage.leads) store.add(l);
    for (const n of stage.notes) log('authz', n);
    for (const e of stage.enumeration.filter((x) => x.ok)) log('enumerate', `${e.seed.replace(/^https?:\/\/[^/]+/, '')}: ${e.reachable}/${e.probes} adjacent objects exposed another identity (${e.blastRadius}%)`);
    coverage.lens('identity-diff');
  }


  // ---- 6b. protocol stage: graphql / jwt / cache / ato chains ----
  if (!o.skipProtocols) {
    coverage.phase('protocols');
    // Corpus for capability detection: captured lead evidence plus page html.
    const corpus = store.all().map((l) => [l.title, l.url, l.evidence].filter(Boolean).join(' ')).join('\n');
    let psCtx = sharedCtx;
    if (!psCtx) {
      const pw2 = loadPlaywright();
      if (pw2) {
        try { const b2 = await pw2.chromium.launch({ headless: true }); psCtx = await b2.newContext({ ignoreHTTPSErrors: true, extraHTTPHeaders: hp.playwright() }); psCtx.__close = () => b2.close(); }
        catch { psCtx = makeHttpContext(); }
      } else { psCtx = makeHttpContext(); }
    }
    const ps = await runProtocolStage(psCtx, {
      target: o.target, kb, store, corpus,
      maxGqlProbes: o.maxGqlProbes, skipCache: o.skipCache,
      log: (k, v) => log(k, v),
    });
    for (const l of ps.leads) store.add(l);
    if (ps.observedJwtWeak) coverage.lens('jwt-mutation');
    if (psCtx && psCtx.__close) await psCtx.__close().catch(() => {});
  }

  // ---- 7. CHAIN ----
  coverage.phase('correlate');
  const chains = correlate(store);
  log('chain', `${chains.length} composable attack path(s)`);

  // ---- 8. GATE ----
  coverage.phase('gate');
  const answers = o.answers ? readJson(o.answers, {}) : {};
  const findings = [];
  let hold = 0;
  for (const l of store.all()) {
    const res = toFinding(l, answers[l.id] || {});
    if (res.ok) findings.push(res.finding);
    else if (res.verdict.verdict === 'drop') ledger.suppress(l, (res.verdict.reasons[0] || 'filtered').split(':')[0]);
    else hold++;
  }
  // Proven-by-validator leads ship without further adjudication.
  for (const l of store.all()) {
    if (l.confidence !== 'confirmed') continue;
    if (findings.some((f) => f.id === l.id)) continue;
    findings.push({ type: 'finding', id: l.id, title: l.title, severity: l.severity_hint || 'high', target: l.url, category: l.cls, description: l.evidence, evidence: l.evidence, tool_used: l.source, confidence: 'confirmed' });
  }

  const cov = coverage.assess();
  const durationSec = Math.round((Date.now() - t0) / 1000);
  const out = {
    tool: 'pentharness', target: o.target, startedAt: new Date(t0).toISOString(),
    durationSec, steps, coverage: { ...coverage.counts, complete: cov.complete, gaps: cov.gaps, statement: coverage.statement() },
    chains, findings, suppressed: ledger.toJSON(),
    proof: { nonce: V.NONCE, proven: proven.length, refuted: refuted.length, hypothesis: hypotheses.length },
  };
  fs.writeFileSync(path.join(dir, 'hunt.json'), JSON.stringify(out, null, 2));
  fs.writeFileSync(path.join(dir, 'findings.json'), JSON.stringify(findings, null, 2));
  fs.writeFileSync(path.join(dir, 'leads.json'), JSON.stringify(store.toJSON(), null, 2));
  kb.endRun({ hunt: true, findings: findings.length, chains: chains.length, complete: cov.complete });
  kb.save(path.join(dir, 'knowledge.json'));
  return out;
}

/**
 * Minimal request context over global fetch, with the same surface the prober
 * expects (`request.get` -> {status, text}). Keeps the pipeline runnable even
 * when Playwright cannot launch.
 */
let hpRef = null;   // active header policy, set by runHunt
function makeHttpContext() {
  const req = async (url, opts = {}) => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), opts.timeout || 12000);
    try {
      const pol = opts.headerPolicy || hpRef;
      if (pol && !pol.isAllowed(url)) return { status: () => 0, text: async () => '', url: () => url, headers: () => ({}) };
      if (pol) await pol.take();
      const init = { method: opts.method || 'GET', signal: ctrl.signal, redirect: 'follow', headers: pol ? pol.merge(opts.headers) : (opts.headers || {}) };
      if (opts.data != null) { init.body = typeof opts.data === 'string' ? opts.data : JSON.stringify(opts.data); }
      const res = await fetch(url, init);
      const body = await res.text();
      return { status: () => res.status, text: async () => body, url: () => res.url || url, headers: () => Object.fromEntries(res.headers) };
    } finally { clearTimeout(timer); }
  };
  return {
    request: {
      // get() must also be able to carry a body, because GraphQL introspection
      // is issued over GET by several servers and the prober reuses this
      // context. Honour _method/data so a GET can behave as a POST when a
      // module only has `get` available.
      get: async (url, opts = {}) => {
        const method = opts._method || 'GET';
        return req(url, { ...opts, method });
      },
      fetch: async (url, opts = {}) => req(url, opts),
    },
  };
}

/** Resolve playwright from wherever it is installed, verifying the shape. */
function loadPlaywright() {
  const candidates = [
    'playwright',
    // A sibling checkout, which is how this repo is normally laid out.
    path.join(__dirname, '..', '..', 'webfuzz', 'node_modules', 'playwright'),
    path.join(__dirname, '..', 'node_modules', 'playwright'),
  ];
  // Honour an explicit install location first, then fall back to the common
  // paths above. Hardcoding one machine's home directory made the module
  // unusable anywhere else, so it is env-driven instead.
  const fromEnv = process.env.PLAYWRIGHT_MODULE || process.env.PENTHARNESS_PLAYWRIGHT;
  if (fromEnv) candidates.unshift(fromEnv);
  for (const c of candidates) {
    try {
      const m = require(c);
      // Verify it is really the library, not a transitive shim: the module
      // must expose chromium WITH a launch function.
      if (m && m.chromium && typeof m.chromium.launch === 'function') return m;
    } catch { /* try next */ }
  }
  return null;
}

function readJson(f, dflt) { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return dflt; } }

module.exports = { hunt, slug, loadPlaywright };
