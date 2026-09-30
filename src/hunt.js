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
const { LeadStore, makeLead } = require('./leads');
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
const jscapture = require('./jscapture');
const browser = require('./browser');
const identity = require('./identity');
const subdomains = require('./subdomains');
const takeover = require('./takeover');
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

  // The header policy is function-scoped: the map, scan, js, and protocol
  // phases all need it. It was previously declared inside `if (!o.skipScan)`,
  // which made the later phases throw "hp is not defined" whenever they ran.
  const hp = o.headerPolicy || new HeaderPolicy();
  hpRef = hp;

  // ---- 1. MAP (never hunt before mapping) ----
  coverage.phase('recon');
  if (!o.skipScan) {
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

  // ---- 0. SUBDOMAINS ----
  // Single-host testing is the practical ceiling on "works on any target": most
  // real findings sit on a host nobody links from the homepage. Enumeration is
  // scope-gated before a single request, because a program that scopes
  // "target.tld" usually does not mean every subdomain of it.
  if (!o.skipSubs && o.enumSubs !== false) {
    coverage.phase('subs');
    const subRes = await subdomainPhase(o, kb, store, coverage, log);
    if (subRes.totals.discovered) {
      log('subs', `${subRes.totals.discovered} discovered, ${subRes.totals.inScope} in scope, ${subRes.totals.outOfScope} out of scope, ${subRes.totals.thirdParty} third-party`);
      for (const h of subRes.inScope.slice(0, 10)) {
        log('  sub', `${String(h.score).padStart(3)}  https://${h.host}${h.title ? '  ' + h.title.slice(0, 40) : ''}${h.reasons.length ? '  (' + h.reasons[0] + ')' : ''}`);
      }
      if (subRes.outOfScope.length) log('subs', `${subRes.outOfScope.length} host(s) excluded by scope and never contacted`);

      // Takeover: only the hosts whose CNAME points at a third-party service
      // are candidates. Pointing at a CDN is normal configuration; only a
      // de-provisioned one is a finding, and that is verified per host.
      if (!o.skipTakeover && subRes.thirdParty.length) {
        coverage.phase('takeover');
        const candidates = subRes.thirdParty
          .filter((h) => takeover.fingerprintFor(h.cname))
          .map((h) => h.host);
        if (candidates.length) {
          log('takeover', `checking ${candidates.length} host(s) with a third-party CNAME (read-only DNS + GET)`);
          const toResults = await takeover.checkAll(candidates, {
            limit: o.maxTakeover || 40,
            delayMs: o.takeoverDelayMs || 250,
            timeout: 10000,
          });
          const toFindings = takeover.toFindings(toResults);
          const inconclusive = toResults.filter((r) => r.verdict === 'inconclusive').length;
          for (const f of toFindings) {
            log('  TAKEOVER', `${f.host} — ${f.provider} (${f.severity})`);
            store.add(makeLead({
              cls: 'subdomain-takeover', title: f.title, url: `https://${f.host}`,
              source: 'takeover', severity_hint: f.severity,
              evidence: f.evidence.join(' | ').slice(0, 400),
              tags: ['takeover', f.provider.toLowerCase().replace(/\W+/g, '-')],
            }));
            coverage.endpoint(`https://${f.host}`);
          }
          if (inconclusive) log('takeover', `${inconclusive} inconclusive — DNS/HTTP neither confirmed nor cleared`);
          log('takeover', `${toFindings.length} confirmed, ${inconclusive} inconclusive, ${toResults.length - toFindings.length - inconclusive} not vulnerable`);
        }
      }
    }
  }

  // ---- 1a. AUTHENTICATE FIRST ----
  // Authentication has to happen before any surface discovery, not after. An
  // anonymous crawl only ever sees the login page: no application JavaScript,
  // no forms beyond the sign-in one, no authenticated endpoints. Every
  // high-value finding lives behind auth, so the session is established up front
  // and every later phase reuses it.
  //
  // Only the FIRST usable identity is used for discovery. A second identity is
  // only needed later for the authorization diff, and using it here would
  // conflate "what the app exposes" with "what differs between users".
  let session = null;
  if (o.accounts && Object.keys(o.accounts).length && o.loginUrl) {
    coverage.phase('authenticate');
    const pwA = loadPlaywright();
    if (!pwA) {
      log('auth', 'playwright unavailable — cannot authenticate; discovery will be anonymous');
    } else {
      let bA = null;
      try {
        bA = await pwA.chromium.launch({ headless: !o.headful });
        const first = Object.keys(o.accounts)[0];
        const creds = o.accounts[first];
        const r = await identity.login(bA, o.loginUrl, creds, {
          headerPolicy: o.headerPolicy, timeout: o.timeoutMs || 30000,
          mode: o.authMode, selectors: o.selectors,
        }).catch((e) => ({ ok: false, reason: String(e.message || e).slice(0, 100) }));
        if (r.ok && r.storage) {
          session = { identity: first, storage: r.storage };
          o.storageState = r.storage;
          log('auth', `${first} authenticated (${r.storage.cookies.length} cookies) — JS, browser and crawl phases now run logged in`);
        } else {
          log('auth', `${first}: ${r.reason}`);
          if (r.blocked && r.blocked.length) log('auth', `blocked by ${r.blocked.join(', ')} — needs a human`);
        }
      } catch (e) {
        log('auth', `failed: ${String(e.message || e).slice(0, 100)}`);
      } finally {
        if (bA) await bA.close().catch(() => {});
      }
    }
  }

  // ---- 1b. JAVASCRIPT SURFACE ----
  // Read the JavaScript the application actually serves. Published hunter
  // methodology calls this the highest-yield single source: endpoints the
  // crawler never reaches, client-side-only authorization, and embedded
  // credentials all live here. The hunt previously probed HTTP but never read
  // a single bundle.
  if (!o.skipJs && !o.skipScan) {
    coverage.phase('js');
    const jsRes = await jsPhase(o, kb, store, coverage, log);
    if (jsRes.forms && jsRes.forms.length) log('js', `${jsRes.forms.length} form(s) parsed for parameters`);
    if (jsRes.scripts) {
      log('js', `${jsRes.scripts} script(s), ${(jsRes.bytes / 1024).toFixed(0)}KB, ${jsRes.minified} minified, ${jsRes.fromSourceMaps} from source maps`);
      log('js', `${jsRes.endpoints.length} endpoint(s) from JS (${jsRes.newEndpoints} never crawled before)`);
      for (const e of jsRes.endpoints.slice(0, 12)) log('  js', e);
    } else {
      log('js', 'no application scripts captured');
    }
    if (jsRes.secrets.length) {
      log('js', `${jsRes.secrets.length} embedded credential(s): ${[...new Set(jsRes.secrets.map((s) => s.kind))].join(', ')}`);
      for (const s of jsRes.secrets.slice(0, 5)) store.add(makeLead({
        cls: 'secrets', title: `Embedded ${s.kind} in ${String(s.url).replace(/^https?:\/\/[^/]+/, '')}`,
        url: s.url, source: 'js-analysis', severity_hint: 'high',
        evidence: `${s.kind} in client-side JavaScript (value truncated, never stored)`, tags: ['js', 'secret'],
      }));
    }
    coverage.lens('js-analysis');
  }

  // ---- 1c. BROWSER INTERACTION (click, fill, submit, inject) ----
  // This is what makes the single command a real assessment. An HTTP prober
  // cannot reach a surface that only exists after JavaScript runs or after
  // login, and the browser scanner that could was never called from --hunt at
  // all. Reuses the harvested session, so it sees the logged-in application.
  if (!o.skipBrowser && !o.skipScan) {
    coverage.phase('browser');
    const bRes = await browserPhase(o, kb, store, coverage, log);
    if (bRes.visited.length) {
      log('browser', `${bRes.visited.length} page(s) visited by clicking, ${bRes.forms.length} form(s) examined`);
      if (bRes.injected.length) {
        for (const inj of bRes.injected) {
          log('  found', `${inj.cls.toUpperCase()} candidate via form on ${String(inj.url).replace(/^https?:\/\/[^/]+/, '')} [field: ${inj.field}] status=${inj.status}${inj.errorSignature ? ` err=${inj.errorSignature}` : ''}`);
          store.add(makeLead({
            cls: inj.cls, title: `Browser-injected ${inj.cls} candidate in '${inj.field}'`,
            url: inj.url, source: 'browser-inject', severity_hint: inj.cls === 'sqli' || inj.cls === 'ssti' ? 'high' : 'medium',
            evidence: `form-submitted injection; status=${inj.status}; ${inj.errorSignature ? 'error signature: ' + inj.errorSignature : 'response differs from baseline'}`,
            tags: ['browser', inj.cls],
          }));
        }
      } else {
        log('browser', 'no form injection produced an observable effect');
      }
    } else {
      log('browser', 'no pages reachable in the browser');
    }
    coverage.lens('browser-interaction');
  }

  // ---- 2. PREDICT (slice the surface into ranked hypotheses) ----
  // Link parameters discovered on leads to the endpoints that carry them, so
  // the prober knows *where* to send each payload. Without this the prober has
  // parameters but no targets and silently probes nothing.
  for (const l of store.all()) {
    if (l.param && l.url) kb.learnEndpoint(l.url, { param: l.param });
  }

  // Harvest parameter names from every known URL, not only from leads that a
  // tool already parsed. This was the single biggest reason the hunt reported
  // "0 parameter(s) ranked": a crawled URL like /search?q=laptop carries a
  // usable parameter in its query string, but nothing extracted it, so the
  // predict -> execute chain never started. Without a ranked parameter there is
  // nothing to probe, and the run silently "found nothing" on a target that was
  // full of injectable endpoints.
  const params = [...new Set(store.all().map((l) => l.param).filter(Boolean))];
  const fromUrls = new Set();
  for (const e of kb.endpoints.values()) {
    for (const p of e.params || []) params.push(p);
    const names = paramsInUrl(e.url || '');
    for (const n of names) {
      fromUrls.add(n);
      if (!params.includes(n)) params.push(n);
    }
  }
  const ranked = predict.rank([...new Set(params)]);
  log('predict', `${ranked.length} parameter(s) ranked; top: ${ranked.slice(0, 4).map((r) => `${r.param}(${r.classes.join('/')})`).join(', ') || 'none'}`);
  if (fromUrls.size) log('predict', `${fromUrls.size} parameter name(s) harvested from crawled URLs`);
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
      mode: o.authMode, oauth: o.authMode === 'oauth', selectors: o.selectors, routes: o.routes, headerPolicy: o.headerPolicy, reuseStorage: session ? session.storage : null, reuseIdentity: session ? session.identity : null,
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
/**
 * Capture the target's JavaScript through a real browser and analyse it.
 *
 * A browser is required rather than a fetch loop: which bundles load depends on
 * the session and the route, so only driving the app reveals the JS behind the
 * features that matter.
 */
async function jsPhase(o, kb, store, coverage, log) {
  const empty = { scripts: 0, bytes: 0, minified: 0, fromSourceMaps: 0, endpoints: [], secrets: [], findings: [], newEndpoints: 0, forms: [] };
  const pw = loadPlaywright();
  if (!pw) { log('js', 'playwright unavailable — cannot capture scripts'); return empty; }

  const hp = o.headerPolicy || hpRef || new HeaderPolicy();
  let browser = null;
  try {
    browser = await pw.chromium.launch({ headless: !o.headful });
    const ctxOpts = { ignoreHTTPSErrors: true };
    if (hp.active) ctxOpts.extraHTTPHeaders = hp.playwright();
    const context = await browser.newContext(ctxOpts);
    // Reuse the session established in the auth phase. Without it this phase
    // only ever sees the login page's bundle, which is precisely the surface
    // least likely to hold a finding.
    if (o.storageState && o.storageState.cookies && o.storageState.cookies.length) {
      try { context.addCookies(o.storageState.cookies); } catch { /* fall back to anonymous */ }
    }
    const page = await context.newPage();
    // capture() performs the navigation itself: the response listener has to be
    // attached before the page loads or the bundles are already gone.
    const captured = await jscapture.capture(page, {
      url: o.target, maxScripts: o.maxScripts || 60, gotoTimeout: o.timeoutMs || 30000,
    });

    // Forms are where parameters live. A crawler sees <form action="/search"
    // method="get"> and records /search, but never submits it, so `?q=` is never
    // discovered — and on a target whose only injectable endpoint is behind a
    // search form, that single omission means the run reports nothing at all.
    // Reading the form's inputs directly recovers every field name and the
    // exact request the form would make.
    const forms = await page.evaluate(() => {
      const abs = (h) => { try { return new URL(h, location.href).toString(); } catch { return h; } };
      return [...document.querySelectorAll('form')].map((f) => ({
        action: abs(f.getAttribute('action') || location.href),
        method: (f.getAttribute('method') || 'GET').toUpperCase(),
        fields: [...f.querySelectorAll('input,select,textarea')]
          .filter((i) => ['hidden', 'text', 'email', 'password', 'search', 'number', 'submit', 'checkbox', 'radio'].includes((i.type || 'text').toLowerCase()))
          .map((i) => ({ name: i.name, type: i.type || 'text', placeholder: i.placeholder || '' }))
          .filter((i) => i.name),
      })).filter((f) => f.fields.length);
    }).catch(() => []);


    // Register the forms discovered above, including a concrete probe URL so
    // the prober has something to request. A GET form is expanded with a
    // benign value; a POST form is recorded as a shape for later.
    for (const f of forms) {
      if (!f || !f.action) continue;
      let probeUrl = f.action;
      if (f.method === 'GET' && f.fields.length) {
        try {
          const u = new URL(f.action);
          for (const fld of f.fields.slice(0, 6)) u.searchParams.set(fld.name, fld.type === 'password' ? 'x' : '1');
          probeUrl = u.toString();
        } catch { /* keep the bare action */ }
      }
      kb.learnEndpoint(probeUrl, { forms: 1 });
      for (const fld of f.fields) kb.learnEndpoint(f.action, { param: fld.name });
      coverage.endpoint(probeUrl);
      log('  form', `${f.method} ${f.action.replace(/^https?:\/\/[^/]+/, '')} [${f.fields.map((x) => x.name).slice(0, 6).join(', ')}]`);
    }
    const analysed = jscapture.analyseCapture(captured, o.target);

    // Only endpoints the crawler never saw are genuinely new surface.
    const known = new Set(kb.endpoints ? [...kb.endpoints.keys()].map((k) => { try { return JSON.parse(k)[0]; } catch { return k; } }) : []);
    const newOnes = analysed.endpoints.filter((u) => !known.has(u));
    analysed.newEndpoints = newOnes.length;

    for (const u of newOnes.slice(0, 200)) kb.learnEndpoint(u);
    for (const u of newOnes.slice(0, 40)) coverage.endpoint(u);
    for (const f of analysed.findings.slice(0, 20)) {
      store.add(makeLead({
        cls: 'jslogic', title: `Client-side auth logic: ${f.kind || f.title || 'signal'}`,
        url: f.script || o.target, source: 'js-analysis', severity_hint: 'medium',
        evidence: (f.detail || f.note || f.via || '').slice(0, 300), tags: ['js', 'client-side'],
      }));
    }
    return { ...analysed, endpoints: analysed.endpoints, forms: forms || [] };
  } catch (e) {
    log('js', `capture failed: ${String(e.message || e).slice(0, 120)}`);
    return empty;
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
}

/** Parameter names carried by a URL's query string or path segments. */
function paramsInUrl(u = '') {
  const out = [];
  try {
    const url = new URL(u);
    for (const k of url.searchParams.keys()) if (k && k.length < 60) out.push(k);
    // REST-style ids: /api/invoices/1 -> invoices is the resource, 1 is the id.
    for (const seg of url.pathname.split('/')) {
      if (/^\{?[a-z_][a-z0-9_]{1,40}\}?$/i.test(seg)) out.push(seg.replace(/[{}]/g, ''));
    }
  } catch { return []; }
  return [...new Set(out)];
}

/**
 * Drive a real browser: click through the app, submit forms, inject payloads,
 * and judge each result against a baseline request.
 *
 * Reuses a captured session when one exists, because an unauthenticated crawl
 * only ever sees the login page and the entire value of this phase is the
 * surface behind authentication.
 */
async function browserPhase(o, kb, store, coverage, log) {
  const empty = { visited: [], forms: [], endpoints: [], injected: [] };
  const pw = loadPlaywright();
  if (!pw) { log('browser', 'playwright unavailable — skipping browser interaction'); return empty; }
  const hp = o.headerPolicy || hpRef || new HeaderPolicy();

  let browserProc = null;
  try {
    browserProc = await pw.chromium.launch({ headless: !o.headful });
    const ctxOpts = { ignoreHTTPSErrors: true };
    if (hp.active) ctxOpts.extraHTTPHeaders = hp.playwright();
    if (o.storageState) ctxOpts.storageState = o.storageState;
    const context = await browserProc.newContext(ctxOpts);

    if (o.storageState && o.storageState.cookies && o.storageState.cookies.length) {
      log('browser', 'crawling with an authenticated session');
    }
    const page = await context.newPage();
    const res = await browser.crawl(page, o.target, {
      maxPages: o.maxBrowserPages || 12,
      maxDepth: o.maxBrowserDepth || 2,
      timeout: o.timeoutMs || 20000,
    });

    for (const u of res.endpoints) kb.learnEndpoint(u);
    for (const f of res.forms) {
      for (const fld of f.fields || []) kb.learnEndpoint(f.action, { param: fld, forms: 1 });
    }
    for (const u of res.endpoints.slice(0, 100)) coverage.endpoint(u);
    return res;
  } catch (e) {
    log('browser', `failed: ${String(e.message || e).slice(0, 120)}`);
    return empty;
  } finally {
    if (browserProc) await browserProc.close().catch(() => {});
  }
}

/** Discover subdomains, enforce scope, and record what is worth testing. */
async function subdomainPhase(o, kb, store, coverage, log) {
  const empty = { inScope: [], outOfScope: [], thirdParty: [], totals: { discovered: 0, inScope: 0, outOfScope: 0, thirdParty: 0 } };
  let host = '';
  try { host = new URL(o.target).hostname; } catch { return empty; }
  const domain = o.domain || host.replace(/^www\./, '');
  const scope = o.scope && o.scope.length ? o.scope : [domain];

  const sf = which('subfinder');
  if (!sf) { log('subs', 'subfinder not installed — skipping enumeration'); return empty; }

  let out = '';
  try {
    out = await run(sf, ['-d', domain, '-silent', '-all'], o.timeoutMs || 120000);
  } catch (e) {
    log('subs', `subfinder failed: ${String(e.message || e).slice(0, 80)}`);
    return empty;
  }
  const hosts = subdomains.parseSubfinder(out.stdout || out || '');
  if (!hosts.length) { log('subs', 'no subdomains discovered'); return empty; }

  const triaged = subdomains.triage(hosts, scope, new Map());
  for (const h of triaged.inScope) {
    kb.learnEndpoint(`https://${h.host}`);
    coverage.endpoint(`https://${h.host}`);
  }
  // High-value hosts become leads so the queue surfaces them.
  for (const h of triaged.inScope.slice(0, 20)) {
    store.add(makeLead({
      cls: 'recon', title: `Subdomain: ${h.host}${h.reasons.length ? ' — ' + h.reasons[0] : ''}`,
      url: `https://${h.host}`, source: 'subfinder', severity_hint: h.score >= 8 ? 'medium' : 'info',
      evidence: `score ${h.score}; discovered via ${h.source}${h.cname ? '; CNAME ' + h.cname : ''}`,
      tags: ['subdomain', ...(h.score >= 8 ? ['interesting'] : [])],
    }));
  }
  return triaged;
}

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
