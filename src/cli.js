#!/usr/bin/env node
'use strict';
/**
 * pentharness — deterministic orchestration for AI-assisted pentesting.
 *
 * Design follows the pattern shared by Tenzai, PentestGPT and Shannon:
 *   - deterministic code owns scope, state, correlation and the report gate
 *   - the model reasons over a bounded queue of leads, not a wall of tool text
 *   - nothing becomes a finding without proof (Shannon: "No Exploit, No Report")
 *   - knowledge compounds across runs instead of being rediscovered
 *
 * Phases:
 *   recon   map the target (httpx/nuclei/katana/arjun) -> knowledge base
 *   scan    run detectors (webfuzz/nuclei) -> leads
 *   ingest  normalise any tool JSON dropped in --from
 *   correlate  build candidate attack chains from leads
 *   queue   emit the bounded attention queue for the model to reason over
 *   gate    apply the proof gate and emit findings.json
 *   report  full run of the above in order
 *
 * The harness NEVER decides that a vulnerability exists. It decides what is
 * worth the model's attention and what is allowed to ship.
 */
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');
const exec = promisify(execFile);

const { LeadStore, makeLead } = require('./leads');
const N = require('./normalize');
const { correlate } = require('./correlate');
const { evaluate, triagePrompt, toFinding } = require('./gate');
const { TargetKB } = require('./knowledge');
const predict = require('./predict');
const authmatrix = require('./authmatrix');
const jslogic = require('./jslogic');
const { CoverageLedger } = require('./coverage');
const { SuppressionLedger } = require('./suppress');
const V = require('./validators');
const { HeaderPolicy } = require('./headerpolicy');
const { hunt } = require('./hunt');

const STATE = path.join(__dirname, '..', 'state');
const C = { r: '\x1b[0m', b: '\x1b[1m', dim: '\x1b[2m', red: '\x1b[31m', yel: '\x1b[33m', grn: '\x1b[32m', cyn: '\x1b[36m' };

function parseArgs(argv) {
  const o = { target: null, phases: ['report'], from: [], maxPages: 20, timeout: 300000, out: null, noScan: false, answer: null, identity: [], js: null, prove: null, hunt: false, concurrency: 6, oobServer: null, skipProbe: false, accounts: null, loginUrl: null, passA: null, passB: null, maxEnum: 8, enumSamples: 12, skipProtocols: false, skipCache: false, oobOff: false, oobBin: 'interactsh-client', oobPollMs: 12000, authMode: 'form', recipe: null, researchHeader: [], ninja: null, throttle: 0 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i], next = () => argv[++i];
    switch (a) {
      case '--phase': o.phases = next().split(','); break;
      case '--from': o.from.push(next()); break;
      case '--max-pages': o.maxPages = parseInt(next(), 10) || o.maxPages; break;
      case '--timeout': o.timeout = parseInt(next(), 10) || o.timeout; break;
      case '--out': o.out = next(); break;
      case '--answer': o.answer = next(); break;
      case '--identity': o.identity.push(parseIdentity(next())); break;
      case '--js': o.js = next(); break;
      case '--prove': o.prove = next(); break;
      case '--hunt': o.hunt = true; break;
      case '--concurrency': o.concurrency = parseInt(next(), 10) || o.concurrency; break;
      case '--oob-server': o.oobServer = next(); break;
      case '--oob-off': o.oobOff = true; break;
      case '--oob-bin': o.oobBin = next(); break;
      case '--oob-poll-ms': o.oobPollMs = parseInt(next(), 10) || 0; break;
      case '--oauth': o.authMode = 'oauth'; break;
      case '--recipe': o.recipe = next(); break;
      // Program-mandated identification headers, e.g. a bug bounty's required
      // X-Request-Purpose. Repeatable: --research-header 'Name: value'.
      case '--research-header': o.researchHeader.push(next()); break;
      case '--ninja': o.ninja = next(); break;
      case '--throttle-per-min': o.throttle = parseInt(next(), 10) || 0; break;
      case '--skip-probe': o.skipProbe = true; break;
      case '--login': o.loginUrl = next(); break;
      case '--user-a': (o._uA = next()); break;
      case '--pass-a': o.passA = next(); break;
      case '--user-b': (o._uB = next()); break;
      case '--pass-b': o.passB = next(); break;
      case '--max-enum': o.maxEnum = parseInt(next(), 10) || 8; break;
      case '--enum-samples': o.enumSamples = parseInt(next(), 10) || 12; break;
      case '--skip-protocols': o.skipProtocols = true; break;
      case '--skip-cache': o.skipCache = true; break;
      case '--no-scan': o.noScan = true; break;
      case '-h': case '--help': o.help = true; break;
      default: if (!a.startsWith('-') && !o.target) o.target = a;
    }
  }
  return o;
}

function usage() {
  console.log(`
pentharness — deterministic harness for AI-assisted pentesting

  pentharness <target> [--hunt] [phases...]   # --hunt = one-command autonomous run
  pentharness <target> [--phase recon,scan,jslogic,prioritise,authz,prove,ingest,correlate,queue,gate,report]
               [--from tool.json ...] [--identity id=file ...] [--js PATH]
               [--max-pages N] [--timeout MS] [--answer FILE] [--prove FILE] [--no-scan]

Phases
  recon       map target with httpx / nuclei / katana / arjun -> knowledge base
  scan        run webfuzz + nuclei detectors -> leads
  jslogic     extract client-side auth logic from local JS bundles (--js)
  prioritise  rank known parameters by predicted vuln class -> plan.json
  authz       dual-identity response diffing -> the authorization matrix (--identity x2)
  prove       deterministic validators + adversarial refutation (--prove obs.json)
  ingest      normalise existing tool JSON passed with --from
  correlate   build candidate attack chains (shared asset/param/identity)
  queue       emit the bounded attention queue for LLM reasoning
  gate        apply the proof gate + coverage gate -> findings.json
  report      all of the above, in order

Examples
  # one command: map, predict, execute, prove, contest, chain, gate
  pentharness https://target.tld --hunt --concurrency 8

  # passive map only
  pentharness https://target.tld --phase recon

  # full run, then review the queue
  pentharness https://target.tld --report

  # access control, the highest-yield class: two identities, diffed
  pentharness https://target.tld --phase authz,correlate,queue \
      --identity userA=./cap-userA.jsonl --identity userB=./cap-userB.jsonl

  # validate observed responses: ships only what survives an adversary
  pentharness https://target.tld --phase prove,gate --prove ./observations.json

  # client-side auth logic + a targeted prioritised plan
  pentharness https://target.tld --phase jslogic,prioritise --js ./bundles

  # two real accounts, automatically logged in and diffed
  pentharness https://target.tld --hunt --login https://target.tld/login \
      --user-a alice@corp.test --pass-a 'pw' --user-b bob@corp.test --pass-b 'pw'

  # same, but through Okta/Azure/Google: keeps passwords out of shell history
  pentharness https://target.tld --hunt --oauth --recipe ./target.recipe.json

  # blind SSRF / command injection with real OOB callbacks
  pentharness https://target.tld --hunt --oob-poll-ms 15000
  pentharness https://target.tld --hunt --oob-off   # timing oracle, no infrastructure

  recipe.json:
    { "startUrl": "...", "appOrigin": "...",
      "accounts": { "userA": {"username":"a@corp.test","password":"pw"},
                    "userB": {"username":"b@corp.test","password":"pw"} },
      "selectors": { "ssoButton": ["Continue with Okta"], "userField": ["#username"] },
      "routes": ["/account","/invoices"] }

  # bug bounty program that mandates an identification header
  pentharness https://target.tld --hunt \
      --research-header 'X-Request-Purpose: BugcrowdResearch' \
      --ninja your_bugcrowd_username \
      --throttle-per-min 25

  # any program header can also come from the environment or the recipe file
  export PENTHARNESS_HEADERS=$'X-Request-Purpose: BugcrowdResearch'

Authorized targets only. Honour the program's scope, required headers and
rate limits. See the skill's /POLICY.md.
`);
}

const slug = (t) => String(t).replace(/^https?:\/\//, '').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 80);

/**
 * Choose URLs worth handing to arjun: ones that actually accept input.
 *
 * A bare homepage is a poor choice — arjun probes parameter differences and a
 * page with no form returns nothing, which reads as "tool broken" rather than
 * "no surface". Prefer routes that look interactive, or that already carry a
 * query string.
 */
function pickArjunTargets(target, o = {}, want = 2) {
  const candidates = [];
  try {
    const kbp = path.join(o.stateDir || path.join(__dirname, '..', 'state', slug(target)), 'knowledge.json');
    const kb = JSON.parse(fs.readFileSync(kbp, 'utf8'));
    // The KB persists endpoints as [url, meta] pairs (a Map serialised to JSON),
    // not as an object keyed by url. Handle both shapes.
    const raw = kb.endpoints || [];
    const entries = Array.isArray(raw) ? raw : Object.entries(raw);
    for (const e of entries) {
      const u = Array.isArray(e) ? e[0] : (typeof e === 'string' ? e : e.url);
      if (typeof u !== 'string') continue;
      let pathname = '';
      try { const p = new URL(u); pathname = p.pathname + p.search; } catch { continue; }
      const hasQuery = /[?&][^=]+=/.test(pathname);
      const interesting = hasQuery
        || /\b(search|query|find|lookup|filter|listing|listings|classifieds|post|posts|item|items|product|detail|profile|edit|add|create|upload|browse|category|tag)\b/i.test(pathname);
      const skip = /\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|pdf|zip|webmanifest|json|txt|xml)$/i.test(pathname)
        || /^\/(static|assets|media|images|dist|build|help-assistant)\//i.test(pathname);
      if (interesting && !skip) candidates.push(hasQuery ? u : `${u}${u.includes('?') ? '&' : '?'}q=test`);
    }
  } catch { /* no knowledge base yet: fall back to the origin */ }
  const uniq = [...new Set(candidates)];
  return uniq.length ? uniq.slice(0, want) : [target];
}

/**
 * Resolve a tool, preferring the ProjectDiscovery build when the plain name is
 * shadowed by an unrelated package. On this host `httpx` is HTTPie (a Python
 * HTTP client), which shares the name with ProjectDiscovery's prober but has
 * an incompatible CLI; the real prober is installed as `httpx-pd`.
 */
function resolve(bin) {
  if (bin === 'httpx') {
    const pd = whichSync('httpx-pd');
    if (pd) return pd;
  }
  return whichSync(bin) || bin;
}

function whichSync(b) {
  const dirs = (process.env.PATH || '').split(':');
  for (const d of dirs) {
    if (!d) continue;
    const p = path.join(d, b);
    try {
      // follow symlinks: several tools here are symlinks into venvs/opt dirs.
      // NOTE: fs.accessSync returns undefined on success, so the check must be
      // "did it throw", not the truthiness of the return value.
      fs.statSync(p);
      fs.accessSync(p, fs.constants.X_OK);
      return p;
    } catch { /* keep looking */ }
  }
  return null;
}

/** Run a tool if present; never let a missing/failing tool abort the phase. */
async function runTool(bin, args, timeout) {
  const real = resolve(bin);
  const child = exec(real, args, { timeout, maxBuffer: 64 * 1024 * 1024 });
  // Several Go/CLI tools (httpx, katana, nuclei) read stdin and block forever
  // when it is an open pipe with no writer. Closing it makes them exit
  // promptly; leaving it open silently burns the entire phase timeout.
  if (child.child && child.child.stdin) {
    child.child.on('error', () => {});
    child.child.stdin.end();
  }
  try {
    const { stdout, stderr } = await child;
    return { ok: true, stdout, stderr };
  } catch (e) {
    // A killed process can still have produced usable output on stdout. Many
    // crawlers stream results continuously and only hang at the end, so
    // partial output is signal, not failure.
    const stdout = e.stdout || '';
    return {
      ok: !e.killed && e.code === 0,
      partial: !!e.killed && stdout.length > 0,
      stdout,
      stderr: String(e.stderr || e.message || ''),
    };
  }
}

async function phaseRecon(o, kb, store) {
  const notes = [];
  const t = o.target;

  // httpx: liveness, tech, title, status.
  // No -follow-redirects: with it, httpx keeps the connection pool open and
  // never exits before the harness timeout, yielding no output at all.
  const hx = await runTool('httpx', ['-u', t, '-json', '-silent', '-no-color', '-td', '-tech-detect', ...(o.headerPolicy ? o.headerPolicy.flagsFor('httpx') : [])], o.timeout);
  const hxLeads = N.ingest('httpx', hx.stdout);
  for (const l of hxLeads) store.add(l);
  if (hxLeads[0]) {
    kb.learnTech((hxLeads[0].tags || []).map((x) => String(x).toLowerCase()));
    kb.learnEndpoint(hxLeads[0].url);
  }
  notes.push(`httpx: ${hxLeads.length} host lead(s)${hxLeads.length ? '' : toolNote(hx)}`);

  // katana: endpoint discovery, collapsed to unique route shapes
  const kat = await runTool('katana', ['-u', t, '-jsonl', '-silent', '-d', '2', '-jc', ...(o.headerPolicy ? o.headerPolicy.flagsFor('katana') : [])], o.timeout);
  const rawKat = N.ingest('spider', kat.stdout);
  const katC = N.dedupeCrawl(rawKat, { maxPaths: 60 });
  for (const l of katC.leads) { store.add(l); kb.learnEndpoint(l.url); }
  notes.push(`katana: ${rawKat.length} url(s) -> ${katC.uniqueShapes} route shape(s), kept ${katC.leads.length}`);

  // arjun: hidden parameters -> the injection surface.
  // `-oJ -` writes JSON to stdout; without the trailing `-` arjun treats `-oJ`
  // as taking an argument and exits with a usage error. arjun is slow, so it
  // gets a fraction of the phase budget and partial output is kept.
  //
  // Run it against URLs that actually take input, not the bare origin. Pointed
  // at a homepage it reports nothing and looks broken; pointed at a real search
  // or listing endpoint it recovers parameters the crawler never saw (on this
  // target: 28 of them, including url/target/website, which are SSRF-shaped).
  const arjTargets = pickArjunTargets(t, o, 2);
  const arjLeads = [];
  for (const at of arjTargets) {
    const arj = await runTool('arjun', ['-u', at, '-oJ', '-', '-m', 'GET,POST', '--stable', ...(o.headerPolicy ? o.headerPolicy.flagsFor('arjun') : [])], Math.min(o.timeout, 90000));
    arjLeads.push(...N.ingest('arjun', arj.stdout));
  }
  for (const l of arjLeads) { store.add(l); kb.learnEndpoint(l.url, { param: l.param }); }
  notes.push(`arjun: ${arjLeads.length} hidden param(s) on ${arjTargets.length} input-taking url(s): ${arjTargets.map((u) => u.replace(/^https?:\/\/[^/]+/, '') || '/').join(', ')}`);

  return notes;
}

/** Surface why a tool produced nothing, so silence is never mistaken for "clean". */
function toolNote(r) {
  if (!r) return '';
  if (r.partial) return ' (timed out — partial output used)';
  const err = String(r.stderr || '').trim().split('\n').filter(Boolean).slice(0, 1).join('');
  if (r.ok) return ' (no output)';
  return err ? ` (failed: ${err.replace(r.stderr && err.includes('Command failed') ? /^Command failed:\s*/ : '', '').slice(0, 70)})` : ' (failed)';
}

async function phaseScan(o, store, kb) {
  const notes = [];
  // webfuzz: browser-driven, so it reaches JS-rendered surfaces
  const wf = path.join(__dirname, '..', '..', 'webfuzz', 'src', 'cli.js');
  if (fs.existsSync(wf)) {
    const wfOut = path.join(STATE, slug(o.target), 'webfuzz');
    const r = await runTool('node', [wf, o.target, '--vulns', '--max-pages', String(Math.min(o.maxPages, 10)), '--out', wfOut], o.timeout);
    const rep = path.join(wfOut, 'report.json');
  // webfuzz leads: learn their endpoints/params so the injection surface and
  // the compounding knowledge base include them on later runs.
  if (fs.existsSync(rep)) {
    const leads = N.ingest('webfuzz', fs.readFileSync(rep, 'utf8'));
    for (const l of leads) { store.add(l); kb.learnEndpoint(l.url, { param: l.param }); }
    notes.push(`webfuzz: ${leads.length} lead(s) -> ${rep}`);
  } else {
      notes.push('webfuzz: no report produced');
    }
  } else {
    notes.push('webfuzz: not found (skipped)');
  }

  // nuclei: broad detector sweep
  const nu = await runTool('nuclei', ['-u', o.target, '-jsonl', '-silent', '-no-color', '-severity', 'low,medium,high,critical', '-rate-limit', '20', ...(o.headerPolicy ? o.headerPolicy.flagsFor('nuclei') : [])], o.timeout);
  const nuLeads = N.ingest('nuclei', nu.stdout);
  for (const l of nuLeads) { store.add(l); kb.learnEndpoint(l.url, { param: l.param }); }
  notes.push(`nuclei: ${nuLeads.length} template match(es)${nuLeads.length ? '' : toolNote(nu)}`);

  return notes;
}

function phaseIngest(o, store, kb) {
  const notes = [];
  for (const f of o.from) {
    if (!fs.existsSync(f)) { notes.push(`${path.basename(f)}: missing`); continue; }
    const raw = fs.readFileSync(f, 'utf8');
    // infer the tool from filename, or try each normalizer
    const base = path.basename(f).toLowerCase();
    const guess = base.includes('nuclei') ? 'nuclei'
      : base.includes('webfuzz') || base.includes('report') ? 'webfuzz'
      : base.includes('ffuf') ? 'ffuf'
      : base.includes('httpx') ? 'httpx'
      : base.includes('gitleaks') ? 'gitleaks'
      : base.includes('arjun') ? 'arjun'
      : null;
    const tools = guess ? [guess] : Object.keys(N.NORMALIZERS);
    let total = 0;
    for (const tool of tools) {
      const leads = N.ingest(tool, raw);
      if (leads.length) { for (const l of leads) { store.add(l); kb.learnEndpoint(l.url, { param: l.param }); } total += leads.length; }
    }
    notes.push(`${path.basename(f)}: ${total} lead(s)`);
  }
  return notes;
}

/**
 * Bounded projection for the model (PentestGPT pattern). The point of a bounded
 * queue is that every slot is worth reading. Bulk recon inventory (thousands of
 * crawled endpoints) is stored in the knowledge base, not the queue — it would
 * otherwise evict every actionable lead and teach the model that all pages look
 * the same.
 */
function buildQueue(store, chains, limit) {
  const items = [];
  const inChain = new Set();
  for (const c of chains) for (const s of c.steps) inChain.add(s.lead);

  for (const c of chains.slice(0, 8)) {
    items.push({ kind: 'chain', id: c.key, severity: c.severity, impact: c.impact, title: c.narrative, stages: c.stages, steps: c.steps });
  }

  const actionable = [];
  const reconCount = { total: 0, sampled: 0 };
  for (const l of store.all()) {
    if (l.cls === 'recon' && !l.chain_hints.length) { reconCount.total++; continue; }
    const v = evaluate({ cls: l.cls, severity: l.severity_hint, proof: l.evidence, impact: null, by_design: null, reproduction: null });
    actionable.push({
      kind: 'lead', id: l.id, cls: l.cls, priority: l.priority, title: l.title,
      url: l.url, param: l.param, source: l.source, gate: v.verdict,
      in_chain: inChain.has(l.id), prompt: triagePrompt(l),
    });
  }

  // Reserve a few slots so a brand-new target still shows its surface.
  const reconSample = [...store.byClass('recon')].filter((l) => l.chain_hints.length).slice(0, 3);
  reconCount.sampled = reconSample.length;

  const queue = [...items, ...actionable, ...reconSample.map((l) => ({
    kind: 'lead', id: l.id, cls: l.cls, priority: l.priority, title: l.title,
    url: l.url, param: l.param, source: l.source, gate: 'hold',
    in_chain: inChain.has(l.id), prompt: triagePrompt(l),
  }))];

  const out = queue.slice(0, limit);
  out.recon_suppressed = reconCount.total - reconCount.sampled;
  return out;
}

/**
 * Phase `prioritise` — turn known parameters into a ranked, class-aware test
 * plan. This is the "don't out-race, out-think" step: the parameter name tells
 * you which bug lives there, so you run the right mutation set instead of
 * blasting every probe at every parameter.
 */
function phasePrioritise(o, store, kb, coverage) {
  const notes = [];
  const params = [...new Set(store.all().map((l) => l.param).filter(Boolean))];
  // also pull every parameter seen anywhere in the knowledge base
  for (const e of kb.endpoints.values()) for (const p of e.params || []) params.push(p);
  const uniq = [...new Set(params)];

  const ranked = predict.rank(uniq);
  if (!ranked.length) {
    notes.push('no parameters known yet — run recon/scan first');
    return { notes, plan: [] };
  }

  const plan = ranked.map((r) => ({
    param: r.param,
    predict: r.classes,
    score: r.score,
    reason: r.reason,
    mutations: predict.mutationPlan(r.classes),
  }));

  // Authz-shaped parameters are the highest-yield surface in the current
  // market, so build their endpoints into the matrix plan.
  const authzParams = plan.filter((p) => p.predict.includes('authz'));
  if (authzParams.length) {
    for (const e of kb.endpoints.values()) {
      if ((e.params || []).some((p) => authzParams.some((a) => a.param === p))) coverage.endpoint(e.first_seen || '');
    }
  }

  fs.writeFileSync(path.join(STATE, slug(o.target), 'plan.json'), JSON.stringify(plan, null, 2));
  notes.push(`prioritise: ${plan.length} param(s) ranked; top = ${plan.slice(0, 3).map((p) => `${p.param}(${p.predict.join('/')})`).join(', ')}`);
  for (const p of authzParams.slice(0, 5)) coverage.param(p.param);
  return { notes, plan };
}

/**
 * Phase `authz` — the dual-identity authorization matrix.
 *
 * Requires two identities (e.g. two storage states / cookie jars). This is the
 * primitive every BAC guide converges on, and the one automated scanners cannot
 * do. Without a second identity we refuse to claim any authorization finding.
 */
async function phaseAuthz(o, store, kb, coverage, matrix) {
  const notes = [];
  const states = (o.identity || []).map((s) => ({ id: s.id, file: s.file }));
  if (states.length < 2) {
    notes.push('authz: SKIPPED — needs 2 identities (--identity id=file,id=file). Single-identity runs cannot prove access control.');
    return notes;
  }
  // Load each identity's captured requests (JSONL or JSON array of
  // {method,url,status,length,body,id}). Each file holds ONE identity.
  const sets = states.map((s) => ({ id: s.id, file: s.file, data: authmatrix.readCapture(path.resolve(s.file), s.id) }));
  for (const s of sets) {
    if (!s.data.length) { notes.push(`authz: ${s.id} has no usable rows in ${path.basename(s.file)}`); continue; }
    matrix.addIdentity(s.id);
    coverage.identity(s.id);
  }
  const all = sets.flatMap((s) => s.data.map((d) => ({ ...d, identity: d.identity || s.id })));
  if (all.length < 2) { notes.push('authz: not enough observations to diff'); return notes; }

  // Group identical (method,url) across identities and diff.
  const byReq = new Map();
  for (const o2 of all) {
    const k = `${o2.method} ${o2.url}`;
    if (!byReq.has(k)) byReq.set(k, []);
    byReq.get(k).push(o2);
  }
  // Learn each identity's own markers from the objects it is granted — but ONLY
  // from responses that do not themselves look like another identity's data.
  // Learning from a compromised response poisons the baseline: if an attacker
  // already reads alice's invoice, alice's email enters the attacker's "own"
  // set, and every subsequent real cross-identity read looks self-owned.
  // Mitigation: only accept markers seen in a response the identity was NOT
  // simultaneously allowed to read on another identity's request, and require
  // the marker set to be corroborated by at least one other granted response.
  const markerCounts = new Map();   // identity -> Map(marker -> count)
  for (const o2 of all) {
    if (o2.status < 200 || o2.status >= 300) continue;
    const m = authmatrix.ownershipMarkers(o2.body);
    if (!m.ids.size && !m.emails.size) continue;
    let agg = markerCounts.get(o2.identity);
    if (!agg) { agg = new Map(); markerCounts.set(o2.identity, agg); }
    for (const x of [...m.ids, ...m.emails]) agg.set(x, (agg.get(x) || 0) + 1);
  }
  // A marker shared across identities' payloads is ambiguous (leaked/shared
  // content), so it cannot establish ownership.
  const identityOfMarker = new Map();
  for (const [id, agg] of markerCounts) for (const m of agg.keys()) {
    if (!identityOfMarker.has(m)) identityOfMarker.set(m, new Set());
    identityOfMarker.get(m).add(id);
  }
  const ownMarkers = new Map();
  for (const [id, agg] of markerCounts) {
    const set = { ids: new Set(), emails: new Set() };
    for (const [m, n] of agg) {
      const holders = identityOfMarker.get(m);
      if (holders && holders.size > 1) continue;      // appears for several identities → not an ownership signal
      if (/^[^\s@]+@[^\s@]+$/.test(m)) set.emails.add(m); else set.ids.add(m);
    }
    if (set.ids.size || set.emails.size) ownMarkers.set(id, set);
  }

  let diffs = 0;
  for (const [k, obs] of byReq) {
    if (obs.length < 2) continue;
    const sp = k.indexOf(' ');
    const method = k.slice(0, sp);
    const fullUrl = k.slice(sp + 1);
    const pathname = fullUrl.replace(/^https?:\/\/[^/]+/, '');
    const qp = pathname.includes('?') ? pathname.split('?')[1].split('=')[0] : undefined;

    // Record every identity's observation on the same request shape, then diff
    // every ordered pair. Identity A's own view of an object is the baseline;
    // the breach is any *other* identity receiving that same object.
    for (const o2 of obs) {
      matrix.record({ method, path: pathname, lens: 'lowpriv', identity: o2.identity, status: o2.status, length: o2.length, expected: 'deny' });
    }
    // An identity is "denied somewhere" if it 401/403'd on ANY request shape in
    // this capture. The gate is a property of the resource, not of one URL — if
    // the same user is refused elsewhere in the surface, a 200 here for an
    // object they do not own is a genuine access-control gap, not public data.
    const deniedIdentities = new Set(
      all.filter((o) => o.status === 401 || o.status === 403).map((o) => o.identity),
    );

    for (let i = 0; i < obs.length; i++) {
      for (let j = 0; j < obs.length; j++) {
        if (i === j) continue;
        const owner = obs[i];      // identity that legitimately holds the object
        const other = obs[j];      // identity probing for it
        if (owner.identity === other.identity) continue;
        // The other identity must actually have been granted something.
        if (other.status < 200 || other.status >= 300) continue;
        if (owner.status < 200 || owner.status >= 300) continue;   // need a victim baseline

        // Objective proof: does B's payload carry A's identity markers? A 200 is
        // not an IDOR on its own — reading your own record is legitimate, and a
        // public endpoint returns 200 to everyone. The disclosure is proven when
        // the bytes handed to B name A as the owner.
        const xid = authmatrix.isCrossIdentityDisclosure(owner.body, other.body, other.identity, ownMarkers.get(other.identity));
        if (!xid.proven) continue;
        // Note: byte-identical bodies are NOT exculpatory. When B receives the
        // exact bytes A gets, and those bytes name A as owner, that is the
        // cleanest possible IDOR proof — so diffResponses is informational here,
        // never a filter.
        const d = authmatrix.diffResponses(owner, other);
        diffs++;
        const leak = authmatrix.identifierLeak(other.body, other.identity);
        const lead = makeLead({
          cls: 'authz',
          title: `Cross-identity disclosure: ${other.identity} received ${other.status} on ${method} ${pathname}, an object owned by ${owner.identity}`,
          url: fullUrl,
          param: qp,
          source: 'authmatrix',
          severity_hint: 'high',
          identity: other.identity,
          evidence: `${xid.reason}. owner ${owner.identity} status=${owner.status} len=${owner.length}; ${other.identity} status=${other.status} len=${other.length}.${deniedIdentities.has(other.identity) ? ` ${other.identity} is denied elsewhere in this surface, confirming the resource is gated.` : ` Note: ${other.identity} was not observed being denied elsewhere; confirm the object is intended to be private.`}${leak ? ` Body also exposes object identifiers (${leak.kinds.join(', ')}).` : ''}`,
          proof_needed: [
            `show the body returned to ${other.identity} names ${owner.identity} as owner/author`,
            'show the same request is denied (401/403) for an identity unrelated to the object',
            'record the exact curl reproduction with each identity\'s cookie',
          ],
        });
        store.add(lead);
        coverage.lens('identity-diff');
        if (leak) {
          store.add(makeLead({
            cls: 'recon',
            title: `Identifier leak endpoint: ${pathname} returns object references usable across identities`,
            url: fullUrl,
            source: 'authmatrix',
            severity_hint: 'low',
            evidence: `${leak.count} identifier(s) of kinds ${leak.kinds.join(', ')}; samples ${leak.samples.join(', ')}`,
            chain_hints: ['authz'],
          }));
        }
      }
    }
  }
  notes.push(`authz: ${byReq.size} request shape(s) across ${matrix.identities.size} identities, ${diffs} differential(s)`);
  const mfind = matrix.evaluate();
  for (const f of mfind) if (!store.all().some((l) => l.title === f.title)) store.add(f);
  if (mfind.length) notes.push(`authz: ${mfind.length} authorization-matrix breach cell(s)`);
  return notes;
}

/**
 * Phase `jslogic` — extract client-side authorisation logic from bundles.
 * Requires a local path (a checkout, a downloaded bundle dir, or a saved HAR's
 * JS). This finds what secret scanners structurally cannot: auth encoded in a
 * function rather than a key string.
 */
function phaseJsLogic(o, store, kb) {
  const notes = [];
  if (!o.js) { notes.push('jslogic: skipped (--js <path> to bundles)'); return notes; }
  const r = jslogic.scanPath(path.resolve(o.js));
  for (const l of r.leads) store.add(l);
  const sigs = r.analyses.reduce((n, a) => n + (a.signatures ? a.signatures.length : 0), 0);
  const priv = r.analyses.reduce((n, a) => n + (a.privilegeFields ? a.privilegeFields.length : 0), 0);
  notes.push(`jslogic: ${r.files} bundle(s), ${sigs} client auth header(s), ${priv} privilege field(s), ${r.leads.length} lead(s)`);
  // Feed discovered absolute URLs and admin endpoints into the KB.
  for (const a of r.analyses) {
    for (const u of a.urls || []) kb.learnEndpoint(u);
    for (const e of a.adminEndpoints || []) kb.learnEndpoint(o.target.replace(/\/$/, '') + e);
  }
  return notes;
}

/** --identity id=path/to/capture.json (repeatable) */
function parseIdentity(spec) {
  const s = String(spec || '');
  const m = s.match(/^([^=]+)=(.+)$/);
  const out = m ? { id: m[1], file: m[2] } : { id: path.basename(s), file: s };
  if (!out.file) { out.file = s; out.id = s || 'identity'; }
  return out;
}

/**
 * Phase `prove` — deterministic validation.
 *
 * Consumes a JSON file of *observed* responses (not hypotheses) and runs each
 * through the non-AI validators plus an adversarial refutation pass. This is
 * the PageBreak pattern: the agent proposes, deterministic code disposes.
 *
 * Input file shape:
 * {
 *   "injection": { "url": "...", "param": "q",
 *                  "baseline": {"status":200,"body":"...","ms":120},
 *                  "injected":  {"status":200,"body":"...","ms":3700},
 *                  "booleanTrue": {...}, "booleanFalse": {...} },
 *   "xss":       { "reflected": true, "execution": {"executed": true, "origin": "https://t"} },
 *   "authz":     { "disclosure": {"proven": true, "reason": "..."} }
 * }
 *
 * Only entries that BOTH pass their validator AND survive refutation are marked
 * proven. Everything else is recorded with the reason it did not.
 */
async function phaseProve(o, store, dir) {
  const notes = [];
  if (!o.prove) { notes.push('prove: skipped (--prove observations.json)'); return notes; }
  const f = path.resolve(o.prove);
  if (!fs.existsSync(f)) { notes.push(`prove: ${path.basename(f)} not found`); return notes; }
  let obs;
  try { obs = JSON.parse(fs.readFileSync(f, 'utf8')); }
  catch (e) { notes.push(`prove: cannot parse ${path.basename(f)}: ${e.message}`); return notes; }

  const results = [];
  let proven = 0, refuted = 0, hypothesis = 0;

  for (const [cls, evidence] of Object.entries(obs)) {
    if (!evidence || typeof evidence !== 'object') continue;
    // Fold a paired baseline/injected into the validator's expected shape.
    const ev = { ...evidence };
    if (ev.baseline && ev.injected) {
      if (ev.injected.ms != null && ev.baseline.ms != null) ev.timing = { baseline: ev.baseline.ms, injected: ev.injected.ms };
      if (ev.baseline.body != null && ev.injected.body != null) {
        ev.errorBody = ev.injected.body;
        ev.errorIsEcho = String(ev.injected.body) === String(ev.baseline.body);
      }
    }
    const verdict = V.judge(cls, ev);
    const rec = {
      cls, url: evidence.url, param: evidence.param,
      verdict: verdict.verdict, confidence: verdict.confidence,
      ship: verdict.ship, why: verdict.why,
      refutation: verdict.refutation, evidence: verdict.validator && verdict.validator.evidence,
      questions: verdict.questions,
    };
    results.push(rec);
    if (verdict.verdict === 'proven' && verdict.ship) proven++;
    else if (verdict.verdict === 'refuted') refuted++;
    else hypothesis++;

    // Promote a proven, surviving observation into a lead.
    if (verdict.ship) {
      store.add(makeLead({
        cls,
        title: `PROVEN: ${evidence.title || `${cls} on ${evidence.url || 'target'}`}`,
        url: evidence.url,
        param: evidence.param,
        source: 'validator',
        severity_hint: evidence.severity || 'high',
        confidence: 'confirmed',
        evidence: `${verdict.why}\nRefutation: ${verdict.refutation.why}`,
        chain_hints: evidence.chain_hints || [],
        proof_needed: ['adjudication answers for the open questions'],
      }));
    }
  }

  const out = path.join(dir, 'proof.json');
  fs.writeFileSync(out, JSON.stringify({ run: V.NONCE, results }, null, 2));
  notes.push(`prove: ${proven} proven, ${refuted} refuted, ${hypothesis} hypothesis -> ${out}`);

  console.log(`${C.b}== proof (deterministic validators + adversary) ==${C.r}`);
  for (const r of results) {
    const col = r.ship ? C.grn : r.verdict === 'refuted' ? C.dim : C.yel;
    console.log(`  ${col}${r.verdict.padEnd(10)}${C.r} ${String(r.cls).padEnd(10)} ${r.why.slice(0, 96)}`);
  }
  console.log(`  ${C.dim}non-shippable candidates are retained in proof.json with the reason they failed${C.r}\n`);
  return notes;
}

/** One-command autonomous pipeline: map -> predict -> execute -> prove -> contest -> chain -> gate. */
async function runHunt(o) {
  const dir = path.join(STATE, slug(o.target));
  const res = await hunt({
    target: o.target, stateDir: dir,
    concurrency: o.concurrency, maxEndpoints: o.maxPages,
    oobServer: o.oobServer, oobOff: o.oobOff, oobBin: o.oobBin, oobPollMs: o.oobPollMs, identities: o.identity,
    answers: o.answer, timeoutMs: o.timeout, accounts: o.accounts, loginUrl: o.loginUrl, maxEnum: o.maxEnum, enumSamples: o.enumSamples, skipProtocols: o.skipProtocols, skipCache: o.skipCache, authMode: o.authMode, recipe: o.recipe, headerPolicy: o.headerPolicy,
    skipScan: o.noScan, skipProbe: o.skipProbe, headful: o.headful,
  });
  const b = C.b, dim = C.dim, cyn = C.cyn, grn = C.grn, yel = C.yel, r = C.r;
  console.log(`${b}${cyn}hunt${r} ${dim}${o.target}${r}  ${res.durationSec}s`);
  for (const s of res.steps) console.log(`  ${String(s.step).padEnd(9)} ${s.detail}`);

  console.log(`${b}== proof ==${r}  proven ${res.proof.proven}, refuted ${res.proof.refuted}, hypothesis ${res.proof.hypothesis}`);
  if (res.chains.length) {
    console.log(`${b}== chains ==${r}`);
    for (const c of res.chains.slice(0, 8)) console.log(`  [${c.severity}] ${c.narrative}`);
  }
  if (res.findings.length) {
    console.log(`${b}${grn}== findings (${res.findings.length}) ==${r}`);
    for (const f of res.findings) console.log(`  [${f.severity}] ${String(f.title).slice(0, 78)}`);
    console.log(`  ${dim}-> ${path.join(dir, 'findings.json')}${r}`);
  }
  console.log(`${dim}${res.coverage.statement}${r}`);
  if (!res.coverage.complete) {
    console.log(`${yel}do not present this as "no vulnerabilities found" — coverage is incomplete.${r}`);
  }
  return res;
}

async function main() {
  const o = parseArgs(process.argv.slice(2));
  // Credentials may be given in any flag order; assemble the account pairs
  // after parsing so --user-a/--pass-a interleave correctly.
  if (o._uA) { o.accounts = o.accounts || {}; o.accounts.userA = { username: o._uA, password: o.passA || '' }; }
  if (o._uB) { o.accounts = o.accounts || {}; o.accounts.userB = { username: o._uB, password: o.passB || '' }; }
  if (o._uA && !o.passA) console.log('  note: --pass-a not supplied; login may fail');
  if (o._uB && !o.passB) console.log('  note: --pass-b not supplied; login may fail');
  // A recipe file keeps credentials out of shell history and carries per-IdP
  // selectors; it supplies accounts/startUrl/selectors that flags do not.
  if (o.recipe) {
    try {
      const OA = require('./oauth');
      const rec = OA.loadRecipe(o.recipe);
      o.recipeData = rec;
      o.accounts = { ...(rec.accounts || {}), ...(o.accounts || {}) };
      if (rec.startUrl && !o.loginUrl) o.loginUrl = rec.startUrl;
      if (rec.selectors) o.selectors = rec.selectors;
      if (rec.routes) o.routes = rec.routes;
      if (!o.accounts.userA) { console.log('  note: recipe has no userA account; the authorization matrix needs two identities'); }
    } catch (e) {
      console.log(`  recipe error: ${e.message}`);
      return usage();
    }
  }
  // Build the program header policy. Sources, in increasing precedence:
  // environment, flags, then the recipe file.
  {
    const envH = process.env.PENTHARNESS_HEADERS || '';
    const fromEnv = envH.split(/\n+/).map((l) => l.trim()).filter(Boolean);
    const parsed = {};
    for (const line of [...fromEnv, ...(o.researchHeader || [])]) {
      const i = line.indexOf(':');
      if (i > 0) parsed[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    }
    if (o.ninja) {
      // Bugcrowd's optional identifying header.
      parsed['X-Bugcrowd-Ninja'] = o.ninja;
    }
    if (o.recipeData && o.recipeData.headers) Object.assign(parsed, o.recipeData.headers);
    o.headerPolicy = new HeaderPolicy({ headers: parsed, throttle: o.throttle });
    if (o.headerPolicy.active) console.log(`  headers: ${o.headerPolicy.describe()}`);
    if (o.throttle) console.log(`  throttle: max ${o.throttle} requests/minute`);
  }
  if (o.help || !o.target) return usage();

  // `--hunt` (or bare `hunt`) is the one-command entry point.
  if (o.hunt || process.argv.includes('hunt')) return runHunt(o);
  let host = o.target;
  try { host = new URL(o.target).hostname; } catch { /* keep as-is */ }

  const dir = path.join(STATE, slug(o.target));
  fs.mkdirSync(dir, { recursive: true });
  const kbPath = path.join(dir, 'knowledge.json');
  const leadsPath = path.join(dir, 'leads.json');
  const kb = TargetKB.load(kbPath) || new TargetKB(o.target);
  const store = LeadStore.fromJSON(fs.existsSync(leadsPath) ? JSON.parse(fs.readFileSync(leadsPath, 'utf8')) : []);
  const coverage = new CoverageLedger();
  const matrix = new authmatrix.AuthorizationMatrix(o.target);
  const ledger = new SuppressionLedger();


  const notes = [];
  let runPhases = new Set(o.phases.length === 1 && o.phases[0] === 'report'
    ? ['recon', 'scan', 'jslogic', 'prioritise', 'authz', 'prove', 'ingest', 'correlate', 'queue', 'gate']
    : o.phases);

  for (const p of runPhases) coverage.phase(p);
  console.log(`${C.b}${C.cyn}pentharness${C.r} ${C.dim}target${C.r} ${o.target}`);
  console.log(`${C.dim}phases${C.r} ${[...runPhases].join(' -> ')}`);
  const prior = kb.endpoints.size;
  console.log(`${C.dim}kb${C.r}     ${prior} endpoint(s) known from prior runs${C.r}\n`);

  if (runPhases.has('recon') && !o.noScan) notes.push(...await phaseRecon(o, kb, store));
  if (runPhases.has('scan') && !o.noScan) notes.push(...await phaseScan(o, store, kb));
  if (runPhases.has('jslogic')) notes.push(...phaseJsLogic(o, store, kb));
  if (runPhases.has('authz')) notes.push(...await phaseAuthz(o, store, kb, coverage, matrix));
  if (runPhases.has('prioritise')) notes.push(...phasePrioritise(o, store, kb, coverage).notes);
  if (runPhases.has('prove')) notes.push(...await phaseProve(o, store, dir));
  if (runPhases.has('ingest')) notes.push(...phaseIngest(o, store, kb));

  // Record coverage for everything the scan phases actually touched.
  for (const p of store.all()) { if (p.url) coverage.endpoint(p.url); if (p.param) coverage.param(p.param); }
  if (o.maxPages) for (let i = 0; i < Math.min(o.maxPages, 5); i++) coverage.page(`${o.target}#${i}`);
  if (matrix.identities.size > 1) for (const l of matrix.identities) coverage.lens('identity-diff');

  const chains = correlate(store);
  if (runPhases.has('recon') || runPhases.has('scan') || runPhases.has('ingest') || runPhases.has('jslogic') || runPhases.has('authz') || runPhases.has('prioritise')) {
    for (const n of notes) console.log(`  ${n}`);
    console.log('');
  }

  store.toJSON && fs.writeFileSync(leadsPath, JSON.stringify(store.toJSON(), null, 2));
  kb.save(kbPath);

  if (runPhases.has('correlate')) {
    console.log(`${C.b}== chains (${chains.length}) ==${C.r}`);
    if (!chains.length) console.log(C.dim + '  none — leads do not compose' + C.r);
    for (const c of chains.slice(0, 12)) {
      console.log(`  [${C.yel}${c.severity}${C.r}] ${C.dim}len=${c.length} asset=${c.asset}${C.r}`);
      console.log(`         ${c.narrative}`);
    }
    console.log('');
  }

  if (runPhases.has('queue')) {
    const q = buildQueue(store, chains, 25);
    const qPath = path.join(dir, 'queue.json');
    fs.writeFileSync(qPath, JSON.stringify(q, null, 2));
    console.log(`${C.b}== attention queue (${q.length}) ==${C.r}  ${C.dim}-> ${qPath}${C.r}`);
    if (!q.length) {
      // An empty queue is a real result, but only if explained: it means recon
      // found surface and nothing actionable yet, not that the target is clean.
      const surf = kb.injectionSurface();
      console.log(`  ${C.dim}no actionable leads yet — ${store.size} lead(s) are all reconnaissance.${C.r}`);
      if (surf.length) {
        console.log(`  ${C.dim}${surf.length} endpoint(s) have parameters and are untested. Next: run --phase scan.${C.r}`);
        for (const s of surf.slice(0, 5)) console.log(`    ${s.url}  [${s.params.join(', ')}]`);
      } else {
        console.log(`  ${C.dim}Next: run --phase scan (webfuzz + nuclei) to generate detections.${C.r}`);
      }
    }
    for (const it of q.slice(0, 12)) {
      if (it.kind === 'chain') console.log(`  [chain ${it.severity}] ${it.title}`);
      else console.log(`  [lead ${it.cls}/${it.gate}] ${String(it.title).slice(0, 70)}`);
    }
    if (q.recon_suppressed > 0) console.log(`  ${C.dim}(${q.recon_suppressed} recon leads suppressed; see knowledge.json)${C.r}`);
    console.log('');
  }

  if (runPhases.has('gate')) {
    // --answer supplies the model's triage verdicts for specific leads. Without
    // them the gate can only report that nothing is proven yet, which is the
    // correct default: the harness does not decide truth.
    const answers = o.answer ? loadAnswers(o.answer) : {};
    let report = 0, hold = 0, drop = 0;
    const findings = [];
    for (const l of store.all()) {
      const ans = answers[l.id] || {};
      const res = toFinding(l, ans);
      if (res.ok) { report++; findings.push(res.finding); }
      else if (res.verdict.verdict === 'drop') {
        // Record the dismissal with its reason and evidence, so a reviewer can
        // tell a working filter from one that is discarding real issues.
        const reason = (res.verdict.reasons[0] || '').split(':')[0] || 'filtered';
        ledger.suppress(l, reason, { reasons: res.verdict.reasons });
        drop++;
      } else hold++;
    }
    console.log(`${C.b}== gate ==${C.r}`);
    console.log(`  ${C.grn}report-ready${C.r} ${report}   (proof + impact + by-design + reproduction)`);
    console.log(`  ${C.yel}hold${C.r}        ${hold}   (need proof / impact / by-design argument)`);
    console.log(`  ${C.dim}drop${C.r}        ${drop}   (${Object.keys(ledger.byReason()).join(', ') || 'none'})`);

    // Coverage gate: a partial run must never read as a complete assessment.
    const cov = coverage.assess();
    const covColor = cov.complete ? C.grn : C.yel;
    console.log(`\n  ${covColor}${coverage.statement()}${C.r}`);
    if (!cov.complete) {
      console.log(`  ${C.dim}Do not present these results as "no vulnerabilities found" — coverage is incomplete.${C.r}`);
    }

    if (ledger.entries.length) {
      console.log(`\n  ${C.dim}${ledger.statement()}${C.r}`);
      const wr = ledger.worthReviewing();
      if (wr.length) {
        console.log(`  ${C.yel}Worth a human look (tool asserted high/critical but the gate dropped them):${C.r}`);
        for (const e of wr.slice(0, 5)) console.log(`    [${e.severity_hint}] ${String(e.title).slice(0, 60)} — ${e.reason}`);
      }
    }

    if (findings.length) {
      const fp = path.join(dir, 'findings.json');
      fs.writeFileSync(fp, JSON.stringify(findings, null, 2));
      console.log(`\n  ${C.grn}${findings.length} finding(s) -> ${fp}${C.r}`);
      for (const f of findings) console.log(`    [${f.severity}] ${f.title}`);
      console.log(`\n  ${C.dim}Chain to /report, /gh-export, /remediate, /request-cves.${C.r}`);
    }

    fs.writeFileSync(path.join(dir, 'suppressed.json'), JSON.stringify(ledger.toJSON(), null, 2));
    fs.writeFileSync(path.join(dir, 'coverage.json'), JSON.stringify({ ...coverage.toJSON(), assessment: cov, statement: coverage.statement() }, null, 2));
    kb.endRun({ phases: [...runPhases], leads: store.size, chains: chains.length, reported: report, coverage: coverage.counts, complete: cov.complete });
    kb.save(kbPath);
    if (!findings.length) {
      console.log(`\n${C.dim}Next: answer the queue prompts, save as answers.json, re-run with --answer.`);
    }
    console.log(`State: ${dir}${C.r}`);
  }
}

/** answers.json: { "<lead-id>": { severity, impact, by_design, reproduction, proof, title } } */
function loadAnswers(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return {}; }
}

main().catch((e) => { console.error(`${C.red}harness error:${C.r} ${e.stack || e.message}`); process.exit(1); });
