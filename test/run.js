'use strict';
/**
 * Harness tests. No framework — plain asserts so this runs anywhere.
 * Focus: the two pieces that carry the design (correlation, gating).
 */
const assert = require('assert');
const path = require('path');
const fs = require('fs');
const os = require('os');

const { LeadStore, makeLead, classify } = require('../src/leads');
const N = require('../src/normalize');
const { correlate, composes } = require('../src/correlate');
const { evaluate, toFinding, triagePrompt } = require('../src/gate');
const { TargetKB } = require('../src/knowledge');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log(`  ok  ${name}`); pass++; }
  catch (e) { console.log(`  FAIL ${name}\n       ${e.message}`); fail++; }
}

console.log('\n== leads ==');
t('classifies sqli as injection', () => assert.strictEqual(classify('SQL Injection in q'), 'injection'));
t('classifies idor as authz', () => assert.strictEqual(classify('IDOR / Broken Access Control'), 'authz'));
t('classifies agent card idor as ai when tagged', () => {
  const l = makeLead({ title: 'agent metadata IDOR', category: 'ai', cls: 'ai' });
  assert.strictEqual(l.cls, 'ai');
});
t('leads are NOT findings: no severity is asserted as fact', () => {
  const l = makeLead({ title: 'SQL Injection', url: 'https://x/?q=1' });
  assert.strictEqual(l.severity_hint, 'info', 'a raw lead must default to info, not high');
  assert.strictEqual(l.confidence, 'unverified');
});
t('priority orders authz above config', () => {
  const a = makeLead({ cls: 'authz', title: 'x' });
  const b = makeLead({ cls: 'config', title: 'y' });
  assert.ok(a.priority > b.priority);
});
t('re-observing a lead raises confidence, not severity', () => {
  const s = new LeadStore();
  const a = s.add({ cls: 'xss', title: 'reflected', url: 'https://x/?q=1', severity_hint: 'low' });
  const b = s.add({ cls: 'xss', title: 'reflected', url: 'https://x/?q=1', severity_hint: 'critical' });
  assert.strictEqual(b.severity_hint, a.severity_hint, 'severity must not be escalated by repetition');
  assert.strictEqual(b.observations, 2);
});
t('extracts param from url for correlation', () => {
  assert.strictEqual(makeLead({ title: 't', url: 'https://x/ads/?q=1&id=2' }).param, 'q');
});

console.log('\n== normalizers ==');
t('nuclei jsonl -> leads', () => {
  const raw = '{"templateID":"expo","info":{"name":"Exposed .env","severity":"high","tags":["exposure"]},"matched_at":"https://t/.env"}\n{"templateID":"sqli","info":{"name":"SQLi","severity":"high"},"matched_at":"https://t/?id=1"}';
  const l = N.ingest('nuclei', raw);
  assert.strictEqual(l.length, 2);
  assert.ok(l.some((x) => x.cls === 'injection'));
});
t('webfuzz report -> leads, and info stays info', () => {
  const raw = { findings: [{ title: 'Missing security headers', category: 'Security Headers', severity: 'info', url: 'https://t/', evidence: 'no CSP' }] };
  const l = N.ingest('webfuzz', raw);
  assert.strictEqual(l.length, 1);
  assert.strictEqual(l[0].severity_hint, 'info');
});
t('malformed input yields zero leads, never throws', () => {
  assert.strictEqual(N.ingest('nuclei', 'not json at all').length, 0);
  assert.strictEqual(N.ingest('webfuzz', '{broken').length, 0);
  assert.strictEqual(N.ingest('unknowntool', '{}').length, 0);
});
t('arjun hidden params become recon leads with injection hint', () => {
  const raw = { results: { 'https://t/x': { params: ['debug', 'role'] } } };
  const l = N.ingest('arjun', raw);
  assert.strictEqual(l.length, 2);
  assert.ok(l[0].chain_hints.includes('injection'));
});

console.log('\n== correlation ==');
t('leaked secret + authz on same asset -> chain', () => {
  const s = new LeadStore();
  s.add({ cls: 'secrets', title: 'leaked API key', url: 'https://t/admin/keys', asset: 't' });
  s.add({ cls: 'authz', title: 'IDOR on /admin/users/{id}', url: 'https://t/admin/users/1', asset: 't' });
  const c = correlate(s);
  assert.ok(c.length >= 1, 'expected a chain');
  assert.ok(c[0].stages.includes('secrets') && c[0].stages.includes('authz'));
});
t('authz + ai tool path -> critical chain', () => {
  const s = new LeadStore();
  s.add({ cls: 'authz', title: 'agent card IDOR', url: 'https://t/api/agents/u1/card', asset: 't' });
  s.add({ cls: 'ai', title: '/execute invokes SSH tool as oracle', url: 'https://t/api/agents/u1/execute', asset: 't' });
  const c = correlate(s);
  assert.ok(c.length >= 1);
  assert.strictEqual(c[0].severity, 'critical');
});
t('different assets do NOT chain', () => {
  const a = { id: '1', cls: 'secrets', title: 'k', asset: 'a.com' };
  const b = { id: '2', cls: 'authz', title: 'i', asset: 'b.com' };
  assert.strictEqual(composes(a, b), null);
});
t('order matters: a must enable b, not the reverse', () => {
  const a = { id: '1', cls: 'authz', title: 'i', asset: 't' };
  const b = { id: '2', cls: 'secrets', title: 'k', asset: 't' };
  assert.strictEqual(composes(a, b), null, 'authz must not be a lead stage for secrets');
  assert.ok(composes(b, a), 'secrets must be a lead stage for authz');
});
t('unrelated classes on same asset do not chain', () => {
  const a = { id: '1', cls: 'xss', title: 'x', asset: 't' };
  const b = { id: '2', cls: 'config', title: 'c', asset: 't' };
  assert.strictEqual(composes(a, b), null);
});
t('chain carries per-step proof requirements', () => {
  const s = new LeadStore();
  s.add({ cls: 'injection', title: 'sqli id', url: 'https://t/?id=1', asset: 't' });
  s.add({ cls: 'authz', title: 'admin bypass', url: 'https://t/admin', asset: 't' });
  const c = correlate(s);
  assert.ok(c[0].steps.every((st) => Array.isArray(st.proof_needed) && st.proof_needed.length));
});

console.log('\n== gate ==');
t('a bare lead does not pass the gate', () => {
  const v = evaluate({ cls: 'injection', severity: 'high' });
  assert.strictEqual(v.verdict, 'hold');
  assert.ok(v.missing.some((m) => m.startsWith('proof')));
});
t('reflection without execution is dropped', () => {
  const v = evaluate({ cls: 'xss', proof: 'payload reflected in source, not executed', impact: 'session theft', by_design: 'not intended', reproduction: 'y' });
  assert.strictEqual(v.verdict, 'drop', 'unproven reflection must not ship');
});
t('identical-to-baseline is dropped', () => {
  const v = evaluate({ cls: 'injection', proof: 'response is identical to baseline, no difference', impact: 'read db', by_design: 'no', reproduction: 'y' });
  assert.strictEqual(v.verdict, 'drop');
  assert.ok(v.reasons.some((r) => r.startsWith('differential-noise')));
});
t('explicitly-none impact is dropped', () => {
  const v = evaluate({ cls: 'authz', proof: 'user B got 200 vs baseline 403', impact: 'none', by_design: 'x', reproduction: 'y' });
  assert.strictEqual(v.verdict, 'drop');
  assert.ok(v.reasons.some((r) => r.startsWith('impact-refuted')));
});
t('missing evidence is a HOLD, not a drop (recoverable)', () => {
  const v = evaluate({ cls: 'injection', severity: 'high' });
  assert.strictEqual(v.verdict, 'hold', 'incomplete work must stay in the queue');
  assert.strictEqual(v.reasons.length, 0);
});
t('a fully proven finding passes', () => {
  const v = evaluate({
    cls: 'injection', severity: 'high',
    proof: "payload ' OR 1=1 returned 5000 rows vs baseline 12 rows",
    impact: 'attacker reads all rows of the listings table including seller PII',
    by_design: 'search is documented as a literal LIKE match, not an expression evaluator',
    reproduction: 'GET /ads/?q=%27%20OR%201=1--',
  });
  assert.strictEqual(v.verdict, 'report', JSON.stringify(v));
});
t('exploitation class without baseline reference is flagged', () => {
  const v = evaluate({ cls: 'injection', proof: 'it worked and returned data', impact: 'reads the database', by_design: 'search is a literal match', reproduction: 'x' });
  assert.ok(v.notes.some((r) => /baseline\/control/.test(r)), 'missing baseline is an advisory, not a refutation');
  // An advisory must not downgrade an otherwise-complete finding.
  assert.strictEqual(v.verdict, 'report', 'advisories are guidance, not refutations');
});
t('negated execution is not read as execution', () => {
  const a = evaluate({ cls: 'xss', proof: 'payload reflected in source, not executed', impact: 'session theft', by_design: 'not intended', reproduction: 'y' });
  assert.strictEqual(a.verdict, 'drop', '"not executed" must count as unproven');
  const b = evaluate({ cls: 'xss', proof: 'payload reflected and executed in the target origin', impact: 'session theft', by_design: 'not intended', reproduction: 'y' });
  assert.strictEqual(b.verdict, 'report', 'genuine execution must be reportable');
});
t('toFinding refuses to emit an unproven finding', () => {
  const lead = makeLead({ cls: 'injection', title: 'sqli', url: 'https://t/?id=1' });
  const r = toFinding(lead, { proof: 'reflected' });
  assert.strictEqual(r.ok, false);
});
t('toFinding emits contract shape when proven', () => {
  const lead = makeLead({ cls: 'authz', title: 'IDOR', url: 'https://t/u/2' });
  const r = toFinding(lead, {
    severity: 'high', impact: 'reads other users private invoices', by_design: 'no ownership check documented',
    reproduction: 'GET /api/invoice/2 with user B cookie', proof: 'user B retrieved user A invoice vs baseline 403',
  });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.finding.type, 'finding');
  assert.ok(r.finding.tool_used);
});
t('triage prompt is a bounded single question', () => {
  const p = triagePrompt(makeLead({ cls: 'authz', title: 'IDOR', url: 'https://t/u/1', evidence: '403->200' }));
  assert.ok(p.length < 1200);
  assert.ok(/impact/i.test(p) && /by.design/i.test(p));
});

console.log('\n== knowledge (compounding) ==');
t('kb persists and reloads endpoints + params', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ph-'));
  const f = path.join(dir, 'kb.json');
  const kb = new TargetKB('t');
  kb.learnTech(['Django', 'nginx']);
  kb.learnEndpoint('https://t/ads/?q=1', { param: 'q' });
  kb.learnAuth({ observed: true, cookies: ['sessionid'] });
  kb.addNegative('sqli', 'https://t/ads/?q=', 'identical to baseline');
  kb.save(f);
  const kb2 = TargetKB.load(f);
  assert.ok(kb2.tech.has('django'));
  assert.strictEqual(kb2.untestedParams(['q', 'id']).length, 1);
  assert.ok(kb2.wasTested('sqli', 'https://t/ads/?q='), 'negative result must be remembered');
  fs.rmSync(dir, { recursive: true, force: true });
});
t('injection surface excludes rate-limited endpoints', () => {
  const kb = new TargetKB('t');
  kb.learnEndpoint('https://t/a?q=1', { param: 'q' });
  kb.learnEndpoint('https://t/b?id=1', { param: 'id' });
  kb.markRateLimited('https://t/b?id=1');
  const surf = kb.injectionSurface();
  assert.strictEqual(surf.length, 1);
  assert.ok(surf[0].url.includes('/a'));
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
