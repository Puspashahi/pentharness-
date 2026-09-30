'use strict';
/**
 * Tests for the researched methodology modules:
 *   predict   — parameter name -> vulnerability class
 *   authmatrix — dual-identity diffing, confused-deputy mutations, ID leak
 *   jslogic   — client-side authorisation logic extraction
 *   coverage  — the "fail runs that didn't review enough surface" gate
 *   suppress  — filtered-noise vs suppressed-real-issue ledger
 */
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');

const P = require('../src/predict');
const AM = require('../src/authmatrix');
const JL = require('../src/jslogic');
const { CoverageLedger } = require('../src/coverage');
const { SuppressionLedger } = require('../src/suppress');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log(`  ok  ${name}`); pass++; }
  catch (e) { console.log(`  FAIL ${name}\n       ${e.message}`); fail++; }
}

console.log('\n== predict: parameter name -> class ==');
t('id= predicts IDOR/authz', () => {
  const r = P.predict('id');
  assert.ok(r.classes.includes('authz'), JSON.stringify(r));
  assert.ok(r.score >= 85);
});
t('user_id= predicts authz', () => assert.ok(P.predict('user_id').classes.includes('authz')));
t('invoice= predicts authz (object reference)', () => assert.ok(P.predict('invoice').classes.includes('authz')));
t('url= predicts SSRF', () => assert.ok(P.predict('url').classes.includes('ssrf')));
t('webhook= predicts SSRF', () => assert.ok(P.predict('webhook').classes.includes('ssrf')));
t('file= predicts traversal', () => assert.ok(P.predict('file').classes.includes('traversal')));
t('template= predicts traversal', () => assert.ok(P.predict('template').classes.includes('traversal')));
t('cmd= predicts injection', () => assert.ok(P.predict('cmd').classes.includes('injection')));
t('q= predicts xss+injection (reflected input)', () => {
  const r = P.predict('q');
  assert.ok(r.classes.includes('xss') && r.classes.includes('injection'));
});
t('role= predicts mass-assignment authz', () => {
  const r = P.predict('role');
  assert.ok(r.classes.includes('authz'));
  assert.ok(/mass assignment/i.test(r.reason), r.reason);
});
t('token= predicts authn', () => assert.ok(P.predict('token').classes.includes('authn')));
t('next= predicts open redirect', () => assert.ok(/redirect/i.test(P.predict('next').reason)));
t('file_id= resolves to authz, not SSRF (tokenised match)', () => {
  const r = P.predict('file_id');
  assert.ok(r.classes.includes('authz'), JSON.stringify(r));
});
t('utm_source is noise, not a testable param', () => {
  assert.strictEqual(P.predict('utm_source').is_noise, true);
});
t('xml content type makes XXE reachable regardless of name', () => {
  const r = P.predict('name', { contentType: 'application/xml' });
  assert.ok(/XXE/i.test(r.reason), r.reason);
});
t('numeric value in path implies an object reference', () => {
  const r = P.predict('opaque', { fromPath: true, value: '88213' });
  assert.ok(r.classes.includes('authz'));
});
t('rank sorts by expected yield, noise excluded', () => {
  const r = P.rank(['utm_source', 'cmd', 'id', 'url']);
  assert.ok(!r.some((x) => x.is_noise));
  assert.ok(r[0].score >= r[r.length - 1].score);
});
t('mutationPlan picks identity-swap for authz, not sqli', () => {
  const a = P.mutationPlan(P.predict('id').classes);
  assert.ok(a.includes('identity-swap') && a.includes('object-swap'));
  assert.ok(!a.includes('sqli-error'), 'authz must not trigger injection payloads');
});
t('mutationPlan picks sqli for injection params', () => {
  const a = P.mutationPlan(P.predict('cmd').classes);
  assert.ok(a.includes('sqli-error') || a.includes('ssti'));
});

console.log('\n== authmatrix: dual-identity diffing ==');
t('status difference is flagged', () => {
  const d = AM.diffResponses({ status: 200, length: 500 }, { status: 403, length: 120 });
  assert.strictEqual(d.differs, true);
  assert.strictEqual(d.severityBoost, true);
});
t('identical responses are not a breach', () => {
  const d = AM.diffResponses({ status: 200, body: 'x'.repeat(200) }, { status: 200, body: 'x'.repeat(200) });
  assert.strictEqual(d.differs, false);
});
t('same length but different body is a breach', () => {
  const d = AM.diffResponses({ status: 200, body: 'aaa' }, { status: 200, body: 'bbb' });
  assert.strictEqual(d.differs, true);
});
t('matrix produces an authz lead when a second identity is granted', () => {
  const m = new AM.AuthorizationMatrix('https://t');
  m.addIdentity('userA'); m.addIdentity('userB');
  m.record({ method: 'GET', path: '/api/invoice/1', lens: 'lowpriv', identity: 'userA', status: 403, length: 40, expected: 'deny' });
  m.record({ method: 'GET', path: '/api/invoice/1', lens: 'lowpriv', identity: 'userB', status: 200, length: 900, expected: 'deny' });
  const f = m.evaluate();
  assert.strictEqual(f.length, 1);
  assert.strictEqual(f[0].cls, 'authz');
  assert.ok(/userB/.test(f[0].title));
});
t('a public endpoint (granted to all) is not a breach', () => {
  const m = new AM.AuthorizationMatrix('https://t');
  m.addIdentity('userA'); m.addIdentity('userB');
  m.record({ path: '/api/public', lens: 'lowpriv', identity: 'userA', status: 200, expected: 'deny' });
  m.record({ path: '/api/public', lens: 'lowpriv', identity: 'userB', status: 200, expected: 'deny' });
  assert.strictEqual(m.evaluate().length, 0, 'no identity was denied, so it is public');
});
t('expected=allow endpoints never produce breaches', () => {
  const m = new AM.AuthorizationMatrix('https://t');
  m.addIdentity('userA');
  m.record({ path: '/api/me', lens: 'anon', identity: 'anon', status: 200, expected: 'allow' });
  assert.strictEqual(m.evaluate().length, 0);
});
t('confused-deputy set includes the documented mutations', () => {
  const ids = AM.CONFUSED_DEPUTY.map((m) => m.id);
  for (const want of ['null', 'undefined', 'empty', 'zero', 'negative', 'array-wrap', 'array-param', 'duplicate']) {
    assert.ok(ids.includes(want), `missing ${want}`);
  }
});
t('array-wrap produces a real JSON array', () => {
  const m = AM.CONFUSED_DEPUTY.find((x) => x.id === 'array-wrap');
  assert.strictEqual(m.apply('7'), '["7"]');
});
t('version downgrade finds v1 from v2', () => {
  assert.deepStrictEqual(AM.versionDowngrades('/api/v2/invoices'), ['/api/v1/invoices']);
});
t('version downgrade does not invent versions on non-versioned paths', () => {
  assert.deepStrictEqual(AM.versionDowngrades('/api/invoices'), []);
});
t('altPaths proposes internal/admin variants', () => {
  const p = AM.altPaths('/api/v2/user');
  assert.ok(p.some((x) => x.startsWith('/internal')));
  assert.ok(p.includes('/v2/user'), 'strips the /api prefix');
});
t('planFor runs the full method matrix on read endpoints', () => {
  assert.ok(AM.planFor({ path: '/api/u', method: 'GET' }).methods.includes('DELETE'));
  assert.ok(AM.planFor({ path: '/api/u', method: 'GET' }).lenses.length === 4);
});
t('identifierLeak spots UUIDs with ownership context', () => {
  const body = `<div>owner_id="f47ac10b-58cc-4372-a567-0e02b2c3d479" email="a@b.c" other="3f2504e0-4f89-11d3-9a0c-0305e82c3301">${'x'.repeat(200)}</div>`;
  const r = AM.identifierLeak(body, 'userA');
  assert.ok(r, 'expected a leak');
  assert.ok(r.kinds.includes('owned-object-reference'));
});
t('identifierLeak ignores pages with no object refs', () => {
  assert.strictEqual(AM.identifierLeak('<p>hello world</p>'.repeat(5), 'u'), null);
});

console.log('\n== jslogic: client-side auth logic ==');
const SAMPLE_JS = `
  function computeSignature(userId, ua, ts) {
    return sha256(userId + ua + ts);
  }
  function authHeaders() {
    return {
      "X-Admin-Signature": computeSignature(CURRENT_USER.id, navigator.userAgent, Date.now()),
      "X-Request-Id": uuid()
    };
  }
  if (user.role === 'admin') { showDeleteButton(); }
  const body = { id: 5, is_admin: true, tenant_id: 7, role: 'owner' };
  fetch('https://internal-api.corp.local/v2/orders');
  fetch('/api/admin/settings');
`;
t('finds client-computed auth header', () => {
  const a = JL.analyseJs(SAMPLE_JS, { source: 'app.js' });
  assert.ok(a.signatures.some((s) => s.header === 'x-admin-signature'), JSON.stringify(a.signatures));
});
t('finds the signature function', () => {
  const a = JL.analyseJs(SAMPLE_JS, { source: 'app.js' });
  assert.ok(a.signatureFuncs.some((f) => /computeSignature/i.test(f)), JSON.stringify(a.signatureFuncs));
});
t('finds client-side role checks', () => {
  const a = JL.analyseJs(SAMPLE_JS, { source: 'app.js' });
  assert.ok(a.roles.length > 0);
});
t('finds mass-assignment candidates', () => {
  const a = JL.analyseJs(SAMPLE_JS, { source: 'app.js' });
  for (const f of ['is_admin', 'tenant_id', 'role']) assert.ok(a.privilegeFields.includes(f), `missing ${f}: ${a.privilegeFields}`);
});
t('finds admin endpoints to prioritise', () => {
  const a = JL.analyseJs(SAMPLE_JS, { source: 'app.js' });
  assert.ok(a.adminEndpoints.some((e) => e.includes('/api/admin')));
});
t('surfaces internal hostnames but ignores public CDNs', () => {
  const a = JL.analyseJs(SAMPLE_JS + ' fetch("https://cdn.jsdelivr.net/npm/x");', { source: 'app.js' });
  assert.ok(a.urls.some((u) => u.includes('internal-api.corp.local')));
  assert.ok(!a.urls.some((u) => u.includes('jsdelivr')));
});
t('leads are produced with concrete proof requirements', () => {
  const leads = JL.leadsFromAnalysis(JL.analyseJs(SAMPLE_JS, { source: 'app.js' }), 'https://t');
  assert.ok(leads.length >= 3);
  assert.ok(leads.every((l) => Array.isArray(l.proof_needed) && l.proof_needed.length));
  assert.ok(leads.every((l) => l.confidence === 'unverified'));
});
t('scans a directory of bundles', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'jl-'));
  fs.writeFileSync(path.join(d, 'main.js'), SAMPLE_JS);
  fs.writeFileSync(path.join(d, 'vendor.min.js'), SAMPLE_JS);
  const r = JL.scanPath(d);
  assert.ok(r.files >= 1);
  assert.ok(r.leads.length > 0, 'minified bundles should be skipped, main.js analysed');
  fs.rmSync(d, { recursive: true, force: true });
});

console.log('\n== coverage gate ==');
t('recon-only run is incomplete', () => {
  const c = new CoverageLedger();
  c.phase('recon'); c.page('https://t/1'); c.page('https://t/2'); c.page('https://t/3');
  c.page('https://t/4'); c.page('https://t/5'); c.endpoint('https://t/a'); c.endpoint('https://t/b'); c.endpoint('https://t/c');
  const a = c.assess();
  assert.strictEqual(a.complete, false);
  assert.ok(a.gaps.some((g) => /scan phase/.test(g)), a.gaps.join('|'));
});
t('single-identity run cannot claim an authz-complete assessment', () => {
  const c = new CoverageLedger();
  c.phase('scan'); for (let i = 0; i < 6; i++) c.page(`https://t/${i}`);
  for (let i = 0; i < 4; i++) c.endpoint(`https://t/e${i}`);
  const a = c.assess();
  assert.ok(a.gaps.some((g) => /identities compared/.test(g)), a.gaps.join('|'));
});
t('a full multi-identity run with a scan phase is complete', () => {
  const c = new CoverageLedger();
  c.phase('scan'); for (let i = 0; i < 6; i++) c.page(`https://t/${i}`);
  for (let i = 0; i < 4; i++) c.endpoint(`https://t/e${i}`);
  c.lens('anon'); c.lens('lowpriv'); c.identity('userA'); c.identity('userB');
  assert.strictEqual(c.assess().complete, true, JSON.stringify(c.assess()));
});
t('an aborted run is never complete', () => {
  const c = new CoverageLedger();
  c.phase('scan'); c.abort('browser context closed');
  const a = c.assess();
  assert.strictEqual(a.complete, false);
  assert.ok(/aborted/.test(c.statement()));
});
t('statement warns that partial != clean', () => {
  const c = new CoverageLedger();
  c.phase('recon'); c.page('https://t/');
  assert.ok(/partial, not as an absence/i.test(c.statement()));
});

console.log('\n== suppression ledger ==');
t('records reason and counts by reason', () => {
  const s = new SuppressionLedger();
  s.suppress({ id: '1', title: 'a', severity_hint: 'info' }, 'third-party');
  s.suppress({ id: '2', title: 'b', severity_hint: 'info' }, 'third-party');
  s.suppress({ id: '3', title: 'c', severity_hint: 'info' }, 'reflection-only');
  assert.strictEqual(s.entries.length, 3);
  assert.strictEqual(s.byReason()['third-party'], 2);
});
t('flags suppressed high/critical leads for human review', () => {
  const s = new SuppressionLedger();
  s.suppress({ id: '1', title: 'maybe real', severity_hint: 'high' }, 'reflection-only');
  s.suppress({ id: '2', title: 'noise', severity_hint: 'info' }, 'third-party');
  assert.strictEqual(s.worthReviewing().length, 1);
  assert.ok(/warrant a human look/.test(s.statement()));
});
t('suppression preserves evidence for audit', () => {
  const s = new SuppressionLedger();
  s.suppress({ id: '1', title: 't', evidence: 'reflected in body' }, 'reflection-only');
  assert.ok(/reflected in body/.test(s.entries[0].evidence));
});


// ---- cross-identity disclosure: the objective IDOR proof ----
t('ownershipMarkers extracts owner_id and email', () => {
  const m = AM.ownershipMarkers('<div>owner_id="u-1" contact a@b.com</div>');
  assert.ok(m.ids.has('u-1'));
  assert.ok(m.emails.has('a@b.com'));
});
t('cross-identity disclosure proven when probe carries owner markers', () => {
  const r = AM.isCrossIdentityDisclosure('<div>owner_id=alice-1 a@x.com</div>', '<div>owner_id=alice-1 a@x.com</div>', 'userB');
  assert.strictEqual(r.proven, true, r.reason);
});
t('reading your own record is NOT a disclosure', () => {
  // The probe's own markers are what distinguish "my invoice" from "your invoice".
  const own = AM.ownershipMarkers('<div>owner_id=bob-2 b@x.com</div>');
  const r = AM.isCrossIdentityDisclosure('<div>owner_id=bob-2 b@x.com</div>', '<div>owner_id=bob-2 b@x.com</div>', 'userB', own);
  assert.strictEqual(r.proven, false, r.reason);
});
t('own-marker guard does not mask a real cross-identity read', () => {
  const own = AM.ownershipMarkers('<div>owner_id=bob-2 b@x.com</div>');
  const r = AM.isCrossIdentityDisclosure('<div>owner_id=alice-1 a@x.com</div>', '<div>owner_id=alice-1 a@x.com</div>', 'userB', own);
  assert.strictEqual(r.proven, true, r.reason);
});
t('public content with no identity markers is not a disclosure', () => {
  const r = AM.isCrossIdentityDisclosure('<h1>Catalogue</h1>', '<h1>Catalogue</h1>', 'userB');
  assert.strictEqual(r.proven, false);
});
t('probe payload naming a different owner is not proven', () => {
  const r = AM.isCrossIdentityDisclosure('<div>owner_id=alice-1</div>', '<div>owner_id=bob-2</div>', 'userB');
  assert.strictEqual(r.proven, false, r.reason);
});
t('readCapture parses JSONL capture files', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'cap-'));
  const f = path.join(d, 'u.jsonl');
  fs.writeFileSync(f, JSON.stringify({method:'GET',url:'https://t/a',status:200,body:'x'}) + '\n' + JSON.stringify({method:'GET',url:'https://t/b',status:403}) + '\n');
  const rows = AM.readCapture(f, 'userA');
  assert.strictEqual(rows.length, 2);
  assert.strictEqual(rows[0].identity, 'userA');
  assert.strictEqual(rows[1].status, 403);
  fs.rmSync(d, { recursive: true, force: true });
});
t('readCapture skips malformed lines instead of failing', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'cap-'));
  const f = path.join(d, 'u.jsonl');
  fs.writeFileSync(f, 'garbage\n' + JSON.stringify({url:'https://t/a',status:200}) + '\nnot json');
  assert.strictEqual(AM.readCapture(f, 'i').length, 1);
  fs.rmSync(d, { recursive: true, force: true });
});
t('readCapture returns empty for a missing file', () => {
  assert.deepStrictEqual(AM.readCapture('/nonexistent/x.jsonl', 'i'), []);
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
