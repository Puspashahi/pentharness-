'use strict';
/**
 * Tests for the high-value report patterns:
 *   postmessage — 2 of the 5 largest recent web payouts
 *   enumerate   — the $78k "counter going up by one"
 *   identity    — automated dual-session provisioning
 */
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const PM = require('../src/postmessage');
const EN = require('../src/enumerate');
const ID = require('../src/identity');
const { readCapture } = require('../src/capture-io');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log(`  ok  ${name}`); pass++; }
  catch (e) { console.log(`  FAIL ${name}\n       ${e.message}`); fail++; }
}

console.log('\n== postmessage: the two payout shapes ==');
t('NO origin check reaching a sink is critical', () => {
  const js = `addEventListener('message', function(e){ document.getElementById('x').innerHTML = e.data.html; });`;
  const r = PM.analysePostMessage(js, { source: 'app.js' });
  assert.strictEqual(r.findings.length >= 1, true);
  assert.strictEqual(r.findings[0].severity_hint, 'critical', r.findings[0].title);
});
t('origin checked but payload trusted is the $62.5k shape', () => {
  const js = `addEventListener('message', function(e){
    if (e.origin === 'https://trusted.example') { el.innerHTML = e.data.body; }
  });`;
  const r = PM.analysePostMessage(js, { source: 'fbevents.js' });
  assert.strictEqual(r.findings.length, 1);
  assert.ok(/validates origin but not payload/.test(r.findings[0].title), r.findings[0].title);
  assert.strictEqual(r.findings[0].severity_hint, 'high');
  assert.ok(r.findings[0].proof_needed.length >= 3, 'must carry concrete proof steps');
});
t('origin + schema + nonce validated = no finding', () => {
  const js = `addEventListener('message', function(e){
    if (e.origin !== ALLOWED) return;
    if (!validateMessage(e.data)) return;
    if (e.data.nonce !== session.nonce) return;
    if (e.data.type !== 'ALLOWED_TYPE') return;
    el.innerHTML = sanitise(e.data.body);
  });`;
  const r = PM.analysePostMessage(js, { source: 'good.js' });
  assert.strictEqual(r.findings.length, 0, JSON.stringify(r.findings.map((f) => f.title)));
});
t('wildcard origin check is reported, whichever branch fires first', () => {
  const js = `addEventListener('message', (e) => { if (e.origin === '*') { el.innerHTML = e.data.x; } });`;
  const r = PM.analysePostMessage(js, { source: 'w.js' });
  // A literal '*' passes the origin test, so it lands in the "origin checked
  // but payload trusted" branch. Either way it must be reported, not dropped.
  assert.ok(r.findings.length >= 1, JSON.stringify(r.findings.map((f) => f.title)));
  assert.ok(/innerHTML/.test(r.findings[0].title + r.findings[0].evidence), r.findings[0].title);
});
t('eval relay into a trusted origin is caught', () => {
  const js = `window.addEventListener("message", function(ev){ if (ev.origin === 'https://p.com') { eval(ev.data.cmd); } });`;
  const r = PM.analysePostMessage(js, { source: 'relay.js' });
  assert.ok(r.findings.length >= 1);
});
t('relaying postMessage to an attacker window is flagged', () => {
  const js = `function send(target, data){ target.postMessage(data, '*'); } window.frames[0].postMessage(payload, origin);`;
  const r = PM.analysePostMessage(js, { source: 'relay2.js' });
  assert.ok(r.stats.postCallsites >= 2, 'call sites counted: ' + r.stats.postCallsites);
});
t('no message handlers = no findings, no crash', () => {
  const r = PM.analysePostMessage('const x = 1;', { source: 'x.js' });
  assert.strictEqual(r.findings.length, 0);
  assert.strictEqual(PM.analysePostMessage('', {}).findings.length, 0);
});

console.log('\n== enumerate: the $78k shape ==');
t('idShape detects a contiguous sequential range', () => {
  const s = EN.idShape(['100', '101', '102', '103']);
  assert.strictEqual(s.kind, 'sequential');
  assert.strictEqual(s.enumerable, true);
  assert.strictEqual(s.range.contiguous, true);
});
t('idShape flags UUIDs as not directly enumerable', () => {
  const s = EN.idShape(['f47ac10b-58cc-4372-a567-0e02b2c3d479', '3f2504e0-4f89-11d3-9a0c-0305e82c3301']);
  assert.strictEqual(s.kind, 'uuid');
});
t('idParamOf reads a path identifier', () => {
  const s = EN.idParamOf('https://t/api/case/88213');
  assert.strictEqual(s.kind, 'path');
  assert.strictEqual(s.value, '88213');
});
t('idParamOf reads a query identifier', () => {
  assert.strictEqual(EN.idParamOf('https://t/api/x?id=42').value, '42');
  assert.strictEqual(EN.idParamOf('https://t/api/x?case=77').name, 'case');
});
t('withId substitutes a path id', () => {
  const spec = { kind: 'path', name: 'id' };
  assert.strictEqual(EN.withId('https://t/case/1', spec, 9), 'https://t/case/9');
});
t('withId substitutes a query id', () => {
  const spec = { kind: 'query', name: 'id' };
  assert.ok(EN.withId('https://t/x?a=1&id=2', spec, 7).includes('id=7'));
});
t('non-sequential ids are refused rather than brute-forced', async () => {
  const ctx = { request: { get: async () => ({ status: () => 200, text: async () => 'x' }) } };
  const r = await EN.enumerate(ctx, 'https://t/u/f47ac10b-58cc-4372-a567-0e02b2c3d479');
  assert.strictEqual(r.ok, false);
  assert.ok(/not sequential/.test(r.why), r.why);
});
t('a URL with no identifier is refused', async () => {
  const ctx = { request: { get: async () => ({ status: () => 200, text: async () => 'x' }) } };
  assert.strictEqual((await EN.enumerate(ctx, 'https://t/static/app.js')).ok, false);
});

t('enumeration measures reachability and does not extract a corpus', async () => {
  // Every adjacent ID returns a different owner's data.
  const ctx = { request: { get: async (url) => {
    const m = url.match(/\/case\/(\d+)/);
    const id = m ? m[1] : '1';
    const owner = id === '100' ? 'alice' : 'bob';
    const body = `<div>owner_id="${owner}@corp.test" case ${id} transcript</div>`;
    return { status: () => 200, text: async () => body };
  } } };
  const r = await EN.enumerate(ctx, 'https://t/case/100', { maxSamples: 5 });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.reachable, 5);
  assert.strictEqual(r.blastRadius, 100, '100% of adjacent IDs leak another identity');
});
t('scale drives severity: the low->78k upgrade', () => {
  const mk = (reachable, probes) => ({ ok: true, reachable, probes, blastRadius: Math.round(reachable / probes * 100),
    idSpec: { name: 'id', value: '100' }, shape: { kind: 'sequential', range: { span: probes } },
    ownedStatus: 200, ownedLength: 500, samples: [] });
  assert.strictEqual(EN.toLead('https://t/case/100', mk(10, 10)).severity_hint, 'critical');
  assert.strictEqual(EN.toLead('https://t/case/100', mk(5, 10)).severity_hint, 'high');
  assert.strictEqual(EN.toLead('https://t/case/100', mk(2, 10)).severity_hint, 'medium');
  assert.strictEqual(EN.toLead('https://t/case/100', mk(0, 10)), null, 'no leak = no finding');
});
t('a lead names scale as the impact metric', () => {
  const r = { ok: true, reachable: 9, probes: 10, blastRadius: 90, idSpec: { name: 'id', value: '5' },
    shape: { kind: 'sequential', range: { span: 10, contiguous: true } }, ownedStatus: 200, ownedLength: 900,
    samples: [{ id: 6, carriesOtherIdentity: true }, { id: 7, carriesOtherIdentity: true }] };
  const l = EN.toLead('https://t/case/5', r);
  // The evidence must state the count, the ratio, and the samples.
  assert.ok(/10 adjacent IDs returned 9/.test(l.evidence), l.evidence);
  assert.ok(/90%/.test(l.evidence), l.evidence);
  assert.ok(/Samples: 6, 7/.test(l.evidence), l.evidence);
  assert.ok(/impact metric/.test(l.proof_needed.join(' ')));
});

console.log('\n== identity: automated provisioning ==');
t('reads and writes the shared capture format', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'cap-'));
  const f = path.join(d, 'userA.jsonl');
  const rows = [{ method: 'GET', url: 'https://t/a', status: 200, body: 'x' }];
  const { writeCaptureSafe } = require('../src/capture-io');
  writeCaptureSafe(f, rows, 'userA');
  const back = readCapture(f, 'userA');
  assert.strictEqual(back.length, 1);
  assert.strictEqual(back[0].identity, 'userA');
  fs.rmSync(d, { recursive: true, force: true });
});
t('two identities are required before the matrix is meaningful', () => {
  // The provisioning path is browser-driven, so assert the contract it must meet.
  assert.ok(typeof ID.provision === 'function');
  assert.ok(ID.ROUTES.includes('/account'));
  assert.ok(ID.ROUTES.some((r) => r.startsWith('/api/')));
});
t('the default route set covers the object surfaces that pay', () => {
  for (const r of ['/orders', '/invoices', '/tickets', '/cases']) {
    assert.ok(ID.ROUTES.includes(r), 'missing high-value route ' + r);
  }
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
