'use strict';
const assert = require('assert');
const C = require('../src/change');

let pass = 0, fail = 0; const queue = [];
function t(n, f) { queue.push({ n, f }); }
async function drain() {
  for (const { n, f } of queue) {
    try { await f(); console.log(`  ok  ${n}`); pass++; }
    catch (e) { console.log(`  FAIL ${n}\n       ${(e && e.message) || e}`); fail++; }
  }
}
const kb = (urls) => ({ endpoints: new Map(urls.map((u) => [`["${u}",{}]`, { params: [] }])), params: new Set() });

console.log('\n== first run ==');
t('a baseline is recorded with an explicit next-step message', () => {
  const s = C.take('t.tld', kb(['https://t.tld/a']));
  const d = C.diff(s, null);
  assert.strictEqual(d.firstRun, true);
  assert.match(d.summary, /baseline/i);
});

console.log('\n== what changed ==');
t('new hosts, endpoints and params are detected', () => {
  const prev = C.take('t.tld', kb(['https://t.tld/a']));
  const cur = C.take('t.tld', kb(['https://t.tld/a', 'https://t.tld/b']));
  const d = C.diff(cur, prev);
  assert.strictEqual(d.newEndpoints.length, 1);
  assert.match(d.summary, /1 new endpoint/);
});
t('a stable, fully-probed target says so, quietly', () => {
  const s = C.take('t.tld', kb(['https://t.tld/a']));
  s.testedEndpoints = ['t.tld/a'];   // everything has been exercised
  const d = C.diff(s, s);
  assert.strictEqual(d.newEndpoints.length, 0);
  assert.strictEqual(d.untested.length, 0);
  assert.match(d.summary, /no change/i);
});
t('removed surface is reported too', () => {
  const prev = C.take('t.tld', kb(['https://t.tld/a', 'https://t.tld/gone']));
  const cur = C.take('t.tld', kb(['https://t.tld/a']));
  const d = C.diff(cur, prev);
  assert.strictEqual(d.goneEndpoints.length, 1);
});

console.log('\n== untested surface (the quiet gap) ==');
t('an endpoint probed in a previous run is not reported as untested', () => {
  const prev = C.take('t.tld', kb(['https://t.tld/a', 'https://t.tld/b']));
  prev.testedEndpoints = ['t.tld/a'];
  const cur = C.take('t.tld', kb(['https://t.tld/a', 'https://t.tld/b']));
  const d = C.diff(cur, prev);
  assert.strictEqual(d.untested.length, 1);
  assert.ok(d.untested[0].includes('/b'));
});
t('a never-probed endpoint is reported', () => {
  const prev = C.take('t.tld', kb(['https://t.tld/a']));
  prev.testedEndpoints = [];
  const d = C.diff(prev, prev);
  assert.strictEqual(d.untested.length, 1);
});

console.log('\n== findings across runs ==');
t('a finding that reproduces is NOT reported as resolved', () => {
  // Regression: ids are generated per run, so an id-only comparison made every
  // finding look resolved on every run.
  const f = { id: 'x1', title: "PROVEN INJECTION in 'q'", severity: 'high' };
  const prev = C.take('t.tld', kb(['https://t.tld/a']), { findings: [f] });
  const cur = C.take('t.tld', kb(['https://t.tld/a']), { findings: [f] });
  const d = C.diff(cur, prev);
  assert.deepStrictEqual(d.resolvedFindings, []);
});
t('a finding that genuinely disappears IS reported', () => {
  const prev = C.take('t.tld', kb(['https://t.tld/a']), { findings: [{ id: 'x1', title: 'old bug', severity: 'low' }] });
  const cur = C.take('t.tld', kb(['https://t.tld/a']), { findings: [] });
  assert.deepStrictEqual(C.diff(cur, prev).resolvedFindings, ['x1']);
});

console.log('\n== prioritisation ==');
t('a new staging host outranks a new www host', () => {
  const prev = C.take('t.tld', kb(['https://t.tld/']));
  const cur = C.take('t.tld', kb(['https://t.tld/', 'https://staging.t.tld/', 'https://www2.t.tld/']));
  const p = C.prioritise(C.diff(cur, prev));
  const staging = p.find((x) => /staging/.test(x.value));
  const www = p.find((x) => /www2/.test(x.value));
  assert.ok(staging && www);
  assert.ok(staging.score > www.score, 'staging must rank higher');
});
t('a new debug or admin endpoint ranks highly', () => {
  const prev = C.take('t.tld', kb(['https://t.tld/']));
  const cur = C.take('t.tld', kb(['https://t.tld/', 'https://t.tld/admin/panel', 'https://t.tld/about']));
  const p = C.prioritise(C.diff(cur, prev));
  assert.ok(p[0].value.includes('/admin/'), 'admin should be first, got ' + p[0].value);
  assert.ok(p[0].score >= 10);
});
t('classification returns a reason for every item', () => {
  const prev = C.take('t.tld', kb([]));
  const cur = C.take('t.tld', kb(['https://dev-api.t.tld/x', 'https://t.tld/y']));
  for (const p of C.prioritise(C.diff(cur, prev))) assert.ok(p.why && p.kind && p.value);
});

console.log('\n== persistence ==');
t('save and load round-trip, and loadLast returns null before any save', () => {
  const fs = require('fs'), os = require('os'), path = require('path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'chg-'));
  try {
    assert.strictEqual(C.loadLast(dir, 'nothing.tld'), null);
    const s = C.take('t.tld', kb(['https://t.tld/a']));
    C.save(dir, s);
    const back = C.loadLast(dir, 't.tld');
    assert.ok(back && back.endpoints.length === 1);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

drain().then(() => { console.log(`\n${pass} passed, ${fail} failed\n`); process.exit(fail ? 1 : 0); });
