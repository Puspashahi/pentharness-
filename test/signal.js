'use strict';
/**
 * Signal-based confirmation. The behaviour that matters is negative: a
 * reflected payload with no side effect must resolve to "not vulnerable",
 * because that is the standard false positive.
 */
const assert = require('assert');
const SG = require('../src/signal');

let pass = 0, fail = 0;
const queue = [];
function t(name, fn) { queue.push({ name, fn }); }
async function drain() {
  for (const { name, fn } of queue) {
    try { await fn(); console.log(`  ok  ${name}`); pass++; }
    catch (e) { console.log(`  FAIL ${name}\n       ${(e && e.message) || e}`); fail++; }
  }
}

console.log('\n== side channels exist for the classes we probe ==');
t('every class we actively probe has channels defined', () => {
  for (const cls of ['sqli', 'xss', 'ssrf', 'cmdi', 'idor', 'rce']) {
    const p = SG.plan(cls);
    assert.ok(p.channels.length > 0, `${cls} has no side channel`);
    for (const c of p.channels) assert.ok(c.hint && c.id, `${cls} channel is malformed`);
  }
});
t('the plan states both confirm and refute conditions up front', () => {
  const p = SG.plan('sqli');
  assert.match(p.confirmIf, /side channel fires/i);
  assert.match(p.refuteIf, /no observable difference/i);
});

console.log('\n== signal classification ==');
t('no side effect is signal 0 and must be refuted', () => {
  const r = SG.classify({ channels: ['db-content'], fired: [] });
  assert.strictEqual(r.signal, 0);
  assert.match(r.action, /refute/i);
  assert.match(r.confidenceNote, /false positive/i);
});
t('a blocked payload is not a finding', () => {
  const r = SG.classify({ channels: ['dialog'], fired: [], blocked: true });
  assert.strictEqual(r.signal, 0);
  assert.match(r.action, /not a finding/i);
});
t('a reproducible strong side channel is signal 3', () => {
  const r = SG.classify({ channels: ['dialog', 'dom-node'], fired: ['dialog'], reproducible: true });
  assert.strictEqual(r.signal, 3);
  assert.match(r.action, /reportable/i);
  assert.ok(r.evidenceNeeded.length >= 2, 'must demand a control-vs-attack evidence pair');
});
t('a one-off effect is signal 1, not a finding', () => {
  const r = SG.classify({ channels: ['dialog'], fired: ['dialog'], reproducible: false });
  assert.strictEqual(r.signal, 1);
  assert.match(r.action, /retry/i);
});
t('timing-only evidence is signal 2 and must be strengthened', () => {
  const r = SG.classify({ channels: ['time', 'db-content'], fired: ['time'], reproducible: true });
  assert.strictEqual(r.signal, 2);
  assert.match(r.action, /strengthen/i);
});
t('an effect outside the defined channels is signal 9', () => {
  const r = SG.classify({ channels: ['dialog'], fired: ['something-else'], reproducible: true });
  assert.strictEqual(r.signal, 9);
  assert.match(r.action, /verify/i);
});
t('a clean observation never yields signal 3', () => {
  // The invariant this module exists to enforce.
  const cases = [
    {},
    { fired: [] },
    { blocked: true },
    { fired: ['dialog'] },
    { fired: ['dialog'], reproducible: false },
    { channels: ['time'], fired: ['time'], reproducible: true },
    { channels: ['dialog'], fired: ['unknown-channel'], reproducible: true },
  ];
  for (const c of cases) {
    const r = SG.classify(c);
    assert.notStrictEqual(r.signal, 3, `unexpected signal 3 for ${JSON.stringify(c)}`);
  }
});

console.log('\n== idor needs an ownership signal, not a status code ==');
t('idor channels require other-user data', () => {
  const p = SG.plan('idor');
  assert.ok(p.channels.every((c) => /other-user|write/.test(c.id)), 'idor needs ownership evidence');
});


t('accepts channels as objects from plan() and as bare id strings', () => {
  // Regression: classify() maps `c => c.id`, which yields [undefined] when
  // given an array of strings. Every genuine channel was then "unrecognised"
  // and a confirmed XSS dialog was reported as signal 9. Both caller shapes
  // must work.
  const fromPlan = SG.classify({ channels: SG.plan('xss').channels, fired: ['dialog'], reproducible: true });
  const fromIds = SG.classify({ channels: ['dialog', 'dom-node'], fired: ['dialog'], reproducible: true });
  assert.strictEqual(fromPlan.signal, 3, 'object shape');
  assert.strictEqual(fromIds.signal, 3, 'string shape');
});
t('an omitted channels list is not treated as unknown', () => {
  const r = SG.classify({ fired: ['dialog'], reproducible: true });
  assert.strictEqual(r.signal, 3, 'with no plan to validate against, do not reject a real effect');
});

console.log('\n== describe ==');
t('renders a usable plan', () => {
  const d = SG.describe('xss');
  assert.match(d.readable, /To confirm xss/);
  assert.match(d.readable, /Confirm if/);
  assert.match(d.readable, /dialog/);
});

drain().then(() => {
  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
});
