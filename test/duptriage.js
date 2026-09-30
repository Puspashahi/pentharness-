'use strict';
/**
 * Duplicate / prior-art triage.
 *
 * The point of these tests is the failure mode: treating a genuinely novel
 * chained finding as a duplicate because its individual steps are known. That
 * mistake costs real money, so it is pinned down here alongside the obvious
 * "same bug, same place" case.
 */
const assert = require('assert');
const DT = require('../src/duptriage');

let pass = 0, fail = 0;
const queue = [];
function t(name, fn) { queue.push({ name, fn }); }
async function drain() {
  for (const { name, fn } of queue) {
    try { await fn(); console.log(`  ok  ${name}`); pass++; }
    catch (e) { console.log(`  FAIL ${name}\n       ${(e && e.message) || e}`); fail++; }
  }
}

const PRIOR = [
  { id: 'H1-2021-0442', title: 'IDOR on invoice endpoints', cls: 'idor', url: 'https://t/api/invoices/1', method: 'GET' },
  { id: 'H1-2022-1180', title: 'Stored XSS in profile bio', cls: 'xss', url: 'https://t/profile', method: 'POST' },
];

console.log('\n== path normalisation ==');
t('ids and uuids collapse to :id', () => {
  assert.strictEqual(DT.normalisePath('https://t/api/invoices/1'), '/api/invoices/:id');
  assert.strictEqual(DT.normalisePath('https://t/api/invoices/2'), '/api/invoices/:id');
  assert.strictEqual(DT.normalisePath('https://t/u/11111111-1111-4111-8111-111111111111'), '/u/:id');
});
t('query strings and trailing slashes are dropped', () => {
  assert.strictEqual(DT.normalisePath('https://t/search?q=a'), '/search');
  assert.strictEqual(DT.normalisePath('https://t/a/b/'), '/a/b');
  assert.strictEqual(DT.normalisePath('https://t'), '/');
});

console.log('\n== similarity ==');
t('the same bug at the same place scores high', () => {
  const s = DT.similarity(
    { cls: 'idor', url: 'https://t/api/invoices/5', method: 'GET' },
    { cls: 'idor', url: 'https://t/api/invoices/9', method: 'GET' },
  );
  assert.ok(s >= 0.85, `expected >=0.85, got ${s}`);
});
t('different classes at the same place score low', () => {
  const s = DT.similarity(
    { cls: 'xss', url: 'https://t/api/invoices/5', method: 'GET' },
    { cls: 'idor', url: 'https://t/api/invoices/9', method: 'GET' },
  );
  assert.ok(s < 0.7, `expected <0.7, got ${s}`);
});
t('identity-set overlap contributes', () => {
  const a = { cls: 'idor', url: 'https://t/x/1', identities: ['alice', 'bob'] };
  const b = { cls: 'idor', url: 'https://t/x/1', identities: ['alice', 'bob'] };
  const c = { cls: 'idor', url: 'https://t/x/1', identities: ['carol', 'dave'] };
  assert.ok(DT.similarity(a, b) > DT.similarity(a, c));
});

console.log('\n== verdict: duplicates ==');
t('same class, same endpoint is a duplicate', () => {
  const r = DT.triage({ cls: 'idor', url: 'https://t/api/invoices/77', method: 'GET' }, PRIOR);
  assert.strictEqual(r.verdict, 'duplicate');
  assert.strictEqual(r.action, 'do-not-submit');
  assert.ok(r.reasons.length >= 2);
});
t('the nearest match is named so the researcher can check it', () => {
  const r = DT.triage({ cls: 'idor', url: 'https://t/api/invoices/77', method: 'GET' }, PRIOR);
  assert.strictEqual(r.nearest.id, 'H1-2021-0442');
  assert.ok(r.nearest.sim > 0.8);
});

console.log('\n== verdict: not a duplicate ==');
t('known class at a different endpoint is not a duplicate', () => {
  const r = DT.triage({ cls: 'idor', url: 'https://t/api/orders/1', method: 'GET' }, PRIOR);
  assert.notStrictEqual(r.verdict, 'duplicate');
  assert.strictEqual(r.action, 'submit-with-distinct-impact');
  assert.ok(r.mustShow.length >= 1, 'must tell the researcher what to demonstrate');
});
t('a chained finding is treated as novel', () => {
  // Both steps are individually known, but the composition is the finding.
  const r = DT.triage({
    cls: 'authz',
    url: 'https://t/api/orders/1',
    method: 'GET',
    steps: ['idor-read-order', 'csrf-change-owner'],
    identities: ['alice', 'bob'],
  }, PRIOR);
  assert.strictEqual(r.verdict, 'novel-chain');
  assert.strictEqual(r.action, 'submit-as-chain');
  assert.match(r.mustShow.join(' '), /linkage/i);
});
t('an empty corpus yields novel', () => {
  const r = DT.triage({ cls: 'xss', url: 'https://t/a' }, []);
  assert.strictEqual(r.verdict, 'novel');
  assert.ok(/unverified/.test(r.reasons.join(' ')), 'must not claim novelty it cannot support');
});

console.log('\n== batch dedupe ==');
t('collapses identical findings, keeps distinct ones', () => {
  const batch = [
    { id: 'F1', cls: 'idor', url: 'https://t/api/invoices/1' },
    { id: 'F2', cls: 'idor', url: 'https://t/api/invoices/2' },   // same bug
    { id: 'F3', cls: 'xss', url: 'https://t/profile' },          // different
  ];
  const { kept, dropped } = DT.dedupeBatch(batch);
  assert.strictEqual(kept.length, 2);
  assert.strictEqual(dropped.length, 1);
  assert.strictEqual(dropped[0].duplicateOf, 'F1');
});
t('an empty batch is handled', () => {
  assert.deepStrictEqual(DT.dedupeBatch([]).kept, []);
  assert.deepStrictEqual(DT.dedupeBatch(null).kept, []);
});

drain().then(() => {
  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
});
