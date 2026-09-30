'use strict';
/**
 * CVE applicability matching — the version-comparison and exclusion-reasoning
 * edges, which are where an off-by-one silently produces a wrong answer.
 */
const assert = require('assert');
const CV = require('../src/cvematch');

let pass = 0, fail = 0;
const queue = [];
function t(name, fn) { queue.push({ name, fn }); }
async function drain() {
  for (const { name, fn } of queue) {
    try { await fn(); console.log(`  ok  ${name}`); pass++; }
    catch (e) { console.log(`  FAIL ${name}\n       ${(e && e.message) || e}`); fail++; }
  }
}

console.log('\n== version comparison ==');
t('orders versions correctly', () => {
  assert.strictEqual(CV.compareVersions('4.17.20', '4.17.21'), -1);
  assert.strictEqual(CV.compareVersions('4.17.21', '4.17.20'), 1);
  assert.strictEqual(CV.compareVersions('1.2.3', '1.2.3'), 0);
  assert.strictEqual(CV.compareVersions('1.10.0', '1.9.0'), 1, 'minor must be numeric, not lexical');
  assert.strictEqual(CV.compareVersions('2.0', '1.99.99'), 1);
});
t('tolerates v-prefix and missing components', () => {
  assert.strictEqual(CV.compareVersions('v4.17.21', '4.17.21'), 0);
  assert.strictEqual(CV.compareVersions('1', '1.0.0'), 0);
  assert.strictEqual(CV.compareVersions('1.2', '1.2.0'), 0);
});

console.log('\n== affected-range parsing ==');
t('exclusive upper bound ("before X") is exclusive', () => {
  assert.strictEqual(CV.isAffected('4.17.20', '< 4.17.21'), true);
  assert.strictEqual(CV.isAffected('4.17.21', '< 4.17.21'), false, 'the boundary version must NOT be affected');
});
t('inclusive wording ("through X", "up to and including")', () => {
  assert.strictEqual(CV.isAffected('3.1.0', 'through 3.1'), true);
  assert.strictEqual(CV.isAffected('3.1.0', 'up to and including 3.1'), true);
  assert.strictEqual(CV.isAffected('3.2.0', 'through 3.1'), false);
});
t('ranges with dashes', () => {
  assert.strictEqual(CV.isAffected('1.2.0', '1.0.0 - 1.4.2'), true);
  assert.strictEqual(CV.isAffected('1.4.2', '1.0.0 - 1.4.2'), true);
  assert.strictEqual(CV.isAffected('1.4.3', '1.0.0 - 1.4.2'), false);
  assert.strictEqual(CV.isAffected('0.9', '1.0.0 - 1.4.2'), false);
});
t('operators', () => {
  assert.strictEqual(CV.isAffected('1.0.0', '<= 1.0.0'), true);
  assert.strictEqual(CV.isAffected('1.0.1', '>= 1.0.1'), true);
  assert.strictEqual(CV.isAffected('1.0.0', '= 1.0.0'), true);
  assert.strictEqual(CV.isAffected('2.0.0', '> 1.5.0'), true);
});
t('"and earlier" phrasing', () => {
  assert.strictEqual(CV.isAffected('1.0.0', '1.2.3 and earlier'), true);
  assert.strictEqual(CV.isAffected('1.2.4', '1.2.3 and earlier'), false);
});
t('unparseable input returns null, never a guess', () => {
  assert.strictEqual(CV.isAffected('unknown', '< 4.17.21'), null);
  assert.strictEqual(CV.isAffected('4.17.20', 'see advisory'), null);
  assert.strictEqual(CV.isAffected(null, '< 1.0'), null);
});
t('a real advisory boundary: lodash prototype pollution', () => {
  // CVE-2021-23337 affects lodash < 4.17.21
  assert.strictEqual(CV.isAffected('4.17.20', '< 4.17.21'), true);
  assert.strictEqual(CV.isAffected('4.17.21', '< 4.17.21'), false);
  assert.strictEqual(CV.isAffected('4.17.15', '< 4.17.21'), true);
});

console.log('\n== product fingerprint matching ==');
t('matches regardless of case and spacing', () => {
  assert.strictEqual(CV.techMatches('Lodash 4.17.20', 'lodash'), true);
  assert.strictEqual(CV.techMatches('Apache Tomcat/9.0', 'tomcat'), true);
  assert.strictEqual(CV.techMatches('Django 3.2.1', 'django'), true);
});
t('does not match unrelated products', () => {
  assert.strictEqual(CV.techMatches('Django 3.2', 'lodash'), false);
  assert.strictEqual(CV.techMatches('', 'lodash'), false);
  assert.strictEqual(CV.techMatches(null, 'lodash'), false);
});

console.log('\n== exclusion reasoning ==');
const CVE_SET = [
  { id: 'CVE-A', cls: 'rce', product: 'lodash', affected: '< 4.17.21', cvss: 7.2, requires: { shell: true }, summary: 'post-auth RCE' },
  { id: 'CVE-B', cls: 'xss', product: 'lodash', affected: '< 4.17.21', cvss: 5.3, requires: {}, summary: 'preauth XSS' },
  { id: 'CVE-C', cls: 'idor', product: 'acmecorp', cvss: 8.1, requires: { auth: true }, summary: 'auth-only IDOR' },
  { id: 'CVE-D', cls: 'rce', product: 'lodash', affected: '< 4.17.21', cvss: 9.8, requires: {}, summary: 'preauth RCE' },
];

t('keeps applicable and excludes the rest', () => {
  const r = CV.match(CVE_SET, { tech: 'Lodash 4.17.20', version: '4.17.20', hasAuth: false, hasShell: false });
  const ids = r.applicable.map((c) => c.id);
  assert.ok(ids.includes('CVE-B'), 'preauth XSS should apply');
  assert.ok(ids.includes('CVE-D'), 'preauth RCE should apply');
  assert.ok(!ids.includes('CVE-A'), 'shell-required CVE must be excluded');
  const excl = Object.fromEntries(r.excluded.map((e) => [e.cve.id, e.reasons.join(' ')]));
  assert.match(excl['CVE-A'], /shell/i);
  assert.match(excl['CVE-C'], /not detected/i, 'a product we never saw is excluded outright');
});
t('every applicability claim names its evidence', () => {
  const r = CV.match(CVE_SET, { tech: 'Lodash 4.17.20', version: '4.17.20' });
  for (const a of r.applicable) {
    assert.ok(Array.isArray(a.matchedBecause) && a.matchedBecause.length, a.id);
    assert.ok(/caveat/.test(Object.keys(a).join(' ')), 'must carry a non-exploitability caveat');
  }
});
t('an unverified version is uncertain, not applicable', () => {
  const r = CV.match(CVE_SET, { tech: 'Lodash', version: null });
  assert.ok(r.uncertain.length, 'no version means uncertain');
  assert.ok(r.uncertain.every((c) => c.confidence === 'low'));
  assert.ok(r.uncertain.every((c) => /confirm before relying/i.test(c.matchedBecause.join(' '))));
});
t('a version outside the range is excluded outright', () => {
  const r = CV.match(CVE_SET, { tech: 'Lodash 4.17.21', version: '4.17.21' });
  const excl = r.excluded.map((e) => e.cve.id);
  assert.ok(excl.includes('CVE-B'), 'patched version must be excluded');
  assert.match(r.excluded.find((e) => e.cve.id === 'CVE-B').reasons.join(' '), /outside the affected range/);
});
t('program exclusions are honoured', () => {
  const r = CV.match(CVE_SET, { tech: 'Lodash 4.17.20', version: '4.17.20', programExcludes: ['xss'] });
  assert.ok(!r.applicable.some((c) => c.cls === 'xss'));
  assert.match(r.excluded.find((e) => e.cve.cls === 'xss').reasons.join(' '), /brief excludes/);
});
t('specific_feature requirements are checked', () => {
  const cves = [{ id: 'F1', cls: 'ssrf', product: 'app', cvss: 9.1, requires: { specific_feature: 'webhooks' } }];
  const off = CV.match(cves, { tech: 'app', seenFeatures: ['profile'] });
  assert.strictEqual(off.applicable.length, 0);
  const on = CV.match(cves, { tech: 'app', seenFeatures: ['webhooks', 'profile'] });
  assert.strictEqual(on.applicable.length, 1);
});
t('results are ordered by severity', () => {
  const r = CV.match(CVE_SET, { tech: 'Lodash 4.17.20', version: '4.17.20' });
  const cv = r.applicable.map((c) => c.cvss);
  assert.deepStrictEqual(cv, [...cv].sort((a, b) => b - a));
});
t('savings are reported', () => {
  const r = CV.match(CVE_SET, { tech: 'Lodash 4.17.20', version: '4.17.20', hasShell: false });
  const s = CV.savings(r, CVE_SET.length);
  assert.strictEqual(s.total, 4);
  assert.ok(s.excluded >= 2);
  assert.ok(s.reductionPct > 0);
});
t('an empty input does not throw', () => {
  const r = CV.match([], {});
  assert.strictEqual(r.applicable.length, 0);
  assert.strictEqual(CV.match(null, {}).applicable.length, 0);
});

drain().then(() => {
  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
});
