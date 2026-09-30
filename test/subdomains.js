'use strict';
const assert = require('assert');
const SD = require('../src/subdomains');

let pass = 0, fail = 0; const queue = [];
function t(n, f) { queue.push({ n, f }); }
async function drain() {
  for (const { n, f } of queue) {
    try { await f(); console.log(`  ok  ${n}`); pass++; }
    catch (e) { console.log(`  FAIL ${n}\n       ${(e && e.message) || e}`); fail++; }
  }
}

console.log('\n== scope enforcement (a violation is worse than a miss) ==');
t('an exact scope covers itself and nothing else', () => {
  assert.strictEqual(SD.inScope('app.tld', ['app.tld']).ok, true);
  assert.strictEqual(SD.inScope('other.tld', ['app.tld']).ok, false);
  assert.strictEqual(SD.inScope('api.app.tld', ['app.tld']).ok, true, 'subdomains of the scope are covered');
});
t('a bare domain covers the apex and all subdomains', () => {
  assert.strictEqual(SD.inScope('tld', ['tld']).ok, true);
  assert.strictEqual(SD.inScope('a.b.tld', ['tld']).ok, true);
});
t('a wildcard includes its anchor domain', () => {
  assert.strictEqual(SD.inScope('tld', ['.tld']).ok, true);
  assert.strictEqual(SD.inScope('deep.sub.tld', ['.tld']).ok, true);
});
t('an attacker domain that merely ends with the scope is refused', () => {
  // The suffix-confusion case: "tld.evil.com" ends with "evil.com" but contains
  // the scope as a substring, not as a suffix of the registrable name.
  assert.strictEqual(SD.inScope('tld.evil.com', ['tld']).ok, false);
  assert.strictEqual(SD.inScope('eviltld', ['tld']).ok, false);
  assert.strictEqual(SD.inScope('eviltld.com', ['tld']).ok, false);
});
t('matching is case-insensitive and tolerates a trailing dot', () => {
  assert.strictEqual(SD.inScope('APP.TLD', ['app.tld']).ok, true);
  assert.strictEqual(SD.inScope('app.tld.', ['app.tld']).ok, true);
});
t('multiple rules are all considered', () => {
  assert.strictEqual(SD.inScope('b.other.tld', ['a.tld', 'other.tld']).ok, true);
  assert.strictEqual(SD.inScope('c.third.tld', ['a.tld', 'other.tld']).ok, false);
});
t('an empty host and no scope are handled', () => {
  assert.strictEqual(SD.inScope('', ['tld']).ok, false);
  assert.strictEqual(SD.inScope('anything.tld', []).ok, true, 'no declared scope means authorised');
});

console.log('\n== ranking ==');
t('interesting hostnames rank above generic ones', () => {
  const dev = SD.rank('dev-api.tld');
  const admin = SD.rank('admin.tld');
  const www = SD.rank('www.tld');
  assert.ok(dev.score > www.score, 'dev must outrank www');
  assert.ok(admin.score > www.score, 'admin must outrank www');
  assert.ok(Array.isArray(dev.reasons) && dev.reasons.length, JSON.stringify(dev));
  assert.ok(Array.isArray(admin.reasons) && admin.reasons.length, JSON.stringify(admin));
});
t('a third-party CNAME is demoted and explained', () => {
  const own = SD.rank('cdn.tld', { cname: 'app.azurewebsites.net' });
  const first = SD.rank('cdn.tld');
  assert.ok(own.score < first.score, 'a SaaS CNAME target is not a first-party asset');
  assert.match(own.reasons.join(' '), /third-party/i);
});
t('generated noise is demoted', () => {
  assert.ok(SD.rank('a1234567.b123456.tld').score < SD.rank('api.b.tld').score);
  assert.ok(SD.rank('xn--80ak6aa92e.tld').score < 0);
});
t('alive and gated hosts both count as interesting', () => {
  assert.ok(SD.rank('x.tld', { status: 200 }).score > SD.rank('x.tld').score);
  assert.ok(SD.rank('x.tld', { status: 403 }).score > 0, 'a 403 is alive, just gated');
});

console.log('\n== parsing ==');
t('parses plain host lines', () => {
  const r = SD.parseSubfinder('a.tld\nb.tld\n');
  assert.strictEqual(r.length, 2);
  assert.strictEqual(r[0].host, 'a.tld');
});
t('parses json output and keeps the cname', () => {
  const line = JSON.stringify({ host: 'api.tld', source: 'crtsh', cname: 'x.azurewebsites.net' });
  const r = SD.parseSubfinder(line);
  assert.strictEqual(r.length, 1);
  assert.strictEqual(r[0].cname, 'x.azurewebsites.net');
});
t('deduplicates and ignores junk', () => {
  const r = SD.parseSubfinder('a.tld\na.tld\n\nnot a host\n  \nb.tld');
  assert.strictEqual(r.length, 2);
});

console.log('\n== triage ==');
t('separates in-scope, out-of-scope and third-party', () => {
  const r = SD.triage([
    { host: 'api.tld' }, { host: 'cdn.tld', cname: 'x.cloudfront.net' }, { host: 'evil.com' },
  ], ['tld']);
  assert.strictEqual(r.totals.inScope, 1);
  assert.strictEqual(r.totals.outOfScope, 1);
  assert.strictEqual(r.totals.thirdParty, 1);
  assert.ok(/not covered/.test(r.outOfScope[0].reason));
});
t('in-scope results are ordered by score', () => {
  const r = SD.triage([{ host: 'www.tld' }, { host: 'admin.tld' }, { host: 'dev.tld' }], ['tld']);
  assert.ok(r.inScope[0].score >= r.inScope[1].score);
  assert.ok(r.inScope[1].score >= r.inScope[2].score);
});
t('accepts plain strings as well as objects', () => {
  const r = SD.triage(['a.tld'], ['tld']);
  assert.strictEqual(r.totals.inScope, 1);
});
t('empty input is safe', () => {
  const r = SD.triage([], []);
  assert.strictEqual(r.totals.discovered, 0);
});

console.log('\n== sensitive paths ==');
t('exposes read-only high-value paths', () => {
  const p = SD.sensitivePaths();
  assert.ok(p.length >= 5);
  assert.ok(p.every((x) => x.path.startsWith('/') && x.why));
});

drain().then(() => { console.log(`\n${pass} passed, ${fail} failed\n`); process.exit(fail ? 1 : 0); });
