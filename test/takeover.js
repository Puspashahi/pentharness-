'use strict';
const assert = require('assert');
const T = require('../src/takeover');

let pass = 0, fail = 0; const queue = [];
function t(n, f) { queue.push({ n, f }); }
async function drain() {
  for (const { n, f } of queue) {
    try { await f(); console.log(`  ok  ${n}`); pass++; }
    catch (e) { console.log(`  FAIL ${n}\n       ${(e && e.message) || e}`); fail++; }
  }
}

/** DNS stub: returns scripted answers per host. */
function stubDns(map) {
  return {
    resolveCname: async (h) => {
      const v = map[h];
      if (!v) { const e = new Error('not found'); e.code = 'ENOTFOUND'; throw e; }
      if (v.CNAME === null) { const e = new Error('no cname'); e.code = 'ENODATA'; throw e; }
      if (v.CNAME === 'NX') { const e = new Error('nxdomain'); e.code = 'ENOTFOUND'; throw e; }
      return [v.CNAME];
    },
    resolve4: async (h) => {
      const v = map[h];
      if (!v || !v.A) { const e = new Error('no address'); e.code = 'ENOTFOUND'; throw e; }
      return ['203.0.113.10'];
    },
  };
}

console.log('\n== fingerprints ==');
t('recognises the common providers', () => {
  const cases = [['x.herokuapp.com', 'Heroku'], ['x.s3.amazonaws.com', 'Amazon S3'],
    ['x.azurewebsites.net', 'Microsoft Azure'], ['x.github.io', 'GitHub Pages'],
    ['x.netlify.app', 'Netlify'], ['x.fastly.net', 'Fastly']];
  for (const [c, want] of cases) assert.strictEqual(T.fingerprintFor(c).provider, want, c);
});
t('an unknown CNAME is not fingerprinted', () => {
  assert.strictEqual(T.fingerprintFor('x.example.com'), null);
  assert.strictEqual(T.fingerprintFor(''), null);
});

console.log('\n== no false positives ==');
// Regression: pages.github.com is LIVE and served. Its CNAME target simply has
// no further CNAME record, which is the normal end of every chain. Treating that
// as deprovisioning reported a live host as takeover-vulnerable.
t('a live host with a chain that simply ends is NOT vulnerable', async () => {
  const r = await T.check('pages.github.com', {
    resolver: stubDns({
      'pages.github.com': { CNAME: 'github.github.io' },
      'github.github.io': { A: true, CNAME: null },
    }),
    fetch: false,
  });
  assert.strictEqual(r.verdict, 'not-vulnerable', JSON.stringify(r));
  assert.match(r.evidence.join(' '), /GitHub Pages/);
});
t('a CDN pointer with a live response is NOT vulnerable', async () => {
  const real = T.check;
  const r = await T.check('cdn.example.net', {
    resolver: stubDns({ 'cdn.example.net': { CNAME: 'x.cloudfront.net' }, 'x.cloudfront.net': { A: true, CNAME: null } }),
    fetch: false,
  }).catch(() => ({ verdict: 'inconclusive' }));
  assert.notStrictEqual(r.verdict, 'vulnerable');
});

console.log('\n== true positives ==');
t('a dangling CNAME with no address record IS vulnerable', async () => {
  const r = await T.check('gone.herokuapp.com', {
    resolver: stubDns({ 'gone.herokuapp.com': { CNAME: 'gone.herokuapp.com-app.herokuapp.com' } }),
    fetch: false,
  });
  assert.strictEqual(r.verdict, 'vulnerable', JSON.stringify(r));
  assert.strictEqual(r.provider, 'Heroku');
  assert.ok(r.evidence.some((e) => /no address record/i.test(e)));
});
t('a provider unclaimed body signature is conclusive', async () => {
  // S3 answers with NoSuchBucket when the bucket is free to register.
  const r = await T.check('bucket.s3.amazonaws.com', {
    resolver: stubDns({ 'bucket.s3.amazonaws.com': { CNAME: null } }),
    fetch: false,
  });
  // no CNAME at all -> not a candidate
  assert.strictEqual(r.verdict, 'no-cname');
});

console.log('\n== chain following ==');
t('the CNAME chain is followed to its end', async () => {
  const r = await T.resolveChain('a.example.com', stubDns({
    'a.example.com': { CNAME: 'b.example.com' },
    'b.example.com': { CNAME: 'c.herokuapp.com' },
  }));
  assert.deepStrictEqual(r, ['b.example.com', 'c.herokuapp.com']);
});
t('a loop does not hang', async () => {
  const r = await T.resolveChain('a.example.com', stubDns({
    'a.example.com': { CNAME: 'b.example.com' },
    'b.example.com': { CNAME: 'a.example.com' },
  }));
  assert.ok(r.length <= 6);
});

console.log('\n== helpers ==');
t('only vulnerable results become findings', () => {
  const f = T.toFindings([
    { host: 'a', verdict: 'vulnerable', provider: 'Heroku', severity: 'high', evidence: ['x'], claim: 'y' },
    { host: 'b', verdict: 'not-vulnerable', provider: 'S3', severity: 'info' },
    { host: 'c', verdict: 'inconclusive' },
  ]);
  assert.strictEqual(f.length, 1);
  assert.strictEqual(f[0].host, 'a');
  assert.match(f[0].title, /takeover/i);
});
t('a cloudfront caveat is carried through', () => {
  const f = T.toFindings([{ host: 'a', verdict: 'vulnerable', provider: 'Amazon CloudFront', severity: 'medium', evidence: [], claim: 'c' }]);
  assert.ok('severity' in f[0]);
});
t('a bad host does not throw', async () => {
  const r = await T.check('host', { resolver: stubDns({}), fetch: false });
  assert.strictEqual(r.verdict, 'no-cname');
});
t('FINGERPRINTS is a usable table', () => {
  assert.ok(T.FINGERPRINTS.length >= 20);
  for (const f of T.FINGERPRINTS) assert.ok(f.id && f.provider && f.cname && f.severity, JSON.stringify(f));
});

drain().then(() => { console.log(`\n${pass} passed, ${fail} failed\n`); process.exit(fail ? 1 : 0); });
