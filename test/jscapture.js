'use strict';
/**
 * Live JavaScript capture and analysis.
 *
 * The dominant real-world constraint is minification, so most of these tests
 * use minified input. Two specific bugs found during development are pinned:
 * an absolute URL had its path appended twice, and third-party CDN bundles
 * were counted as application surface.
 */
const assert = require('assert');
const zlib = require('zlib');
const JC = require('../src/jscapture');

let pass = 0, fail = 0;
const queue = [];
function t(name, fn) { queue.push({ name, fn }); }
async function drain() {
  for (const { name, fn } of queue) {
    try { await fn(); console.log(`  ok  ${name}`); pass++; }
    catch (e) { console.log(`  FAIL ${name}\n       ${(e && e.message) || e}`); fail++; }
  }
}

const MINIFIED = '!function(e,t){"use strict";function n(e){return fetch("/api/v2/invoices/"+e.id,{headers:{Authorization:"Bearer "+t}})}var o="/admin/users",r="https://api.acme.io/graphql",i="/auth/token";}';

console.log('\n== endpoint extraction ==');
t('relative endpoints resolve against the base', () => {
  const eps = JC.extractEndpoints(MINIFIED, 'https://target.tld');
  assert.ok(eps.includes('https://target.tld/api/v2/invoices/'), JSON.stringify(eps));
  assert.ok(eps.includes('https://target.tld/admin/users'));
  assert.ok(eps.includes('https://target.tld/auth/token'));
});
t('an absolute URL keeps its own host and is NOT doubled', () => {
  // Regression: the capture group already included the path, so appending it
  // produced "https://api.acme.io/graphql/graphql".
  const eps = JC.extractEndpoints(MINIFIED, 'https://target.tld');
  assert.ok(eps.includes('https://api.acme.io/graphql'), JSON.stringify(eps));
  assert.ok(!eps.some((e) => /graphql\/graphql/.test(e)), 'path was duplicated: ' + JSON.stringify(eps));
});
t('third-party CDN and analytics hosts are excluded', () => {
  const src = 'var a="https://cdn.skypack.com/react",b="https://unpkg.com/x.js",c="https://assets.adobedtm.com/s.js";';
  const eps = JC.extractEndpoints(src, 'https://target.tld');
  assert.ok(!eps.some((e) => /skypack|unpkg|adobedtm/.test(e)), JSON.stringify(eps));
});
t('non-http schemes are ignored', () => {
  const eps = JC.extractEndpoints('var a="data:image/png;base64,AAA",b="mailto:x@y.z";', 'https://t.tld');
  assert.strictEqual(eps.length, 0);
});
t('no base means relative paths are returned as-is', () => {
  const eps = JC.extractEndpoints(MINIFIED, '');
  assert.ok(eps.includes('/admin/users'), JSON.stringify(eps));
});

console.log('\n== secret extraction ==');
t('recognises real token formats', () => {
  const src = [
    'var a="AIza' + 'Sy' + 'A1234567890abcdefghijklmnopqrstuv";',      // google, 39 chars
    'var b="ghp_abcdefghijklmnopqrstuvwxyz01";',
    'var c="xoxb-123456789012-abcdefghijkl";',
    'var d="AKIAIOSFODNN7EXAMPLE";',
  ].join('');
  const kinds = new Set(JC.extractSecrets(src).map((s) => s.kind));
  for (const k of ['google-api-key', 'github-token', 'slack-token', 'aws-access-key']) {
    assert.ok(kinds.has(k), `${k} not detected; got ${[...kinds]}`);
  }
});
t('secret samples are truncated, not echoed in full', () => {
  const out = JC.extractSecrets('var a="ghp_abcdefghijklmnopqrstuvwxyz01";');
  assert.ok(out.every((s) => s.sample.length <= 12), 'a full token must never be stored');
});
t('ordinary code yields no secrets', () => {
  assert.strictEqual(JC.extractSecrets('function add(a,b){return a+b;}').length, 0);
});

console.log('\n== minified-source handling ==');
t('string literals are pulled from minified code', () => {
  const lits = JC.stringLiterals(MINIFIED);
  assert.ok(lits.includes('/admin/users'), JSON.stringify(lits));
  assert.ok(lits.some((l) => /Bearer/.test(l)));
});
t('base64 blobs and single chars are filtered out', () => {
  const lits = JC.stringLiterals('var a="'+'A'.repeat(80)+'",b="x";');
  assert.ok(!lits.some((l) => l.length > 60), 'long base64 blob should be skipped');
  assert.ok(!lits.includes('x'), 'single chars are noise');
});
t('minified code is detected as minified', () => {
  const a = JC.analyseScript(MINIFIED, { url: 'https://t.tld/app.js' });
  assert.strictEqual(a.minified, true);
  assert.ok(a.literalCount > 0);
});
t('readable code is not treated as minified', () => {
  const readable = '// a comment\nfunction fetchUser(id) {\n  return fetch("/api/users/" + id);\n}\n'.repeat(20);
  const a = JC.analyseScript(readable, { url: 'https://t.tld/app.js' });
  assert.strictEqual(a.minified, false);
});

console.log('\n== source maps ==');
t('a sourceMappingURL comment is detected', () => {
  const src = 'var a=1;\n//# sourceMappingURL=app.js.map';
  assert.strictEqual(JC.sourceMapRef(src), 'app.js.map');
});
t('the @ form is also accepted', () => {
  assert.strictEqual(JC.sourceMapRef('//@ sourceMappingURL=x.map'), 'x.map');
});
t('no comment means no reference', () => {
  assert.strictEqual(JC.sourceMapRef('var a=1;'), null);
});

console.log('\n== body decoding ==');
t('gzip is decoded, because an undecoded capture finds nothing', () => {
  const raw = Buffer.from('var api="/api/invoices";');
  const gz = zlib.gzipSync(raw);
  assert.strictEqual(JC.decodeBody(gz, 'gzip'), 'var api="/api/invoices";');
});
t('deflate is decoded', () => {
  const raw = Buffer.from('var api="/api/x";');
  assert.strictEqual(JC.decodeBody(zlib.deflateSync(raw), 'deflate'), 'var api="/api/x";');
});
t('plain and empty bodies are handled', () => {
  assert.strictEqual(JC.decodeBody(Buffer.from('abc'), ''), 'abc');
  assert.strictEqual(JC.decodeBody(null, ''), '');
  assert.strictEqual(JC.decodeBody(Buffer.alloc(0), ''), '');
});
t('a corrupt compressed body does not throw', () => {
  assert.doesNotThrow(() => JC.decodeBody(Buffer.from('not gzip'), 'gzip'));
});

console.log('\n== script classification ==');
t('js and javascript content types count as scripts', () => {
  assert.strictEqual(JC.isAppScript('https://t/a.js'), true);
  assert.strictEqual(JC.isAppScript('https://t/a', 'application/javascript'), true);
  assert.strictEqual(JC.isAppScript('https://t/a', 'text/html'), false);
});

console.log('\n== capture analysis ==');
t('analyseCapture aggregates across scripts', () => {
  const captured = [
    { url: 'https://t.tld/a.js', bytes: 100, source: 'var x="/api/one";var k="ghp_abcdefghijklmnopqrstuvwxyz01";' },
    { url: 'https://t.tld/b.js', bytes: 200, source: 'var y="/api/two";var z="AKIAIOSFODNN7EXAMPLE";' },
  ];
  const r = JC.analyseCapture(captured, 'https://t.tld');
  assert.strictEqual(r.scripts, 2);
  assert.strictEqual(r.bytes, 300);
  assert.ok(r.endpoints.some((e) => /api\/one/.test(e)));
  assert.ok(r.endpoints.some((e) => /api\/two/.test(e)));
  assert.ok(r.secrets.length >= 2, JSON.stringify(r.secrets));
  assert.ok(r.endpoints.some((e) => /a\.js/.test(e)), 'the script url itself is tracked');
});
t('an empty capture is handled', () => {
  const r = JC.analyseCapture([], 'https://t.tld');
  assert.strictEqual(r.scripts, 0);
  assert.deepStrictEqual(r.endpoints, []);
});
t('a script with no body does not break analysis', () => {
  const r = JC.analyseCapture([{ url: 'https://t.tld/x.js', bytes: 0, source: '' }], 'https://t.tld');
  assert.strictEqual(r.scripts, 1);
  assert.ok(r.endpoints.includes('https://t.tld/x.js'));
});

drain().then(() => {
  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
});
