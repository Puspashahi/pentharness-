'use strict';
/**
 * Tests for the deterministic validation layer.
 *
 * The most important assertions here are the NEGATIVE ones: a validator that
 * cannot refute a fake finding is worse than no validator, because it launders
 * a hypothesis into a report.
 */
const assert = require('assert');
const V = require('../src/validators');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log(`  ok  ${name}`); pass++; }
  catch (e) { console.log(`  FAIL ${name}\n       ${e.message}`); fail++; }
}

console.log('\n== layer 1: mechanical ==');
t('status delta detects a real change', () => {
  const r = V.L1.statusDelta({ status: 200 }, { status: 500 });
  assert.strictEqual(r.pass, true);
});
t('status delta passes when identical', () => {
  assert.strictEqual(V.L1.statusDelta({ status: 200 }, { status: 200 }).pass, false);
});
t('timing delta needs a real delay', () => {
  assert.strictEqual(V.L1.timingDelta(100, 3900, 1500).pass, true);
  assert.strictEqual(V.L1.timingDelta(100, 350, 1500).pass, false);
});
t('body length delta ignores trivial jitter', () => {
  assert.strictEqual(V.L1.bodyLengthDelta(10000, 10050, 0.02).pass, false);
  assert.strictEqual(V.L1.bodyLengthDelta(10000, 5000, 0.02).pass, true);
});
t('identical bodies are not evidence', () => {
  assert.strictEqual(V.L1.notIdentical('abc', 'abc').pass, false);
});

console.log('\n== layer 2: markers ==');
t('canary round trip proves the value was used', () => {
  assert.strictEqual(V.L2.canaryRoundTrip('result for ' + V.NONCE).pass, true);
});
t('canary absent means the value never landed', () => {
  assert.strictEqual(V.L2.canaryRoundTrip('nothing here').pass, false);
});
t('real DB error signatures are recognised', () => {
  for (const s of [
    "SQLSTATE[42S02]: Base table not found",
    'You have an error in your SQL syntax',
    'ORA-00942: table or view does not exist',
    'pg_query() failed',
  ]) assert.strictEqual(V.L2.dbError(s).pass, true, s);
});
t('SQLite/JDBC driver error is recognised (real-world dialect)', () => {
  const r = V.L2.dbError('<html><body><b>SQLite/JDBC Driver</b> near &quot;1&apos;&quot;: SQL syntax error</body></html>');
  assert.strictEqual(r.pass, true, r.why);
});
t('python driver exceptions are recognised', () => {
  assert.strictEqual(V.L2.dbError('sqlite3.OperationalError: near "x": syntax error').pass, true);
});
t('an echoed payload is NOT a DB error', () => {
  assert.strictEqual(V.L2.dbError("q=' UNION SELECT null--").pass, false, 'reflection must not count as an error');
});
t('oob callback is conclusive', () => {
  assert.strictEqual(V.L2.oobCallback(['tok-abc-123'], 'tok-abc-123').pass, true);
  assert.strictEqual(V.L2.oobCallback([], 'tok-abc-123').pass, false);
});
t('out-of-root file content proves traversal', () => {
  assert.strictEqual(V.L2.canaryFileRead('root:x:0:0::/root:/bin/sh', V.NONCE).pass, false, 'a real file without our sentinel is not proof');
  assert.strictEqual(V.L2.canaryFileRead('secret=' + V.NONCE, V.NONCE).pass, true);
});

console.log('\n== injection validator ==');
t('boolean differential alone is only a hypothesis', () => {
  const r = V.VALIDATORS.injection({ booleanTrue: { length: 5000 }, booleanFalse: { length: 12 } });
  assert.strictEqual(r.verdict, 'hypothesis', r.why);
});
t('boolean differential + error signature = proven', () => {
  const r = V.VALIDATORS.injection({
    booleanTrue: { length: 5000 }, booleanFalse: { length: 12 },
    errorBody: 'SQLSTATE[42S02]: Base table or view not found',
    baseline: { body: 'normal page' },
  });
  assert.strictEqual(r.verdict, 'proven', r.why);
});
t('timing delta alone can prove blind injection', () => {
  const r = V.VALIDATORS.injection({ timing: { baseline: 120, injected: 3600 } });
  assert.strictEqual(r.verdict, 'proven', r.why);
});
t('the false positive that started everything is refuted', () => {
  // payload reflected back, response otherwise identical to baseline
  const r = V.VALIDATORS.injection({
    errorBody: "q=' UNION SELECT null-- reflected in a share link",
    baseline: { body: "q=' UNION SELECT null-- reflected in a share link" },
  });
  assert.strictEqual(r.verdict, 'refuted', r.why);
});
t('identical true/false responses are refuted', () => {
  const r = V.VALIDATORS.injection({ booleanTrue: { length: 98453 }, booleanFalse: { length: 98453 } });
  assert.strictEqual(r.verdict, 'refuted');
});
t('no evidence at all is refuted', () => {
  assert.strictEqual(V.VALIDATORS.injection({}).verdict, 'refuted');
});

console.log('\n== xss validator ==');
t('executed script is proven', () => {
  const r = V.VALIDATORS.xss({ execution: { executed: true, origin: 'https://target' } });
  assert.strictEqual(r.verdict, 'proven');
});
t('reflection without execution is REFUTED, not proven', () => {
  const r = V.VALIDATORS.xss({ reflected: 'different body', baseline: 'other body' });
  assert.strictEqual(r.verdict, 'refuted', 'this is the single most common false positive in the field');
});
t('nothing observed is refuted', () => {
  assert.strictEqual(V.VALIDATORS.xss({}).verdict, 'refuted');
});

console.log('\n== traversal / ssrf validators ==');
t('traversal needs off-webroot content', () => {
  assert.strictEqual(V.VALIDATORS.traversal({ body: 'nothing', sentinel: V.NONCE }).verdict, 'refuted');
  assert.strictEqual(V.VALIDATORS.traversal({ body: 'x=' + V.NONCE, sentinel: V.NONCE }).verdict, 'proven');
});
t('ssrf without a callback or internal response is refuted', () => {
  const r = V.VALIDATORS.ssrf({});
  assert.strictEqual(r.verdict, 'refuted', r.why);
  assert.ok(/reflected/.test(r.why), r.why);
});
t('ssrf with an oob callback is proven', () => {
  assert.strictEqual(V.VALIDATORS.ssrf({ oob: [V.NONCE] }).verdict, 'proven');
});

console.log('\n== authz validator ==');
t('proven disclosure is proven', () => {
  const r = V.VALIDATORS.authz({ disclosure: { proven: true, reason: 'probe carries owner marker alice@x' } });
  assert.strictEqual(r.verdict, 'proven');
});
t('unproven disclosure is refuted', () => {
  const r = V.VALIDATORS.authz({ disclosure: { proven: false, reason: 'reading its own object' } });
  assert.strictEqual(r.verdict, 'refuted');
});
t('single-identity run is a hypothesis, never proven', () => {
  assert.strictEqual(V.VALIDATORS.authz({}).verdict, 'hypothesis');
});

console.log('\n== adversarial refutation ==');
t('refutation runs and a clean finding survives', () => {
  const r = V.refute('injection', { errorIsEcho: false, injectedEqualsBaseline: false, cacheBypassUnchanged: false });
  assert.strictEqual(r.survives, true);
  assert.ok(r.attacks_run >= 3, r.why);
});
t('echoed payload kills an injection finding', () => {
  const r = V.refute('injection', { errorIsEcho: true });
  assert.strictEqual(r.survives, false);
  assert.ok(/payload-echo/.test(r.refuted_by[0]));
});
t('own-record read kills an authz finding', () => {
  const r = V.refute('authz', { disclosure: { proven: false } });
  assert.strictEqual(r.survives, false);
});
t('execution outside the target origin kills an xss finding', () => {
  const r = V.refute('xss', { executed: true, execution: { origin: 'https://our-harness' }, targetOrigin: 'https://target' });
  assert.strictEqual(r.survives, false);
});
t('refutation cannot crash on a malformed evidence object', () => {
  const r = V.refute('xss', { execution: null });
  assert.strictEqual(r.survives, true, 'a null field must not count as a refutation');
});

console.log('\n== judge: combined verdict ==');
t('proven + survives = ship', () => {
  const r = V.judge('xss', { execution: { executed: true, origin: 'https://target' }, targetOrigin: 'https://target' });
  assert.strictEqual(r.verdict, 'proven');
  assert.strictEqual(r.ship, true);
  assert.ok(Array.isArray(r.questions), 'proven findings carry adjudication questions for the human');
});
t('proven validator but refuted by adversary = NOT shippable', () => {
  const r = V.judge('injection', { booleanTrue: { length: 9000 }, booleanFalse: { length: 12 }, errorIsEcho: true });
  assert.strictEqual(r.ship, false, 'Atlas: a finding must survive an adversary trying to refute it');
  assert.strictEqual(r.verdict, 'refuted');
});
t('hypothesis never ships', () => {
  assert.strictEqual(V.judge('injection', { booleanTrue: { length: 5 }, booleanFalse: { length: 9 } }).ship, false);
});
t('unknown class degrades to hypothesis, never proven', () => {
  const r = V.judge('something-new', {});
  assert.strictEqual(r.ship, false);
});

console.log('\n== failure taxonomy ==');
t('a syntax error is tactical', () => {
  assert.strictEqual(V.diagnose('syntax_error').dimension, 'tactical');
});
t('no differential is strategic — retrying the payload is pointless', () => {
  assert.strictEqual(V.diagnose('no_differential').dimension, 'strategic');
});
t('needing two identities is diagnosed and actionable', () => {
  const d = V.diagnose('needs_two_identities');
  assert.strictEqual(d.dimension, 'strategic');
  assert.ok(/second session/.test(d.fix));
});
t('unrecognised symptoms default to strategic (re-plan)', () => {
  assert.strictEqual(V.diagnose('something odd happened').dimension, 'strategic');
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
