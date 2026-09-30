'use strict';
/**
 * Evidence hygiene.
 *
 * The scenario this guards against is specific and common: a hunter pastes
 * their own request/response into a report. The Cookie header hands the triager
 * a working session on the hunter's account. Nobody means to do this.
 */
const assert = require('assert');
const EV = require('../src/evidence');

let pass = 0, fail = 0;
const queue = [];
function t(name, fn) { queue.push({ name, fn }); }
async function drain() {
  for (const { name, fn } of queue) {
    try { await fn(); console.log(`  ok  ${name}`); pass++; }
    catch (e) { console.log(`  FAIL ${name}\n       ${(e && e.message) || e}`); fail++; }
  }
}

console.log('\n== headers ==');
t('session cookies are masked but their names survive', () => {
  const h = EV.redactHeaders({ Cookie: 'MOS_AUTH_TOKEN=abc123secret; mwa_session=xyz789; theme=dark' });
  assert.match(h.Cookie, /MOS_AUTH_TOKEN=<redacted>/);
  assert.match(h.Cookie, /mwa_session=<redacted>/);
  assert.ok(!/abc123secret/.test(h.Cookie), 'the secret value must be gone');
  assert.match(h.Cookie, /theme=dark/, 'non-secret cookies stay readable');
});
t('authorization keeps its scheme', () => {
  const h = EV.redactHeaders({ Authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig' });
  assert.match(h.Authorization, /^Bearer <redacted>$/);
});
t('evidence headers are preserved', () => {
  const h = EV.redactHeaders({ 'Content-Type': 'application/json', 'X-Request-Purpose': 'BugcrowdResearch' });
  assert.strictEqual(h['Content-Type'], 'application/json');
  assert.strictEqual(h['X-Request-Purpose'], 'BugcrowdResearch', 'a program-required header is evidence');
});

console.log('\n== params and bodies ==');
t('secret-named params are masked, others are kept', () => {
  const r = EV.redactParams('user=alice&password=hunter2&q=laptop&token=abc123');
  assert.match(r, /user=alice/);
  assert.match(r, /q=laptop/);
  assert.match(r, /password=<redacted>/);
  assert.match(r, /token=<redacted>/);
  assert.ok(!/hunter2/.test(r));
});
t('JSON bodies are masked by key', () => {
  const r = JSON.parse(EV.redactParams(JSON.stringify({ username: 'alice', password: 'hunter2', role: 'admin' })));
  assert.strictEqual(r.username, 'alice');
  assert.strictEqual(r.role, 'admin');
  assert.strictEqual(r.password, '<redacted>');
});
t('nested JSON is handled', () => {
  const r = JSON.parse(EV.redactParams(JSON.stringify({ user: { profile: { api_key: 'sk-live-123', name: 'alice' } } })));
  assert.strictEqual(r.user.profile.api_key, '<redacted>');
  assert.strictEqual(r.user.profile.name, 'alice');
});

console.log('\n== free text ==');
t('tokens of every common format are caught', () => {
  const cases = [
    ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abcdefghij', 'jwt'],
    ['ghp_abcdefghijklmnopqrstuvwxyz0123', 'github token'],
    ['xoxb-123456789012-abcdefghijkl', 'slack token'],
    ['AKIAIOSFODNN7EXAMPLE', 'aws key'],
  ];
  for (const [secret] of cases) {
    const out = EV.redactText(`before ${secret} after`);
    assert.ok(!out.includes(secret), `leaked: ${secret}`);
    assert.match(out, /<redacted/);
  }
});
t('a private key is fully removed', () => {
  const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----';
  const out = EV.redactText(pem);
  assert.ok(!/MIIEow/.test(out), 'key body must be gone');
});
t('emails and uuids are masked by default but can be kept', () => {
  const s = 'owner alice@corp.test id 11111111-1111-4111-8111-111111111111';
  assert.match(EV.redactText(s), /<redacted-email>/);
  const kept = EV.redactText(s, { maskEmail: false, maskUuid: false });
  assert.ok(kept.includes('alice@corp.test'), 'an IDOR report may need to show the owner email');
});
t('exploit payloads survive redaction', () => {
  // If this is masked, the report loses its evidence.
  const payload = "' UNION SELECT username,password FROM users-- <script>alert(1)</script> {{7*7}}";
  const out = EV.redactText(payload);
  assert.ok(out.includes('UNION'), 'SQL payload must survive');
  assert.ok(out.includes('alert(1)'), 'XSS payload must survive');
  assert.ok(out.includes('7*7'), 'SSTI probe must survive');
});

console.log('\n== evidence pairs ==');
t('a full request/response pair is sanitized but keeps its proof', () => {
  const out = EV.sanitizeEvidence({
    request: { method: 'GET', url: 'https://t/api/invoices/1', headers: { Cookie: 'mwa_session=secretvalue' }, body: null },
    response: { status: 200, headers: { 'Content-Type': 'application/json' }, body: '{"owner":"alice@corp.test","total":4200}' },
  });
  assert.ok(!/secretvalue/.test(JSON.stringify(out)), 'session must not survive');
  const ev = out.evidence;
  assert.strictEqual(ev.response.status, 200, 'the status code is the proof and must remain');
  assert.match(ev.response.body, /total/, 'the leaked field name is the proof');
  assert.strictEqual(ev.request.method, 'GET');
  // The PII review block intentionally retains matched values so a human can
  // judge them, which makes it the one place unredacted PII survives. It must
  // therefore be excluded from the artifact that actually gets submitted.
  const artifact = JSON.stringify(out.sanitized());
  assert.ok(!/alice@corp\.test/.test(artifact), 'submitted evidence must not contain the email');
  assert.ok(!/secretvalue/.test(artifact), 'submitted evidence must not contain the session');
  assert.ok(out.piiReview.some((x) => x.kind === 'email'), 'the human is still told to review it');
});


t('a RESPONSE body cannot leak a secret that only its key name reveals', () => {
  // Regression: response bodies went through free-text redaction, which only
  // catches tokens whose format is recognisable. An API echoing back
  // {"api_key":"sk-live-abc123"} leaked in full, because "sk-live-..." is not a
  // JWT, bearer token, or known key format. Both bodies now use key-aware
  // redaction.
  const out = EV.sanitizeEvidence({
    response: { status: 200, headers: {}, body: '{"api_key":"sk-live-abc123","user_secret":"hunter2","total":10}' },
  });
  const s = JSON.stringify(out.evidence);
  assert.ok(!/sk-live-abc123/.test(s), 'api_key leaked from the response body');
  assert.ok(!/hunter2/.test(s), 'user_secret leaked from the response body');
  assert.match(out.evidence.response.body, /total/, 'the evidence field survives');
});
t('a non-JSON, non-form body still gets text redaction', () => {
  const out = EV.sanitizeEvidence({ response: { status: 200, headers: {}, body: 'plain text with alice@corp.test' } });
  assert.match(out.evidence.response.body, /<redacted-email>/);
});

console.log('\n== pre-submission audit ==');
t('a report with a live JWT is blocked', () => {
  const a = EV.audit({ evidence: 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig' });
  assert.strictEqual(a.safe, false);
  assert.ok(a.blockers.some((p) => /jwt|auth/i.test(p.kind)));
});
t('a report with a live cookie value is blocked', () => {
  const a = EV.audit({ request: { headers: { Cookie: 'mwa_session=realsecretvalue' } } });
  assert.strictEqual(a.safe, false);
  assert.ok(a.blockers.some((p) => p.kind === 'cookie-value'), JSON.stringify(a.problems || a.blockers));
});
t('a report with an AWS key is blocked', () => {
  const a = EV.audit({ note: 'found AKIAIOSFODNN7EXAMPLE in JS' });
  assert.strictEqual(a.safe, false);
});
t('emails are flagged for review, not blocked', () => {
  const a = EV.audit({ body: 'leaked alice@corp.test and bob@corp.test' });
  assert.strictEqual(a.safe, true, 'a PII-exposure report is legitimate; the human decides');
  assert.ok(a.review.length >= 1);
  assert.match(a.review[0].detail, /include only if/i);
});
t('a properly redacted report is clean', () => {
  const a = EV.audit({
    request: { method: 'GET', url: 'https://t/api/invoices/1', headers: { Cookie: 'mwa_session=<redacted>' } },
    response: { status: 200, body: 'status 200 returned another user\'s invoice' },
  });
  assert.strictEqual(a.safe, true, JSON.stringify(a));
});
t('an empty report is safe', () => {
  assert.strictEqual(EV.audit({}).safe, true);
});

console.log('\n== PII review helper ==');
t('reviewForPii names what to look at and why', () => {
  const r = EV.reviewForPii('contact alice@corp.test card 4111111111111111');
  const kinds = r.map((x) => x.kind);
  assert.ok(kinds.includes('email'));
  assert.ok(kinds.includes('card-like number'));
  assert.ok(r.every((x) => x.why));
});

drain().then(() => {
  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
});
