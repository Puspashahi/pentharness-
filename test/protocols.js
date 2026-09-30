'use strict';
/**
 * Tests for GraphQL, JWT, cache-poisoning and ATO-chain detection.
 * The negative cases matter as much as the positive ones: a JWT tester that
 * "accepts" everything, or a cache tester that calls plain reflection
 * poisoning, is worse than no tester.
 */
const assert = require('assert');

const GQL = require('../src/graphql');
const JWT = require('../src/jwt');
const CACHE = require('../src/cache');
const ATO = require('../src/atoj');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log(`  ok  ${name}`); pass++; }
  catch (e) { console.log(`  FAIL ${name}\n       ${e.message}`); fail++; }
}

console.log('\n== graphql: schema parsing ==');
const SCHEMA_JSON = { data: { __schema: {
  queryType: { name: 'Query' }, mutationType: { name: 'Mutation' },
  types: [
    { kind: 'OBJECT', name: 'Query', fields: [
      { name: 'user', args: [{ name: 'id', type: { name: 'ID' } }], type: { name: 'User' } },
      { name: 'me', args: [], type: { name: 'User' } },
      { name: 'adminUsers', args: [], type: { name: 'User' } },
    ] },
    { kind: 'OBJECT', name: 'Mutation', fields: [
      { name: 'updateUser', args: [{ name: 'id', type: { name: 'ID' } }, { name: 'role', type: { name: 'String' } }], type: { name: 'User' } },
      { name: 'transferCredits', args: [{ name: 'fromId', type: { name: 'ID' } }, { name: 'amount', type: { name: 'Int' } }], type: { name: 'Boolean' } },
    ] },
    { kind: 'OBJECT', name: 'User', fields: [
      { name: 'adminNotes', args: [], type: { name: 'String' } },
      { name: 'paymentMethod', args: [], type: { name: 'String' } },
    ] },
  ],
} } };

t('parses queries, mutations and types from introspection', () => {
  const s = GQL.parseSchema(SCHEMA_JSON.data);
  assert.strictEqual(s.queries.length, 3);
  assert.strictEqual(s.mutations.length, 2);
  assert.ok(s.types.has('User'));
});
t('introspection response parses end to end', async () => {
  const ctx = { request: { fetch: async () => ({ status: () => 200, text: async () => JSON.stringify(SCHEMA_JSON) }) } };
  const r = await GQL.introspect(ctx, 'https://t/graphql');
  assert.strictEqual(r.ok, true);
  assert.ok(r.schema.mutations.length === 2);
});
t('disabled introspection is reported, not crashed on', async () => {
  const ctx = { request: { fetch: async () => ({ status: () => 200, text: async () => JSON.stringify({ errors: [{ message: 'introspection is disabled' }] }) }) } };
  const r = await GQL.introspect(ctx, 'https://t/graphql');
  assert.strictEqual(r.ok, false);
  assert.ok(/disabled/.test(r.reason));
});

console.log('\n== graphql: the nested-resolver bypass ==');
t('detects a root IDOR field (user(id:))', () => {
  const s = GQL.parseSchema(SCHEMA_JSON.data);
  const p = GQL.buildProbes(s);
  assert.ok(p.some((x) => x.kind === 'idor-direct' && x.field === 'user'), JSON.stringify(p.map((x) => x.kind)));
});
t('detects the nested sensitive-field bypass (User.adminNotes)', () => {
  const s = GQL.parseSchema(SCHEMA_JSON.data);
  const p = GQL.buildProbes(s);
  assert.ok(p.some((x) => x.kind === 'nested-sensitive' && x.field === 'adminNotes'), 'the documented bypass must be found');
});
t('detects mutation privilege escalation (updateUser(role:))', () => {
  const s = GQL.parseSchema(SCHEMA_JSON.data);
  const p = GQL.buildProbes(s);
  const m = p.find((x) => x.kind === 'mutation-privilege' && x.field === 'updateUser');
  assert.ok(m, 'updateUser(role:) must be flagged');
  assert.strictEqual(m.severity, 'critical');
});
t('detects state-changing IDOR on a mutation', () => {
  const s = GQL.parseSchema(SCHEMA_JSON.data);
  assert.ok(GQL.buildProbes(s).some((x) => x.kind === 'mutation-idor'));
});
t('alias batching produces N operations in one document', () => {
  const b = GQL.aliasBatch('login', 3, 'username', 'admin');
  assert.ok(/a0:/.test(b.query) && /a2:/.test(b.query));
  assert.strictEqual((b.query.match(/login\(/g) || []).length, 3);
});

console.log('\n== graphql: probe execution ==');
t('a GraphQL error counts as a BLOCK, not a gap', async () => {
  const ctx = { request: { fetch: async () => ({ status: () => 200, text: async () => JSON.stringify({ errors: [{ message: 'forbidden' }] }) }) } };
  const s = GQL.parseSchema(SCHEMA_JSON.data);
  const r = await GQL.runProbes(ctx, 'https://t/graphql', s, { maxProbes: 4 });
  assert.strictEqual(r.stats.differences, 0, 'a blocked probe must not be a finding');
  assert.ok(r.stats.blocked > 0);
});
t('both identities resolving a neighbour is a finding', async () => {
  const ctx = { request: { fetch: async () => ({ status: () => 200, text: async () => JSON.stringify({ data: { user: { __typename: 'User' } } }) }) } };
  const s = GQL.parseSchema(SCHEMA_JSON.data);
  const r = await GQL.runProbes(ctx, 'https://t/graphql', s, { maxProbes: 4 });
  assert.ok(r.stats.differences > 0, 'expected at least one gap');
  assert.ok(r.leads.every((l) => l.cls === 'authz'));
});

console.log('\n== jwt: parsing and forging ==');
const TOKEN = JWT.forge({ alg: 'HS256', typ: 'JWT' }, { sub: '42', role: 'user' }, 'sig');
t('parses a three-part token', () => {
  const p = JWT.parse(TOKEN);
  assert.strictEqual(p.valid, true);
  assert.strictEqual(p.payload.sub, '42');
});
t('rejects a malformed token without throwing', () => {
  assert.strictEqual(JWT.parse('not.a.jwt.at.all').valid, false);
  assert.strictEqual(JWT.parse('').valid, false);
  assert.strictEqual(JWT.parse(null).valid, false);
});
t('alg:none forgery is offered as a critical mutation', () => {
  const m = JWT.mutations(TOKEN);
  const n = m.find((x) => x.id === 'alg-none');
  assert.ok(n, 'alg:none must be tested');
  assert.strictEqual(n.severity, 'critical');
  assert.strictEqual(JWT.parse(n.token).header.alg.toLowerCase(), 'none');
  assert.strictEqual(n.token.split('.').pop(), '', 'alg:none token must have an empty signature');
});
t('kid path traversal is tested', () => {
  assert.ok(JWT.mutations(TOKEN).some((x) => x.id === 'kid-traversal'));
});
t('privilege claim escalation is tested', () => {
  const m = JWT.mutations(TOKEN);
  const role = m.find((x) => x.id === 'claim-role');
  assert.ok(role, 'role claim escalation must be offered');
  // "admin" is base64url-encoded in the token, so assert on the decoded payload.
  assert.strictEqual(JWT.parse(role.token).payload.role, 'admin');
});
t('weak-secret candidates are only produced for HMAC tokens', () => {
  assert.ok(JWT.secretCandidates(TOKEN).length > 0);
  const rs = JWT.forge({ alg: 'RS256' }, { sub: '1' }, 's');
  assert.strictEqual(JWT.secretCandidates(rs).length, 0, 'RS256 is not an HMAC secret test');
});
t('alg confusion is offered for asymmetric tokens', () => {
  const rs = JWT.forge({ alg: 'RS256' }, { sub: '1' }, 's');
  assert.ok(JWT.mutations(rs).some((x) => x.id === 'alg-confusion'));
});

console.log('\n== jwt: acceptance is measured, not assumed ==');
t('a 401 for every mutation yields no leads', async () => {
  const ctx = { request: { fetch: async () => ({ status: () => 401, text: async () => '{"error":"unauthorized"}' }) } };
  const r = await JWT.test(ctx, { url: 'https://t/api/me', token: TOKEN });
  assert.ok(r.results.every((x) => !x.accepted), 'nothing should be accepted');
  assert.strictEqual(JWT.toLeads(r.results, {}).length, 0);
});
t('a mutation accepted where the original 401s becomes a lead', async () => {
  let n = 0;
  const ctx = { request: { fetch: async (_u, o) => {
    const tok = (o.headers || {}).Authorization || '';
    n++;
    if (tok.includes('"alg":"none"') || tok.includes('"alg":"None"')) return { status: () => 200, text: async () => '{"user":"admin"}' };
    return { status: () => 401, text: async () => '{"error":"unauthorized"}' };
  } } };
  const r = await JWT.test(ctx, { url: 'https://t/api/me', token: TOKEN });
  const leads = JWT.toLeads(r.results, { url: 'https://t/api/me' });
  assert.ok(leads.length >= 1, 'alg:none acceptance must produce a lead');
  assert.ok(leads.some((l) => /JWT accepted/.test(l.title)));
});

console.log('\n== cache poisoning: reflection is not poisoning ==');
t('plain reflection without caching is NOT reported as poisoning', async () => {
  const ctx = { request: { fetch: async (_u, o) => {
    const h = o.headers || {};
    const v = h['x-forwarded-host'] || '';
    return { status: () => 200, text: async () => `<html>host: ${v || 'example.com'}</html>` };
  } } };
  const r = await CACHE.probeHeader(ctx, 'https://t/', 'x-forwarded-host');
  assert.strictEqual(r.poisoned, false);
  assert.ok(/not cached/.test(r.reason), r.reason);
});
t('a canary that survives a clean request IS poisoning', async () => {
  let seeded = false;
  const ctx = { request: { fetch: async (_u, o) => {
    const v = (o.headers || {})['x-forwarded-host'];
    if (v) { seeded = true; return { status: () => 200, text: async () => `<html>${v}</html>` }; }
    // Clean request: served from the poisoned cache entry.
    return { status: () => 200, text: async () => seeded ? '<html>poison-value</html>' : '<html>ok</html>' };
  } } };
  const r = await CACHE.probeHeader(ctx, 'https://t/', 'x-forwarded-host', { value: 'poison-value' });
  assert.strictEqual(r.poisoned, true, r.reason);
  assert.ok(/did not send the header/.test(r.reason));
});
t('a header that is not reflected is ignored', async () => {
  const ctx = { request: { fetch: async () => ({ status: () => 200, text: async () => '<html>static</html>' }) } };
  assert.strictEqual((await CACHE.probeHeader(ctx, 'https://t/', 'x-original-url')).poisoned, false);
});

console.log('\n== ato chains ==');
t('a jwt-weak + id + email + reset corpus yields a complete takeover chain', () => {
  const corpus = `
    {"user":{"id":"usr_9f2","workspaces":[{"users":[{"id":"usr_owner"}]}]}}
    mutation ProfileFormUpdateUser($id:ID!,$email:String){ updateUser(id:$id,email:$email){id} }
    POST /forgot-password  action=sendResetLink
  `;
  const obs = ATO.observe(corpus);
  assert.ok(obs.has('id_disclosure'));
  assert.ok(obs.has('email_change'));
  assert.ok(obs.has('password_reset'));
  // jwt_weak is observed by replaying forged tokens against a live endpoint,
  // not by scanning text, so it is added here as the JWT tester would add it.
  obs.add('jwt_weak');
  const chains = ATO.reachableChains(obs);
  const full = chains.find((c) => c.id === 'jwt-forgery-ato');
  assert.ok(full && full.complete, 'expected jwt-forgery-ato to be complete: ' + chains.map((c) => c.id + ':' + c.complete).join(','));
  assert.strictEqual(full.severity, 'critical');
  assert.ok(ATO.toLeads(chains, {}).length >= 1);
});
t('a partial capability set yields an incomplete chain, not a finding', () => {
  const chains = ATO.reachableChains(new Set(['password_reset']));
  assert.ok(chains.every((c) => !c.complete || c.id !== 'jwt-forgery-ato'));
  assert.strictEqual(ATO.toLeads(chains, {}).length, 0, 'an incomplete chain must not become a lead');
});
t('a single MFA disclosure is a critical chain on its own', () => {
  const c = ATO.reachableChains(new Set(['totp_disclosure']));
  assert.ok(c.some((x) => x.id === 'mfa-bypass' && x.complete));
});
t('a clean corpus yields nothing', () => {
  const obs = ATO.observe('<html><body>hello</body></html>');
  assert.strictEqual(ATO.toLeads(ATO.reachableChains(obs), {}).length, 0);
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
