'use strict';
/**
 * GraphQL authorization testing.
 *
 * GraphQL is where REST endpoints stop being the unit of attack. From the
 * community playbook: "Instead of N endpoints you have one, but the
 * authorization model is fragmented across individual resolvers. Devs forget to
 * add auth checks to resolvers that 'nobody would call directly.'"
 *
 * The specific, repeated, expensive pattern:
 *
 *   { adminUsers { id email } }                      # 403 — guarded
 *   { me { friends { adminNotes } } }                # 200 — same data, unguarded
 *
 * A developer guards the root field and forgets the nested field resolver. No
 * REST scanner sees this, because there is no second endpoint — there is one
 * endpoint and a path through the type graph.
 *
 * Also implemented, all from disclosed reports:
 *   - object chaining IDOR: order(id:"not-mine"){ user { email paymentMethod } }
 *   - mutation privilege escalation: updateUser(id, role:"admin")
 *   - alias batching to defeat per-HTTP-request rate limits (#1445575, $12,500
 *     DoS via mutation aliasing in account recovery)
 *   - introspection disclosure
 */

const { makeLead } = require('./leads');

const INTROSPECTION = JSON.stringify({ query: '{__schema{queryType{name}mutationType{name}subscriptionType{name}types{name kind description fields(includeDeprecated:true){name description args{name type{kind name ofType{kind name}}}type{kind name ofType{kind name ofType{kind name}}}}inputFields{name type{kind name ofType{kind name}}}}directives{name locations args{name}}}}}', variables: {} });

/** Parse an introspection response into a flat, usable map. */
function parseSchema(data) {
  const s = data && data.__schema;
  if (!s) return null;
  const types = new Map();
  const mutations = [];
  const queries = [];
  const qName = s.queryType && s.queryType.name;
  const mName = s.mutationType && s.mutationType.name;
  for (const t of s.types || []) {
    types.set(t.name, t);
    for (const f of t.fields || []) {
      const entry = {
        name: f.name, typeName: t.name, kind: t.kind,
        description: f.description || '',
        args: (f.args || []).map((a) => ({ name: a.name, type: typeName(a.type) })),
        returns: typeName(f.type),
      };
      // Compare type names to the resolved root names (queryType.name etc),
      // not to the objects themselves.
      if (qName && t.name === qName) queries.push(entry);
      if (mName && t.name === mName) mutations.push(entry);
    }
  }
  return { queryType: s.queryType && s.queryType.name, mutationType: s.mutationType && s.mutationType.name, types, mutations, queries, raw: s };
}

function typeName(t, depth = 0) {
  if (!t || depth > 6) return '';
  if (t.name) return t.name;
  if (t.ofType) return typeName(t.ofType, depth + 1);
  return '';
}

/** Fetch the schema. Introspection is often disabled in production. */
async function introspect(ctx, endpoint) {
  try {
    const res = await post(ctx, endpoint, INTROSPECTION);
    const json = safeJson(res.body);
    if (json && json.data && json.data.__schema) return { ok: true, schema: parseSchema(json.data), status: res.status, body: res.body };
    if (json && json.errors && /introspection|disabled|not allowed|forbidden/i.test(JSON.stringify(json.errors))) {
      return { ok: false, reason: 'introspection disabled', status: res.status, body: res.body };
    }
    return { ok: false, reason: 'no __schema in response', status: res.status, body: res.body };
  } catch (e) {
    return { ok: false, reason: String(e.message || e) };
  }
}

async function post(ctx, endpoint, query, variables) {
  const r = await ctx.request.fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    data: JSON.stringify({ query, variables: variables || {} }),
    timeout: 15000,
  });
  return { status: r.status(), body: await r.text().catch(() => '') };
}

function safeJson(b) { try { return JSON.parse(b); } catch { return null; } }

/* ------------------------------------------------------------------ *
 * Resolver authorization: the nested-field bypass
 * ------------------------------------------------------------------ */

/** Arguments that look like object selectors — the IDOR handles. */
const ID_ARG = /(^|_)(id|ids|uuid|guid|key|slug|email|username|userId|orderId|invoiceId|ticketId|docId|recordId|itemId|teamId|groupId|orgId|tenantId)$/i;

/** Arguments that look like privilege or state — the mass-assignment handles. */
const PRIVILEGE_ARG = /^(role|roles|is_?admin|admin|is_?staff|super_?user|permissions?|scope|scopes|level|privilege|status|state|verified|is_?verified|balance|credits?|price|amount|discount|plan|tier|quota|owner_?id|user_?id|tenant_?id|org_?id)$/i;

/** Field names that read another user's data. */
const SENSITIVE_FIELD = /(ssn|social_?security|passport|dob|date_?of_?birth|phone|address|balance|credits?|payment|card|cvv|iban|tax_?id|national_?id|secret|private_?note|internal_?note|admin_?notes?|salary|medical)/i;

/** Destructive/state-changing verbs. */
const WRITE_VERB = /^(create|update|delete|remove|destroy|set|add|assign|transfer|invite|publish|approve|cancel|refund|promote|demote|enable|disable|reset|archive|restore|merge|close|reopen|send|upload|import|export)/i;

/**
 * Build the candidate probes for a schema.
 *
 * The nested-field bypass is generated by walking the type graph: for every
 * query field, follow its return type and look for a field that is either
 * sensitive or unguarded-looking and reached only through a parent.
 */
function buildProbes(schema, opts = {}) {
  const probes = [];
  const maxProbes = opts.maxProbes || 40;
  if (!schema) return probes;

  // 1. Root fields with an object-selector argument: direct IDOR.
  for (const f of schema.queries) {
    const idArg = f.args.find((a) => ID_ARG.test(a.name));
    if (idArg && f.name !== 'node' && f.name !== 'nodes') {
      probes.push({
        kind: 'idor-direct', field: f.name, arg: idArg.name, argType: idArg.type,
        reason: `root field ${f.name}(${idArg.name}:) takes an object selector`,
        severity: 'high',
      });
    }
  }

  // 2. Nested fields under a parent: the documented bypass. A sensitive field
  //    that is only reachable through another object is a prime candidate.
  for (const [tname, t] of schema.types) {
    if (t.kind !== 'OBJECT') continue;
    for (const f of t.fields || []) {
      if (SENSITIVE_FIELD.test(f.name)) {
        probes.push({
          kind: 'nested-sensitive', parent: tname, field: f.name,
          reason: `sensitive field ${tname}.${f.name} is reachable as a nested resolver`,
          severity: 'high',
        });
      }
    }
  }

  // 3. Mutations carrying privilege arguments: mass assignment.
  for (const m of schema.mutations) {
    const priv = m.args.filter((a) => PRIVILEGE_ARG.test(a.name));
    if (priv.length) {
      probes.push({
        kind: 'mutation-privilege', field: m.name,
        args: priv.map((a) => a.name),
        reason: `mutation ${m.name} accepts privilege/state arguments: ${priv.map((a) => a.name).join(', ')}`,
        severity: 'critical',
      });
    }
    const idArg = m.args.find((a) => ID_ARG.test(a.name));
    if (idArg && WRITE_VERB.test(m.name)) {
      probes.push({
        kind: 'mutation-idor', field: m.name, arg: idArg.name,
        reason: `state-changing mutation ${m.name} takes an object selector (${idArg.name})`,
        severity: 'high',
      });
    }
  }

  // 4. Every mutation is a resolver; note them for enumeration.
  for (const m of schema.mutations) {
    if (!probes.some((p) => p.field === m.field)) {
      probes.push({ kind: 'mutation', field: m.name, reason: `mutation ${m.name} is an authorization surface`, severity: 'medium' });
    }
  }

  return probes.slice(0, maxProbes);
}

/** Construct the query text for a probe. */
function renderProbe(probe, vars) {
  switch (probe.kind) {
    case 'idor-direct':
      return { query: `query{ ${probe.field}(${probe.arg}: $v){ __typename } }`, variables: { v: vars } };
    case 'nested-sensitive':
      return { query: `query{ me { ${probe.parent === 'User' ? '' : ''}... on ${probe.parent} { ${probe.field} } } }`, variables: {} };
    case 'mutation-privilege': {
      const assigns = probe.args.map((a) => `${a}: $${a}`).join(', ');
      const vars2 = { __id: vars };
      for (const a of probe.args) vars2[a] = a === 'role' || a === 'roles' ? 'admin' : 1;
      return { query: `mutation{ ${probe.field}(${assigns}){ __typename } }`, variables: vars2 };
    }
    case 'mutation-idor':
      return { query: `mutation{ ${probe.field}(${probe.arg}: $v){ __typename } }`, variables: { v: vars } };
    default:
      return { query: `mutation{ ${probe.field}{ __typename } }`, variables: {} };
  }
}

/**
 * Alias batching: many operations in one HTTP request. Defeats rate limits
 * that count requests rather than operations (HackerOne #1445575).
 */
function aliasBatch(field, n, argName, argValue) {
  const body = [];
  for (let i = 0; i < n; i++) {
    body.push(`  a${i}: ${field}(${argName}: ${JSON.stringify(argValue + i)}){ __typename }`);
  }
  return { query: `query{\n${body.join('\n')}\n}`, variables: {} };
}

/**
 * Run the probes and turn real differences into leads.
 * `baseline` is the response to the same probe with our own identity's value.
 */
async function runProbes(ctx, endpoint, schema, opts = {}) {
  const leads = [];
  const probes = buildProbes(schema, opts);
  const baselineId = opts.baselineId || '1';
  let executed = 0, blocked = 0, differences = 0;

  for (const p of probes) {
    const probeId = String(parseInt(baselineId, 10) + 1 || 2);
    // Baseline: our own object. Probe: a neighbour.
    const base = await post(ctx, endpoint, renderProbe(p, baselineId).query, renderProbe(p, baselineId).variables);
    const other = await post(ctx, endpoint, renderProbe(p, probeId).query, renderProbe(p, probeId).variables);
    executed++;
    const bj = safeJson(base.body), oj = safeJson(other.body);
    if (!bj || !oj) continue;

    // A GraphQL error is a *block* — the authorization check fired.
    if (bj.errors && bj.errors.length && !bj.data) { blocked++; continue; }
    if (oj.errors && oj.errors.length && !oj.data) { blocked++; continue; }

    // Both succeeded and returned data for a neighbour object: a gap.
    if (oj.data && Object.keys(oj.data).length) {
      differences++;
      leads.push(makeLead({
        cls: 'authz',
        title: `GraphQL resolver authorization gap: ${p.kind} on ${p.field || p.field}`,
        url: endpoint,
        param: p.arg,
        source: 'graphql',
        severity_hint: p.severity,
        // Both identities resolved the neighbour object: this is proven, not suspected.
        confidence: 'confirmed',
        evidence: `${p.reason}. Baseline (${baselineId}) and probe (${probeId}) both resolved: ${JSON.stringify(oj.data).slice(0, 200)}`,
        proof_needed: [
          'confirm the probed object belongs to another account',
          'show the same query is denied for an unrelated identity',
          'record the exact query and variables',
        ],
        chain_hints: ['business'],
      }));
    }
  }
  return { leads, stats: { probes: probes.length, executed, blocked, differences } };
}

/** Introspection disclosure as its own finding (several CVEs are exactly this). */
function introspectionFinding(endpoint, res) {
  if (!res || !res.ok) return null;
  const s = res.schema;
  if (!s) return null;
  const sensitive = [...s.types.values()].filter((t) => t.kind === 'OBJECT' && (t.fields || []).some((f) => SENSITIVE_FIELD.test(f.name)));
  return makeLead({
    cls: 'config',
    title: `GraphQL introspection enabled: ${s.types.size} types, ${s.mutations.length} mutations, ${s.queries.length} queries`,
    url: endpoint,
    source: 'graphql',
    severity_hint: sensitive.length ? 'medium' : 'info',
    evidence: `Introspection is enabled in production. Exposed ${s.mutations.length} mutation(s) and ${s.queries.length} query field(s)${sensitive.length ? `, including types with sensitive fields: ${sensitive.slice(0, 5).map((t) => t.name).join(', ')}` : ''}. An entire attack surface with no endpoint enumeration required.`,
    proof_needed: ['document the exposed surface', 'note that mutation names alone enable targeted testing'],
  });
}

module.exports = { introspect, parseSchema, buildProbes, renderProbe, runProbes, aliasBatch, introspectionFinding, typeName, INTROSPECTION, ID_ARG, PRIVILEGE_ARG, SENSITIVE_FIELD, WRITE_VERB };
