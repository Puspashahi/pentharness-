/**
 * Protocol-level stage: GraphQL, JWT, cache poisoning, and ATO chain assembly.
 * Runs against the knowledge base and captured corpus, feeding the same
 * deterministic validators as the rest of the harness.
 */
'use strict';

const GQL = require('./graphql');
const JWT = require('./jwt');
const CACHE = require('./cache');
const MCP = require('./mcp');
const ATO = require('./atoj');
const { makeLead } = require('./leads');

/**
 * @param ctx.request request context
 * @param opts { target, kb, corpus:Array, store, log }
 */
async function runProtocolStage(ctxIn, opts) {
  const { target, kb, store } = opts;
  const out = { leads: [], notes: [], stats: {} };
  const log = opts.log || (() => {});
  const corpus = Array.isArray(opts.corpus) ? opts.corpus.join('\n') : String(opts.corpus || '');

  // The stage needs a request context with POST support (GraphQL) and header
  // control (cache). The probe stage may not have created one, so normalise
  // whatever we were handed into something that can issue the verbs we need.
  const ctx = ensureVerbSupport(ctxIn);

  // ---- GraphQL ----
  const gqlEndpoints = findGraphQL(target, kb, corpus);
  if (gqlEndpoints.length) {
    for (const ep of gqlEndpoints) {
      const intro = await GQL.introspect(ctx, ep);
      if (intro.ok && intro.schema) {
        const disc = GQL.introspectionFinding(ep, intro);
        if (disc) out.leads.push(disc);
        const probes = await GQL.runProbes(ctx, ep, intro.schema, { maxProbes: opts.maxGqlProbes || 12 });
        out.leads.push(...probes.leads);
        out.stats.graphql = { endpoint: ep, types: intro.schema.types.size, mutations: intro.schema.mutations.length, ...probes.stats };
        log('graphql', `${ep}: ${intro.schema.types.size} types, ${probes.stats.differences} resolver gap(s), ${probes.stats.blocked} blocked`);
      } else {
        out.stats.graphql = { endpoint: ep, introspection: intro.reason };
        log('graphql', `${ep}: ${intro.reason}`);
      }
    }
  }

  // ---- JWT: find a token, then replay mutations against an authenticated URL ----
  const token = findToken(corpus);
  if (token) {
    const authUrl = findAuthUrl(kb, corpus) || target;
    const r = await JWT.test(ctx, { url: authUrl, token: token.raw, headers: token.headers });
    const leads = JWT.toLeads(r.results, { url: authUrl });
    out.leads.push(...leads);
    out.stats.jwt = { endpoint: authUrl, original: r.original.status, mutations: r.results.length, accepted: leads.length };
    log('jwt', `${leads.length}/${r.results.length} mutation(s) accepted at ${authUrl}`);
    if (leads.length) out.observedJwtWeak = true;
  } else {
    out.stats.jwt = { note: 'no JWT found in captures' };
  }

  // ---- Cache poisoning on the most promising URL ----
  const cacheUrl = pickCacheUrl(kb, target);
  if (cacheUrl && !opts.skipCache) {
    const c = await CACHE.probe(ctx, cacheUrl, { maxFindings: 2, attempts: 2 });
    out.leads.push(...CACHE.toLeads(c));
    out.stats.cache = { url: cacheUrl, poisoned: c.found.length };
    if (c.found.length) log('cache', `${c.found.length} unkeyed header(s) on ${cacheUrl}`);
  }

  // ---- MCP / AI-agent surface ----
  const mcpEndpoints = findMCP(target, kb, corpus);
  if (mcpEndpoints.length) {
    for (const ep of mcpEndpoints) {
      const a = await MCP.auditServer(ctx.request ? { request: ctx.request } : ctx, ep);
      if (a.ok) {
        out.leads.push(...MCP.toLeads(a, { url: ep }));
        out.stats.mcp = { endpoint: ep, ...a.summary };
        log('mcp', `${ep}: ${a.summary.tools} tool(s), ${a.summary.poisoned} poisoned, ${a.summary.excessiveAuthority} excessive-authority`);
        if (a.summary.poisoned || a.summary.excessiveAuthority) out.observedAiWeak = true;
      } else {
        out.stats.mcp = { endpoint: ep, note: a.reason };
      }
    }
  }

  // ---- ATO chain assembly ----
  const observed = ATO.observe(corpus);
  if (out.observedJwtWeak) observed.add('jwt_weak');
  if (out.observedAiWeak) observed.add('excessive_tool_authority');
  const chains = ATO.reachableChains(observed);
  out.atoChains = chains;
  out.leads.push(...ATO.toLeads(chains, { url: target }));
  const complete = chains.filter((c) => c.complete);
  if (complete.length) log('ato', `${complete.length} takeover chain(s) reachable: ${complete.map((c) => c.id).join(', ')}`);

  return out;
}

/* ---------- discovery helpers ---------- */

/**
 * Guarantee the context can issue arbitrary verbs. A GET-only context (the
 * lightweight fetch fallback) is wrapped so GraphQL POSTs and cache probes
 * with custom headers still work.
 */
function ensureVerbSupport(ctx) {
  if (ctx && ctx.request && typeof ctx.request.fetch === 'function') return ctx;
  const base = (ctx && ctx.request && typeof ctx.request.get === 'function') ? ctx.request : null;
  return {
    request: {
      get: (url, opts) => (base ? base.get(url, opts) : failGet(url)),
      fetch: (url, opts = {}) => {
        if (base && typeof base.fetch === 'function') return base.fetch(url, opts);
        // A GET-only context cannot carry a POST body. Rather than silently
        // dropping the query (which yields a confusing "no __schema"), issue
        // the GET equivalent and let the caller see a real error. Most GraphQL
        // servers accept introspection over GET, so this still works.
        const method = String(opts.method || 'GET').toUpperCase();
        const viaGet = base
          ? base.get(url, { ...opts, _method: method, data: opts.data, headers: { Accept: 'application/json', ...(opts.headers || {}) } })
          : failGet(url);
        return viaGet;
      },
    },
  };
}

function failGet(url) {
  return Promise.resolve({ status: () => 0, text: async () => '', url: () => url, headers: () => ({}) });
}

function findGraphQL(target, kb, corpus) {
  const found = new Set();
  for (const u of kb.endpoints.keys()) if (/\/graphql|\/gql|graphql/i.test(u)) found.add(u);
  for (const e of kb.endpoints.keys()) {
    // Common GraphQL paths on the origin.
    for (const p of ['/graphql', '/api/graphql', '/gql', '/v1/graphql', '/query']) {
      try { found.add(new URL(p, e).toString()); } catch { /* skip */ }
    }
  }
  if (/\/graphql\b/i.test(corpus)) { try { found.add(new URL('/graphql', target).toString()); } catch { /* skip */ } }
  return [...found].slice(0, 3);
}

function findToken(corpus) {
  // JWT pattern: three base64url segments. Also pick up the cookie/header name.
  const m = String(corpus).match(/\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*/);
  if (!m) return null;
  const around = String(corpus).slice(Math.max(0, m.index - 200), m.index);
  const nameMatch = around.match(/(authorization|cookie|token|access_token|jwt)["'\s:=]+/i);
  return { raw: m[0], headers: {}, name: nameMatch ? nameMatch[1] : 'Authorization' };
}

function findAuthUrl(kb, corpus) {
  // An authenticated-looking endpoint is a better JWT replay target than "/".
  const candidates = [...kb.endpoints.keys()].filter((u) => /\/api\/|\/me\b|\/account|\/user\b|\.json$/i.test(u));
  return candidates[0] || null;
}

/** Common MCP paths plus anything the corpus or KB already mentions. */
function findMCP(target, kb, corpus) {
  const found = new Set();
  for (const u of kb.endpoints.keys()) if (/mcp/i.test(u)) found.add(u);
  if (/\btools\/list|mcpServers|modelcontextprotocol/i.test(String(corpus))) {
    for (const p of ['/mcp', '/mcp/', '/api/mcp', '/mcp/rpc', '/rpc']) {
      try { found.add(new URL(p, target).toString()); } catch { /* skip */ }
    }
  }
  return [...found].slice(0, 3);
}

function pickCacheUrl(kb, target) {
  // Prefer a URL that reflects a host (pages render it); a JSON API is a poor
  // cache-poisoning target because the body is not usually reflected.
  const pages = [...kb.endpoints.keys()].filter((u) => !/\.json|\/api\//i.test(u));
  return pages[0] || target;
}

module.exports = { runProtocolStage, findGraphQL, findToken, findAuthUrl, pickCacheUrl, findMCP };
