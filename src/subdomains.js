'use strict';
/**
 * Subdomain discovery with scope enforcement.
 *
 * Single-host testing only ever sees one host, which is the practical limit on
 * "works on any target". Most real findings live on a subdomain nobody links
 * from the homepage: an internal API, a forgotten staging host, an admin panel
 * on its own origin. On a real target, subfinder returns thousands of
 * candidates, so the hard part is not finding them — it is deciding which ones
 * are in scope, which are alive, and which deserve attention.
 *
 * Two failure modes this module is built around:
 *
 * 1. Testing out of scope. A program scope of `target.tld` usually does NOT
 *    cover every subdomain, and hitting an out-of-scope host is a policy
 *    violation, not just a wasted request. Scope is enforced here, before any
 *    request is made, and every rejection is recorded with its reason.
 *
 * 2. Drowning in noise. A thousand subdomains, most dead or third-party
 *    (Azure/Cloudflare CNAME targets, marketing CDNs). Ranking by what is worth
 *    testing keeps the run focused on hostnames that actually plausibly hold a
 *    vulnerability.
 */

/** Hostname fragments that suggest an exposed or forgotten asset. */
const INTERESTING = [
  { rx: /^(dev|develop|development|dev\d)/i, weight: 10, why: 'development environment' },
  { rx: /^(stg|stage|staging|uat|qa|test|testing|sandbox|preprod|pre-prod)/i, weight: 10, why: 'non-production environment' },
  { rx: /^(admin|administrator|manage|manager|panel|cpanel|webadmin|admin\d)/i, weight: 9, why: 'administrative interface' },
  { rx: /^(api|apis|apigw|gateway|rest|graphql|grpc|ws)\d*\.?/i, weight: 8, why: 'API surface' },
  { rx: /^(internal|intranet|corp|private|backend|origin)/i, weight: 8, why: 'internal-facing host' },
  { rx: /^(vpn|remoteaccess|ras|sslvpn|citrix|rdp|ssh|bastion|jump)/i, weight: 9, why: 'remote access entry point' },
  { rx: /^(git|gitlab|github|gitea|jenkins|ci|cd|build|jenkins)/i, weight: 8, why: 'source or CI system' },
  { rx: /^(jira|confluence|sonar|nexus|artifactory|registry|docker|k8s|kube|consul|vault)/i, weight: 7, why: 'infrastructure tooling' },
  { rx: /^(mail|smtp|imap|pop|webmail|exchange|owa)/i, weight: 5, why: 'mail system' },
  { rx: /^(db|database|sql|mysql|postgres|mongo|redis|elastic|cache)/i, weight: 8, why: 'datastore exposed' },
  { rx: /(uat|qa|stg|dev|temp|tmp|old|legacy|backup|bak|deprecated|archive)/i, weight: 8, why: 'possibly forgotten' },
  { rx: /\d{1,3}(?:\.\d{1,3}){3}/, weight: 7, why: 'IP-based host' },
  { rx: /^(admin|secure|login|auth|sso|idp|vpn|support)/i, weight: 6, why: 'sensitive name' },
  { rx: /\d{4,}/, weight: 4, why: 'looks like a build or environment id' },
];

/** CNAME targets that indicate a third-party SaaS, not the client's own asset. */
const THIRD_PARTY_CNAME = [
  /\.azurewebsites\.net$/i, /\.cloudapp\.net$/i, /\.cloudfront\.net$/i,
  /\.amazonaws\.com$/i, /\.s3\.amazonaws\.com$/i, /\.elb\.amazonaws\.com$/i,
  /\.trafficmanager\.net$/i, /\.herokuapp\.com$/i, /\.vercel\.app$/i,
  /\.netlify\.app$/i, /\.pages\.dev$/i, /\.web\.app$/i, /\.firebaseapp\.com$/i,
  /\.github\.io$/i, /\.gitlab\.io$/i, /\.onrender\.com$/i, /\.fly\.dev$/i,
  /\.digitaloceanspaces\.com$/i, /\.blob\.core\.windows\.net$/i,
  /\.azurefd\.net$/i, /\.fastly\.net$/i, /\.akamaitechnologies\.com$/i,
  /\.wordpress\.com$/i, /\.myshopify\.com$/i, /\.ghost\.io$/i,
];

/**
 * Is a host inside the declared scope?
 *
 * Scope semantics follow how programs actually write them:
 *   exact host      "app.target.tld"          -> that host only
 *   suffix with dot "*.target.tld" or ".target.tld" -> subdomains, not the apex
 *   bare domain     "target.tld"              -> apex + all subdomains
 */
function inScope(host, scope = []) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  if (!h) return { ok: false, reason: 'empty hostname' };
  const rules = (Array.isArray(scope) ? scope : [scope]).filter(Boolean).map((s) => String(s).toLowerCase().replace(/^\*\./, '.').replace(/\/$/, ''));
  if (!rules.length) return { ok: true, reason: 'no scope declared — assuming the target host is authorised' };

  for (const rule of rules) {
    const isWildcard = rule.startsWith('.');
    const base = isWildcard ? rule.slice(1) : rule;
    // The rule host itself is always in scope, whether or not it is written
    // as a wildcard. A scope of "target.tld" obviously covers target.tld, and
    // "*.target.tld" likewise covers the domain it is anchored to.
    if (h === base) {
      // A wildcard scope includes the domain it is anchored to. Programs that
      // write "*.target.tld" almost always mean the whole domain, and treating
      // the apex as excluded would refuse to test the host the researcher was
      // explicitly given. Use a bare rule without a wildcard when the apex is
      // genuinely out of scope.
      return { ok: true, reason: `within scope rule ${rule}` };
    }
    // Subdomain of the rule's base.
    if (h.endsWith(`.${base}`)) {
      // A leading dot means "subdomains", which some programs intend to exclude
      // the apex from; honour that strictly.
      return isWildcard
        ? { ok: true, reason: `subdomain of wildcard scope ${rule}` }
        : { ok: true, reason: `subdomain of scope ${rule}` };
    }
  }
  return { ok: false, reason: `not covered by any scope rule (${rules.join(', ')})` };
}

/** Rank a subdomain by how likely it is to hold a real finding. */
function rank(host, meta = {}) {
  let score = 0;
  const reasons = [];
  for (const rule of INTERESTING) {
    if (rule.rx.test(host)) { score += rule.weight; reasons.push(rule.why); }
  }
  if (meta.status && meta.status < 400) score += 6;
  else if (meta.status === 401 || meta.status === 403) score += 5;   // alive, gated
  if (meta.title) score += 2;
  if (meta.tech && meta.tech.length) score += 2;
  if (meta.cname && THIRD_PARTY_CNAME.some((rx) => rx.test(meta.cname))) {
    score -= 3;
    reasons.push('third-party CDN/SaaS target (takeover candidate, not a first-party asset)');
  }
  // Punycode / very deep names are usually generated noise.
  if (/^xn--/.test(host)) score -= 4;
  if (host.split('.').length > 5) score -= 2;
  if (/\d{6,}/.test(host)) score -= 3;   // long numeric ids: machine-generated
  return { score, reasons: [...new Set(reasons)] };
}

/** Parse subfinder output, which mixes bare hosts and JSON lines. */
function parseSubfinder(stdout = '') {
  const hosts = new Map();
  for (const line of String(stdout).split(/\r?\n/)) {
    const s = line.trim();
    if (!s) continue;
    if (s.startsWith('{')) {
      try {
        const j = JSON.parse(s);
        const h = j.host || j.input || j.name;
        if (h) hosts.set(String(h).toLowerCase(), { host: String(h).toLowerCase(), source: j.source || 'subfinder', cname: j.cname || '' });
        continue;
      } catch { /* fall through to the plain-text form */ }
    }
    if (/^[a-z0-9._-]+$/i.test(s) && s.includes('.')) hosts.set(s.toLowerCase(), { host: s.toLowerCase(), source: 'subfinder', cname: '' });
  }
  return [...hosts.values()];
}

/**
 * Split discovered hosts into in-scope, out-of-scope and third-party.
 * Out-of-scope hosts are reported, never probed — a violation is worse than a
 * missed finding.
 */
function triage(hosts = [], scope = [], live = new Map()) {
  const inScopeList = [];
  const outOfScope = [];
  const thirdParty = [];

  for (const h of hosts) {
    const name = typeof h === 'string' ? { host: h.toLowerCase(), cname: '' } : { host: String(h.host).toLowerCase(), cname: h.cname || '' };
    const s = inScope(name.host, scope);
    if (!s.ok) { outOfScope.push({ ...name, reason: s.reason }); continue; }
    // A third-party CNAME is still in scope for *reading* (dangling DNS is a
    // finding), but it is not a first-party asset to test, so it is tracked
    // separately and must not also be counted as in-scope.
    if (name.cname && THIRD_PARTY_CNAME.some((rx) => rx.test(name.cname))) {
      thirdParty.push({ ...name, why: `CNAME ${name.cname} points at a third-party service`, score: rank(name.host, {}).score });
      continue;
    }
    const meta = live.get(name.host) || {};
    const r = rank(name.host, meta);
    inScopeList.push({ ...name, score: r.score, reasons: r.reasons, status: meta.status, title: meta.title, tech: meta.tech });
  }

  inScopeList.sort((a, b) => b.score - a.score);
  return {
    inScope: inScopeList,
    outOfScope,
    thirdParty,
    totals: { discovered: hosts.length, inScope: inScopeList.length, outOfScope: outOfScope.length, thirdParty: thirdParty.length },
  };
}

/**
 * Dangerous hostnames worth a look even when nothing else is known.
 * These are read-only GET requests for well-known files.
 */
function sensitivePaths() {
  return [
    { path: '/.git/HEAD', cls: 'config', why: 'exposed git repository' },
    { path: '/.env', cls: 'secrets', why: 'environment file with credentials' },
    { path: '/swagger.json', cls: 'config', why: 'API documentation' },
    { path: '/openapi.json', cls: 'config', why: 'API documentation' },
    { path: '/graphql', cls: 'config', why: 'GraphQL endpoint' },
    { path: '/actuator/health', cls: 'config', why: 'Spring Boot actuator' },
    { path: '/.well-known/security.txt', cls: 'info', why: 'security contact' },
  ];
}

module.exports = {
  inScope, rank, parseSubfinder, triage, sensitivePaths,
  INTERESTING, THIRD_PARTY_CNAME,
};
