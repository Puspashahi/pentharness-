'use strict';
/**
 * Subdomain takeover detection.
 *
 * One of the best effort-to-payout ratios in bug bounty: a subdomain whose DNS
 * still points at a third-party service that has been de-provisioned, so an
 * attacker can re-register the resource and serve content from the victim's
 * domain. Frequently the first finding a researcher files on a new program.
 *
 * The dangerous part is claiming it. This module therefore separates two
 * questions that are routinely conflated:
 *
 *   1. Does the CNAME point at a recognised third-party service?   (DNS)
 *   2. Does that service's response prove the resource is unclaimed? (HTTP)
 *
 * Only the combination is a finding. Pointing at `*.cloudfront.net` is not a
 * bug — thousands of hosts do. Pointing at a *deprovisioned* S3 bucket or an
 * unclaimed Heroku app is.
 *
 * Non-negotiable: nothing here writes, registers, or claims anything. Every
 * check is a DNS lookup or a GET request. Claiming a resource is the
 * researcher's decision, made deliberately, with the program's permission.
 */

const dns = require('dns');

/**
 * Service fingerprints: the CNAME suffix, and the response bodies that mean
 * "this resource is no longer provisioned".
 *
 * `nx` is used when the provider signals deprovisioning with an NXDOMAIN rather
 * than an HTTP response, which is the case for several of them.
 */
const FINGERPRINTS = [
  {
    id: 'heroku', provider: 'Heroku', cname: /\.herokuapp\.com$/i,
    nx: true, severity: 'high',
    claim: 'the Heroku app name can be registered by anyone',
  },
  {
    id: 's3-bucket', provider: 'Amazon S3', cname: /\.s3\.amazonaws\.com$/i,
    match: [/NoSuchBucket/i, /The specified bucket does not exist/i],
    severity: 'high',
    claim: 'the bucket name can be registered, then hosted content on the victim domain',
  },
  {
    id: 's3-website', provider: 'Amazon S3 website', cname: /\.s3-website[.-][a-z0-9-]+\.amazonaws\.com$/i,
    match: [/NoSuchBucket/i, /The specified bucket does not exist/i],
    severity: 'high', claim: 'bucket name is claimable',
  },
  {
    id: 'cloudfront', provider: 'Amazon CloudFront', cname: /\.cloudfront\.net$/i,
    match: [/ERROR: The specified bucket does not exist/i, /NoSuchBucket/i],
    severity: 'medium', claim: 'a distribution with a matching ID would need to exist; verify before reporting',
    caveat: 'CloudFront returns this for any unknown Host header, so it is a weak signal on its own — confirm the distribution is gone from the AWS console side.',
  },
  {
    id: 'azure', provider: 'Microsoft Azure', cname: /\.azurewebsites\.net$/i,
    nx: true, severity: 'high', claim: 'the app service name can be re-registered',
  },
  {
    id: 'azure-static', provider: 'Azure Blob static', cname: /\.azurewebsites\.net$/i,
    nx: true, severity: 'high', claim: 'static site name is claimable',
  },
  {
    id: 'appspot', provider: 'Google App Engine', cname: /\.appspot\.com$/i,
    nx: true, severity: 'high', claim: 'the app name can be registered',
  },
  {
    id: 'firebase', provider: 'Firebase Hosting', cname: /\.firebaseapp\.com$/i,
    match: [/Site Not Found/i, /404 Not Found/i], nx: true, severity: 'medium',
    claim: 'the Firebase project name may be claimable',
  },
  {
    id: 'github-pages', provider: 'GitHub Pages', cname: /\.github\.io$/i,
    match: [/There isn't a GitHub Pages site here/i],
    severity: 'high', claim: 'the GitHub Pages site can be created by anyone',
  },
  {
    id: 'gitlab-pages', provider: 'GitLab Pages', cname: /\.gitlab\.io$/i,
    match: [/Page Not Found|404 Not Found/i], severity: 'medium', claim: 'project namespace may be claimable',
  },
  {
    id: 'netlify', provider: 'Netlify', cname: /\.netlify\.app$/i,
    match: [/Not Found|Page Does Not Exist|404/i], severity: 'medium', claim: 'the site name can be claimed',
  },
  {
    id: 'vercel', provider: 'Vercel', cname: /\.vercel\.app$/i,
    match: [/The deployment could not be found|404/i], severity: 'medium', claim: 'the project name can be claimed',
  },
  {
    id: 'surge', provider: 'Surge.sh', cname: /\.surge\.sh$/i,
    match: [/project not found/i], severity: 'high', claim: 'the surge.sh project is unclaimed',
  },
  {
    id: 'bitbucket', provider: 'Bitbucket Pages', cname: /\.bitbucket\.io$/i,
    nx: true, severity: 'medium', claim: 'the repository/space can be created',
  },
  {
    id: 'fastly-domain', provider: 'Fastly', cname: /\.fastly\.net$/i,
    match: [/Fastly error: unknown domain/i], severity: 'high',
    claim: 'the Fastly domain is unclaimed; register it and point it anywhere',
  },
  {
    id: 'fly', provider: 'Fly.io', cname: /\.fly\.dev$/i,
    match: [/Could not resolve|Not Found|404/i], severity: 'medium', claim: 'the app name can be claimed',
  },
  {
    id: 'elastic-beanstalk', provider: 'AWS Elastic Beanstalk', cname: /\.elasticbeanstalk\.com$/i,
    match: [/EnvironmentNotFound|404 Not Found/i], severity: 'high', claim: 'the environment name can be registered',
  },
  {
    id: 'readthedocs', provider: 'Read the Docs', cname: /\.readthedocs\.io$/i,
    nx: true, severity: 'low', claim: 'the project slug may be claimable',
  },
  {
    id: 'ghost', provider: 'Ghost', cname: /\.ghost\.io$/i,
    match: [/The thing you were looking for is no longer here|404/i], severity: 'medium', claim: 'the Ghost site is unclaimed',
  },
  {
    id: 'zendesk', provider: 'Zendesk', cname: /\.zendesk\.com$/i,
    nx: true, severity: 'medium', claim: 'the subdomain can be claimed on a new Zendesk account',
  },
  {
    id: 'shopify', provider: 'Shopify', cname: /\.myshopify\.com$/i,
    match: [/Sorry, this shop is currently unavailable|404/i], severity: 'high', claim: 'the shop name can be registered',
  },
  {
    id: 'tumblr', provider: 'Tumblr', cname: /\.domains\.tumblr\.com$/i,
    match: [/Whatever you were looking for doesn't currently exist|404/i], severity: 'medium', claim: 'the blog name can be claimed',
  },
  {
    id: 'pantheon', provider: 'Pantheon', cname: /\.pantheonsite\.io$/i,
    match: [/The gods are wise, but do not know of the site which you seek|404/i], severity: 'high', claim: 'the site name can be claimed',
  },
  {
    id: 'ionix', provider: 'IONIX', cname: /\.ionix\.io$/i,
    match: [/Site Not Found|404/i], severity: 'medium', claim: 'the account can be recreated',
  },
  {
    id: 'jira-cloud', provider: 'Atlassian Cloud', cname: /\.atlassian\.net$/i,
    match: [/Site not found|404/i], severity: 'low',
    claim: 'the site name can be taken by another Atlassian tenant',
  },
  {
    id: 'statuspage', provider: 'Statuspage', cname: /\.statuspage\.io$/i,
    match: [/DOCTYPE.*html.*404|404 Not Found/i], nx: true, severity: 'medium', claim: 'the page can be claimed',
  },
];

/** Which fingerprint, if any, does this CNAME match? */
function fingerprintFor(cname = '') {
  const c = String(cname).replace(/\.$/, '');
  return FINGERPRINTS.find((f) => f.cname.test(c)) || null;
}

/**
 * Resolve the full CNAME chain.
 * Subfinder reports the CNAME it saw, but chains matter: a host may point at
 * another host which is the one that actually dangles.
 */
async function resolveChain(host, resolver = dns.promises) {
  const chain = [];
  let current = host;
  for (let i = 0; i < 6; i++) {
    let target;
    try {
      const r = await resolver.resolveCname(current);
      if (!r || !r.length) break;
      target = String(r[0]).replace(/\.$/, '');
    } catch {
      break;
    }
    if (!target || chain.includes(target)) break;
    chain.push(target);
    current = target;
  }
  return chain;
}

/**
 * Judge one candidate host.
 *
 * Returns a verdict object, never a bare boolean, so the reason is always
 * carried with the result. A host that merely points at a CDN is `not-vulnerable`
 * with the CNAME recorded — that is a normal configuration, not a finding.
 */
async function check(host, opts = {}) {
  const h = String(host).replace(/\.$/, '');
  const result = {
    host: h, cname: null, chain: [], provider: null, fingerprint: null,
    verdict: 'no-cname', severity: 'info', evidence: [], caveat: null, claim: null,
  };

  let chain = [];
  try {
    chain = await resolveChain(h, opts.resolver || dns.promises);
  } catch (e) {
    result.evidence.push(`DNS resolution failed: ${e.code || e.message}`);
    return result;
  }

  if (!chain.length) {
    // No CNAME at all. A dangling A record is a different problem; this module
    // only claims what it can evidence.
    result.verdict = 'no-cname';
    result.evidence.push('no CNAME record — nothing to fingerprint');
    return result;
  }

  result.chain = chain;
  result.cname = chain[chain.length - 1];

  // Fingerprint the whole chain: the dangling resource may be an intermediate.
  let fp = null;
  for (const link of chain) {
    const f = fingerprintFor(link);
    if (f) { fp = f; result.evidence.push(`CNAME chain: ${chain.join(' -> ')} (matched ${f.provider} on ${link})`); break; }
  }
  if (!fp) {
    result.verdict = 'not-vulnerable';
    result.evidence.push(`CNAME points at ${result.cname}, which is not a recognised third-party service`);
    return result;
  }

  result.provider = fp.provider;
  result.fingerprint = fp.id;
  result.severity = fp.severity;
  result.claim = fp.claim;
  result.caveat = fp.caveat || null;

  // Deprovisioning signal.
  //
  // The distinction that matters: `ENODATA` from resolveCname means "no further
  // CNAME record", which is the NORMAL end state of every CNAME chain, not
  // evidence of deprovisioning. Treating it as NXDOMAIN reported the live,
  // correctly-served host pages.github.com as takeover-vulnerable because
  // github.github.io simply had no further CNAME.
  //
  // So the CNAME is followed to the end of the chain, and then the FINAL target
  // is asked whether it resolves at all. Only a real resolution failure there is
  // a deprovisioning signal.
  let nx = false;
  let nxCode = null;
  try {
    const finalTarget = result.cname;
    await (opts.resolver || dns.promises).resolve4(finalTarget);
    nx = false;
  } catch (e) {
    nxCode = e.code || e.message;
    // ENOTFOUND / ENODATA on the *address* query means the name has no A
    // record at all: the provider is not serving it.
    nx = nxCode === 'ENOTFOUND' || nxCode === 'ENODATA';
  }

  // HTTP fingerprint. Read-only GET to the dangling host.
  let body = '';
  let status = 0;
  if (opts.fetch !== false) {
    try {
      const res = await fetch(`https://${h}/`, {
        method: 'GET', redirect: 'manual',
        headers: { 'User-Agent': opts.userAgent || 'pentharness-takeover-check' },
        signal: AbortSignal.timeout(opts.timeout || 10000),
      });
      status = res.status;
      body = (await res.text().catch(() => '')).slice(0, 4000);
    } catch (e) {
      result.evidence.push(`HTTP request failed: ${String(e.message || e).slice(0, 80)}`);
    }
  }

  const bodyMatch = fp.match && body && fp.match.some((rx) => rx.test(body));

  // A live 200 from the host overrides an NX signal: if the provider is still
  // serving content, nothing is dangling, whatever DNS said.
  if (nx && !(status >= 200 && status < 400 && body.length > 0)) {
    result.verdict = 'vulnerable';
    result.evidence.push(`DNS: ${result.cname} has no address record (${nxCode}) — ${fp.provider} is not serving it`);
    if (status) result.evidence.push(`HTTP: ${status} from the dangling host`);
    return result;
  }

  // A body fingerprint is direct evidence and outranks everything else.
  if (bodyMatch) {
    result.verdict = 'vulnerable';
    const sig = fp.match.find((rx) => rx.test(body));
    result.evidence.push(`HTTP ${status}: body matches the ${fp.provider} unclaimed signature /${sig.source}/${sig.flags.replace('i','')}/`);
    result.evidence.push(`body excerpt: ${body.match(sig)[0].slice(0, 80)}`);
    return result;
  }

  if (status && status >= 200 && status < 400 && body.length > 0) {
    result.verdict = 'not-vulnerable';
    result.evidence.push(`${fp.provider} returned a live response (HTTP ${status}) — the resource is still provisioned`);
    return result;
  }

  // The CNAME target resolves to an address, DNS reports nothing wrong, and
  // there is no unclaimed-body signature. That is the normal state of a working
  // configuration, not an open question — calling it "inconclusive" would push
  // a triage decision back to the researcher that the evidence already answers.
  if (!nx && (opts.fetch === false || (status === 0 && !body))) {
    result.verdict = 'not-vulnerable';
    result.evidence.push(`${result.cname} resolves to an address and shows no unclaimed signature — the resource is in use`);
    return result;
  }

  result.verdict = 'inconclusive';
  result.evidence.push(`CNAME matches ${fp.provider} but neither DNS nor HTTP confirmed de-provisioning (status ${status || 'n/a'})`);
  return result;
}

/** Check a list of hosts, serially so a program is not hit in bursts. */
async function checkAll(hosts = [], opts = {}) {
  const out = [];
  for (const h of hosts.slice(0, opts.limit || 60)) {
    out.push(await check(h, opts).catch((e) => ({
      host: h, verdict: 'error', severity: 'info', evidence: [String(e.message || e).slice(0, 100)],
    })));
    if (opts.delayMs) await new Promise((r) => setTimeout(r, opts.delayMs));
  }
  return out;
}

/** Turn results into finding-shaped objects, dropping the non-findings. */
function toFindings(results = []) {
  return results
    .filter((r) => r.verdict === 'vulnerable')
    .map((r) => ({
      host: r.host,
      provider: r.provider,
      severity: r.severity,
      title: `Subdomain takeover: ${r.host} (${r.provider})`,
      claim: r.claim,
      caveat: r.caveat,
      evidence: r.evidence,
      cname: r.cname,
      chain: r.chain,
    }));
}

module.exports = { FINGERPRINTS, fingerprintFor, resolveChain, check, checkAll, toFindings };
