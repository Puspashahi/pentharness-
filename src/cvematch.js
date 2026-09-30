'use strict';
/**
 * CVE applicability matching with exclusion reasoning.
 *
 * The naive approach is "scan, then show matching CVEs." That produces a list of
 * 500 mostly-irrelevant results and buries the three that matter.
 *
 * The insight from public work on this (Pentest-MCP's exclusion reasoning) is
 * that knowing what does NOT apply is as valuable as knowing what does. An
 * unauthenticated tester has no use for auth-required CVEs; a tester with no
 * shell has no use for post-auth RCE chains. Filtering those out before they
 * reach the operator is the difference between an actionable shortlist and noise.
 *
 * This module never claims a CVE is exploitable. It can only say a CVE is
 * *plausible given observed facts*, and it must name the fact that made it
 * plausible so a human can check. Version matching against a real advisory
 * database is a separate step that this module refuses to fake.
 *
 * Version comparison lives here rather than depending on an external package
 * because the affected ranges in advisories are frequently expressed as
 * "before X", "through Y", or "up to but not including Z", and getting the
 * boundaries wrong in either direction is worse than not answering.
 */

/** Parse a version string into comparable numeric parts. */
function parseVersion(v) {
  if (v == null) return null;
  const s = String(v).trim().replace(/^[vV]/, '');
  // Debian/RPM style epochs and revisions are not comparable to upstream.
  const m = s.match(/^(\d+)(?::(\d+))?[.\-]?(\d+)?[.\-]?(\d+)?/);
  if (!m) return null;
  return {
    epoch: parseInt(m[2] || '0', 10),
    major: parseInt(m[1], 10),
    minor: parseInt(m[3] || '0', 10),
    patch: parseInt(m[4] || '0', 10),
    raw: s,
  };
}

/** Compare two versions. Returns -1, 0, 1. */
function compareVersions(a, b) {
  const va = typeof a === 'string' ? parseVersion(a) : a;
  const vb = typeof b === 'string' ? parseVersion(b) : b;
  if (!va && !vb) return 0;
  if (!va) return -1;   // unknown is treated as older, so it does not match a "before" range
  if (!vb) return 1;
  for (const k of ['epoch', 'major', 'minor', 'patch']) {
    if (va[k] !== vb[k]) return va[k] < vb[k] ? -1 : 1;
  }
  return 0;
}

/**
 * Is `version` inside an affected range?
 * Supports the forms advisories actually use:
 *   "< 4.17.21"           "<4.17.21"
 *   "<= 1.2.3"
 *   ">= 2.0.0"
 *   "= 1.0.0" / "1.0.0"
 *   "1.0.0 - 1.4.2"       range
 *   "through 3.1"         implicit upper bound
 *   "up to 2.9.9"
 *   "1.2.3 and earlier"
 */
function isAffected(version, range) {
  const v = parseVersion(version);
  const r = String(range || '').trim();
  if (!v || !r) return null;   // unknown: do not guess

  const rangeMatch = r.match(/^\s*([\d.]+)\s*(?:-|–|to|until|through)\s*([\d.]+)\s*$/i);
  if (rangeMatch) {
    return compareVersions(v, rangeMatch[1]) >= 0 && compareVersions(v, rangeMatch[2]) <= 0;
  }

  const upperOnly = r.match(/^(?:through|up to(?: and including)?|before|prior to|older than)\s*(?:version\s*)?([\d.]+)$/i);
  if (upperOnly) {
    const words = /^(through|up to)/i.test(r);
    // "through X" is inclusive; "before X" is exclusive.
    const c = compareVersions(v, upperOnly[1]);
    return words ? c <= 0 : c < 0;
  }

  const opMatch = r.match(/^(<=|>=|<|>|=)?\s*([\d.]+)$/);
  if (opMatch) {
    const op = opMatch[1] || '=';
    const c = compareVersions(v, opMatch[2]);
    switch (op) {
      case '<': return c < 0;
      case '<=': return c <= 0;
      case '>': return c > 0;
      case '>=': return c >= 0;
      default: return c === 0;
    }
  }

  if (/earlier|and before/i.test(r)) {
    const n = r.match(/([\d.]+)/);
    if (n) return compareVersions(v, n[1]) < 0;
  }
  return null;
}

/** Does an observed tech string mention this product? */
function techMatches(observed, product) {
  if (!observed) return false;
  const hay = String(observed).toLowerCase();
  const needle = String(product).toLowerCase();
  if (hay.includes(needle)) return true;
  // Common shorthand: "Lodash" vs "lodash", "Apache Tomcat" vs "tomcat".
  const compact = needle.replace(/[^a-z0-9]/g, '');
  return compact.length >= 4 && hay.replace(/[^a-z0-9]/g, '').includes(compact);
}

/**
 * Exclusion reasoning: given what the operator actually has, decide which CVEs
 * are even reachable.
 *
 * This is the core value. Most CVEs in a product's list require a precondition
 * the tester does not have. Surfacing those wastes triage time and, worse,
 * encourages submitting findings that cannot be demonstrated.
 */
function excludeReasons(cve, context = {}) {
  const out = [];
  const req = cve.requires || {};

  if (req.auth === true && !context.hasAuth) {
    out.push('requires authentication, and no session is available');
  }
  if (req.auth === false && context.hasAuth && cve.authOptionalOnly) {
    out.push('only exploitable unauthenticated; an authenticated session does not add reachability here');
  }
  if (req.networkAccess === true && context.hasNetworkAccess === false) {
    out.push('requires the target to make outbound network requests, which is not the case here');
  }
  if (req.shell === true && !context.hasShell) {
    out.push('requires a shell on the target; no foothold exists');
  }
  if (req.privilege === 'root' && !context.hasRoot) {
    out.push('requires root; current privilege is insufficient');
  }
  if (req.specific_feature && context.seenFeatures && !context.seenFeatures.includes(req.specific_feature)) {
    out.push(`requires the "${req.specific_feature}" feature, which was not observed on the target`);
  }
  // Payout-aware filtering: a program that caps this class will not reward it.
  if (context.programExcludes && context.programExcludes.includes(cve.cls)) {
    out.push('program brief excludes this finding class');
  }
  return out;
}

/**
 * Rank candidate CVEs for a target.
 *
 * @param cves   [{id, cls, product, affected, requires, cvss, summary}]
 * @param context {
 *   tech: "Lodash 4.17.20, Django 3.2",
 *   version: "4.17.20",
 *   product: "lodash",
 *   hasAuth, hasNetworkAccess, hasShell, hasRoot, seenFeatures,
 *   programExcludes: ['idor','open-redirect']
 * }
 * @returns {applicable:[], excluded:[{cve, reasons}], uncertain:[]}
 */
function match(cves, context = {}) {
  const applicable = [];
  const excluded = [];
  const uncertain = [];

  for (const cve of cves || []) {
    // 1. Product must be observed. This is the strongest, cheapest filter.
    if (cve.product && !techMatches(context.tech, cve.product)) {
      excluded.push({ cve, reasons: [`${cve.product} was not detected on the target`] });
      continue;
    }

    // 2. Version, when we know one.
    let versionVerdict = null;
    if (cve.affected && context.version) {
      versionVerdict = isAffected(context.version, cve.affected);
      if (versionVerdict === false) {
        excluded.push({
          cve,
          reasons: [`detected version ${context.version} is outside the affected range (${cve.affected})`],
        });
        continue;
      }
    }

    // 3. Precondition exclusions.
    const reasons = excludeReasons(cve, context);
    if (reasons.length) { excluded.push({ cve, reasons }); continue; }

    const entry = {
      ...cve,
      // Every applicability claim must name the evidence behind it.
      matchedBecause: [
        `${cve.product || 'component'} observed in target fingerprint`,
        versionVerdict === true
          ? `version ${context.version} is inside the affected range (${cve.affected})`
          : (versionVerdict === null ? 'version not verified — confirm before relying on this' : null),
      ].filter(Boolean),
      confidence: versionVerdict === true ? 'moderate' : 'low',
      caveat: 'plausibility only — confirm the advisory and reproduce before reporting',
    };
    if (versionVerdict === null && cve.affected) uncertain.push(entry);
    else applicable.push(entry);
  }

  const byCvss = (a, b) => (b.cvss || 0) - (a.cvss || 0);
  applicable.sort(byCvss);
  uncertain.sort(byCvss);
  // Most-excluded-first surfaces which filters are doing the most work.
  excluded.sort((a, b) => b.reasons.length - a.reasons.length);

  return { applicable, excluded, uncertain };
}

/**
 * How much work did exclusion actually save? Useful as a report line and as a
 * regression signal: if this number collapses, a fingerprint stopped working.
 */
function savings(result, total) {
  const kept = result.applicable.length + result.uncertain.length;
  return {
    total: total || (result.applicable.length + result.uncertain.length + result.excluded.length),
    considered: kept,
    excluded: result.excluded.length,
    reductionPct: total ? Math.round((result.excluded.length / total) * 100) : 0,
  };
}

module.exports = { parseVersion, compareVersions, isAffected, techMatches, excludeReasons, match, savings };
