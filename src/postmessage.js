'use strict';
/**
 * postMessage / origin-trust analysis.
 *
 * Two of the five largest publicly reported web bugs of the last cycle were
 * this exact class:
 *
 *   $62,500 (Meta) — a payment iframe's remote config was attacker-controlled,
 *   turning the iframe into an eval() relay. Facebook's handler validated
 *   event.origin correctly, but "origin validation only holds if the trusted
 *   origin itself is secure. If your trusted origin gets XSS'd, your own origin
 *   is XSS'd by extension."
 *
 *   $32,500 (Meta) — fbevents.js trusted any message from facebook.com, and
 *   an endpoint could relay an attacker-crafted message *under the trusted
 *   origin*. A deliberately wrong OAuth nonce routed the victim to an error page
 *   that still loaded the script and still had window.opener.
 *
 * The transferable lesson, in the researchers' own words: "validating
 * event.origin is not enough by itself. You should also validate the expected
 * message types and structure, and ideally check a nonce or session token
 * inside the message payload itself."
 *
 * This module finds that class statically: handlers that check origin but not
 * schema, that trust `*`, that reflect `event.data` into the DOM, and endpoints
 * that relay messages to an attacker-chosen window.
 */

const { makeLead } = require('./leads');

/** addEventListener('message', ...) with a handler body. */
const HANDLER = /addEventListener\s*\(\s*['"]message['"]\s*,\s*(?:async\s*)?(?:function\s*\w*\s*\((\w+)\)|\(([^)]*)\)\s*=>|(\w+)\s*=>)/g;

/** postMessage call sites. */
const POST = /\.postMessage\s*\(/g;

/** Origin validation. */
const ORIGIN_CHECK = /(?:event|e|evt|message)\s*\.\s*origin\s*(?:===|==|!==|!=)|origin\s*(?:===|==)\s*['"]|isOriginTrusted|allowedOrigin|trustedOrigin|eventOrigin/i;

/** payload schema / nonce validation — the part the reports say is missing. */
const SCHEMA_CHECK = /(?:validate|verify|check|assert|isValid)[A-Za-z]*\s*\(\s*(?:data|msg|message|payload|event)\b/i;
const NONCE_CHECK = /\bnonce\b|\bcsrf\b|\btoken\b|\bseq\b|\bmessageId\b|\bstate\b/i;
const TYPE_CHECK = /\b(?:msg_?type|type|action|channel|kind)\b\s*(?:===|==|\bin\b|\bhas\b)/i;

/** Reflecting message data into the DOM or an execution sink. */
const DANGEROUS_SINK = [
  /\.\s*innerHTML\s*=/,
  /\.\s*outerHTML\s*=/,
  /insertAdjacentHTML/,
  /\beval\s*\(/,
  /new\s+Function\s*\(/,
  /document\s*\.\s*write\s*\(/,
  /\bsetTimeout\s*\(\s*['"`]/,
  /src\s*=\s*[^;]*\.\s*data\b/i,
  /location\s*=\s*[^;]*\.\s*data\b/i,
  /appendChild\s*\(/,
];

/** Does a handler verify where the message came from at all? */
function hasOriginCheck(body) {
  return ORIGIN_CHECK.test(body);
}

/** Does a handler validate the *shape* of the message before trusting it? */
function hasSchemaCheck(body) {
  return SCHEMA_CHECK.test(body) || TYPE_CHECK.test(body) || NONCE_CHECK.test(body);
}

/** Which dangerous sinks the message data flows into. */
function sinks(body) {
  const found = [];
  for (const rx of DANGEROUS_SINK) {
    const m = body.match(rx);
    if (m) found.push(m[0].trim().slice(0, 40));
  }
  return found;
}

/** Extract a handler body by brace matching from the opening brace. */
function bodyFrom(src, openIdx) {
  let depth = 0, i = openIdx;
  for (; i < src.length && i < openIdx + 6000; i++) {
    const ch = src[i];
    if (ch === '{') depth++;
    else if (ch === '}') { depth--; if (depth === 0) return src.slice(openIdx, i + 1); }
  }
  return src.slice(openIdx, openIdx + 2000);
}

/**
 * Analyse a bundle for postMessage weaknesses.
 * @returns {{findings:Array, stats:object}}
 */
function analysePostMessage(source, meta = {}) {
  const src = String(source || '');
  const srcName = (meta && meta.source) || 'bundle';
  const findings = [];
  const stats = { handlers: 0, withOriginCheck: 0, withSchemaCheck: 0, toWildcard: 0, toDynamic: 0, postCallsites: 0 };

  if (!src) return { findings, stats };

  // --- message handlers ---
  HANDLER.lastIndex = 0;
  let m;
  while ((m = HANDLER.exec(src))) {
    stats.handlers++;
    const braceIdx = src.indexOf('{', m.index);
    if (braceIdx < 0) continue;
    const body = bodyFrom(src, braceIdx);
    const origin = hasOriginCheck(body);
    const schema = hasSchemaCheck(body);
    if (origin) stats.withOriginCheck++;
    if (schema) stats.withSchemaCheck++;
    const hit = sinks(body);

    const ctx = src.slice(Math.max(0, m.index - 60), m.index).replace(/\s+/g, ' ').trim().slice(-60);

    // 1. No origin check at all + a dangerous sink = critical.
    if (!origin && hit.length) {
      findings.push(makeLead({
        cls: 'xss',
        title: `postMessage handler with NO origin check reaching a dangerous sink (${srcName})`,
        url: meta.url || '',
        source: 'postmessage',
        severity_hint: 'critical',
        evidence: `Handler accepts messages from any origin and flows data into: ${hit.join(', ')}.\nContext: ${ctx}`,
        proof_needed: [
          'post a message from an attacker-controlled page',
          'confirm the payload reaches the sink without an origin check',
          'demonstrate script execution in the target origin',
        ],
      }));
      continue;
    }

    // 2. Origin checked but payload trusted — the exact class of both payouts.
    if (origin && !schema && hit.length) {
      findings.push(makeLead({
        cls: 'xss',
        title: `postMessage validates origin but not payload, then reaches ${hit[0]} (${srcName})`,
        url: meta.url || '',
        source: 'postmessage',
        severity_hint: 'high',
        evidence: `Origin is checked, but there is no schema/type/nonce validation before the payload reaches ${hit.join(', ')}. A compromised trusted origin therefore becomes XSS in this origin, and attacker-supplied message types are processed.\nContext: ${ctx}`,
        proof_needed: [
          'identify the full set of accepted message types',
          'show a type the handler does not expect still reaching the sink',
          'demonstrate origin-confusion (trusted origin compromised or relayed)',
        ],
      }));
      continue;
    }

    // 3. Origin checked against a wildcard — equivalent to no check.
    if (origin && /origin\s*(?:===|==)\s*['"]\*['"]/.test(body)) {
      findings.push(makeLead({
        cls: 'xss',
        title: `postMessage origin check compares against '*' (${srcName})`,
        url: meta.url || '',
        source: 'postmessage',
        severity_hint: 'high',
        evidence: `The handler compares event.origin to the literal wildcard, which every origin matches.\nContext: ${ctx}`,
        proof_needed: ['post from an unrelated origin', 'confirm the handler processes it'],
      }));
    }
  }

  // --- postMessage call sites: where is the message going? ---
  POST.lastIndex = 0;
  while ((m = POST.exec(src))) {
    stats.postCallsites++;
    const call = src.slice(m.index, m.index + 160).replace(/\s+/g, ' ');
    if (/\*\s*\)/.test(call)) stats.toWildcard++;
    // Relaying to a window/target the attacker can influence is the $32.5k shape.
    if (/\b(?:window|opener|parent|frames?)\s*\.\s*(?:frames|open|document)?/i.test(call) && !/['"]\*['"]/.test(call)) {
      stats.toDynamic++;
      findings.push(makeLead({
        cls: 'authz',
        title: `postMessage relayed to an attacker-influenceable window (${srcName})`,
        url: meta.url || '',
        source: 'postmessage',
        severity_hint: 'medium',
        evidence: `Call site: ${call.slice(0, 140)}. If the target window and/or payload are influenced by a request parameter, this relays a message under this origin to a window the attacker opened.`,
        proof_needed: [
          'determine whether the target window comes from a request parameter',
          'determine whether the message body is attacker-influenced',
          'show a message arriving in a foreign window under a trusted origin',
        ],
      }));
    }
  }

  return { findings, stats };
}

/** Scan a file/dir via jslogic's walker, returning postMessage leads. */
function scanPostMessage(target) {
  const jslogic = require('./jslogic');
  const r = jslogic.scanPath(target);
  const out = [];
  const stats = { handlers: 0, withOriginCheck: 0, withSchemaCheck: 0, toWildcard: 0, toDynamic: 0, postCallsites: 0 };
  const fs = require('fs');
  for (const f of r.files || []) {
    let src = '';
    try { src = fs.readFileSync(f, 'utf8'); } catch { continue; }
    const a = analysePostMessage(src, { source: require('path').basename(f) });
    out.push(...a.findings);
    for (const k of Object.keys(stats)) stats[k] += a.stats[k] || 0;
  }
  return { findings: out, stats, files: r.files || [] };
}

module.exports = { analysePostMessage, scanPostMessage, hasOriginCheck, hasSchemaCheck, sinks, HANDLER, POST };
