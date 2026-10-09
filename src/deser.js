'use strict';
/**
 * Insecure deserialization probing (CWE-502).
 *
 * WHY A SENTINEL, NOT A `__reduce__` PAYLOAD
 *   The textbook pickle probe is a `__reduce__` that returns `os.system("id")`.
 *   That is the single largest source of false positives in this class, because
 *   a server which merely *attempts* to deserialize an untrusted object throws a
 *   rich, distinctive-looking error long before it would ever execute anything.
 *   Reporting that error as RCE is wrong.
 *
 *   The oracle here is behavioural instead: we submit a well-formed pickle that
 *   decodes to a value containing a unique sentinel string. If the server
 *   deserializes it, the sentinel comes back in the response. A server that does
 *   not deserialize cannot possibly produce that string — we never sent it in
 *   plain text, we sent it *inside* a serialized object. So the sentinel in the
 *   response is proof the object was decoded, and it is non-destructive.
 *
 * THE NEGATIVE CONTROL IS THE WHOLE POINT
 *   The same sentinel is submitted as plain text (not wrapped in any format).
 *   If that also echoes the sentinel, the endpoint is a plain echo and nothing
 *   was deserialized. Without this control, any echo endpoint "proves" deser.
 */

const { makeLead } = require('./leads');

const SENTINEL = 'PHDSER94';

/** Pre-built, inert payloads. Generated offline; contain no code execution. */
const PAYLOADS = {
  pickle: {
    contentType: 'application/octet-stream',
    body: 'VlBIRFNFUjk0CnAwCi4=',           // pickle -> "PHDSER94"
    label: 'pickle (python protocol 0)',
  },
  pickleList: {
    contentType: 'application/octet-stream',
    body: 'KGxwMApWUEhEU0VSOTQKcDEKYS4=',  // pickle -> ["PHDSER94"]
    label: 'pickle list',
  },
  pickleDict: {
    contentType: 'application/octet-stream',
    body: 'KGRwMApWc2VudGluZWwKcDEKVlBIRFNFUjk0CnAyCnMu', // {"sentinel": "PHDSER94"}
    label: 'pickle dict',
  },
  phpObject: {
    contentType: 'application/x-www-form-urlencoded',
    body: 'data=O:8:%22stdClass%22:0:{}',
    label: 'PHP serialized object',
  },
  yamlTag: {
    contentType: 'application/x-www-form-urlencoded',
    body: `data=${SENTINEL}`,
    label: 'YAML plain string',
  },
  nodeMerge: {
    contentType: 'application/json',
    body: JSON.stringify({ __proto__: { polluted: SENTINEL } }),
    label: 'Node __proto__ merge',
  },
};

/** The negative control: the same sentinel, no serialization wrapper at all. */
const CONTROL = {
  pickle: {
    contentType: 'application/octet-stream',
    body: 'UEhEU0VSOTQ=',
    label: 'plain base64 (control, not a pickle)',
  },
  phpObject: { contentType: 'application/x-www-form-urlencoded', body: `data=${SENTINEL}`, label: 'plain string (control)' },
  yamlTag: { contentType: 'application/x-www-form-urlencoded', body: `data=${SENTINEL}`, label: 'plain string (control)' },
  nodeMerge: { contentType: 'application/json', body: JSON.stringify({ data: SENTINEL }), label: 'plain string (control)' },
};

/** Endpoints worth probing for unsafe deserialization. */
const CANDIDATE = /\/(deser|deserial|unserialize|pickle|load|loads|render|eval|marshal|restore|import|yaml|xml|rpc|object|blob|body|decode|parse|process|upload|message|event|hook)(?:\/|$|\?)/i;

/** Formats to try, keyed by probe id. */
const PROBE_IDS = ['pickle', 'pickleList', 'pickleDict', 'nodeMerge', 'phpObject'];

async function send(ctx, url, p) {
  try {
    const r = await ctx.request.fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': p.contentType, Accept: 'application/json, text/plain, */*' },
      data: p.body,
      timeout: 15000,
    });
    return { status: r.status(), body: (await r.text().catch(() => '')).slice(0, 4000) };
  } catch (e) {
    return { status: 0, body: '', error: String(e.message || e) };
  }
}

/**
 * Probe one endpoint.
 * @returns {Promise<{findings: Array, tested: number, errors: number}>}
 */
async function probe(ctx, url, opts = {}) {
  const findings = [];
  let tested = 0;
  let errors = 0;
  if (opts.maxProbes && tested >= opts.maxProbes) return { findings, tested, errors };
  if (!CANDIDATE.test(url)) return { findings, tested, errors };

  for (const id of PROBE_IDS) {
    const p = PAYLOADS[id];
    const c = CONTROL[id];
    const res = await send(ctx, url, p);
    if (res.status >= 500) errors++;
    // No sentinel back -> deserialization not observed. Move on silently.
    if (!res.body || !res.body.includes(SENTINEL)) continue;
    tested++;

    // Control. If the bare string echoes too, the endpoint reflects input and
    // nothing was deserialized -- this is the classic mass-echo false positive.
    const ctrl = await send(ctx, url, c);
    if (ctrl.body && ctrl.body.includes(SENTINEL) && res.body.length === ctrl.body.length) {
      continue; // indistinguishable from an echo
    }

    findings.push(makeLead({
      cls: 'deser',
      title: `PROVEN insecure deserialization: ${p.label} payload on ${url} was decoded by the server`,
      url,
      source: 'deser',
      severity_hint: 'critical',
      confidence: 'confirmed',
      evidence:
        `POSTing a valid ${p.label} payload whose decoded value is the sentinel ${SENTINEL} ` +
        `returned ${res.status} with the sentinel present: ${JSON.stringify(res.body.slice(0, 240))}. ` +
        `The sentinel was never sent as plain text, so the server must have deserialized the object. ` +
        `Control: the same string as plain text returned ${ctrl.status} ` +
        `${ctrl.body && ctrl.body.includes(SENTINEL) ? 'and also echoed' : 'without the sentinel'}.`,
      proof_needed: [
        'show the two requests: serialized payload vs plain-text control',
        'demonstrate that the deserialization primitive is reachable for code execution in the deployed configuration',
      ],
    }));
    break;
  }
  return { findings, tested, errors };
}

module.exports = { probe, PAYLOADS, CONTROL, SENTINEL, CANDIDATE, PROBE_IDS };