'use strict';
/**
 * Tool normalizers — the seam that lets any of the 33 installed tools feed the
 * same lead pipeline. Each tool speaks a different dialect; the harness must not.
 *
 * Every normalizer is total: malformed input yields zero leads rather than
 * throwing, because a single bad tool run must never abort an engagement.
 */
const { makeLead, truncate } = require('./leads');

const SEV = { info: 'info', low: 'low', medium: 'medium', high: 'high', critical: 'critical', unknown: 'info' };

/** nuclei -json / -jsonl */
function nuclei(raw) {
  const out = [];
  const rows = Array.isArray(raw) ? raw : parseJsonl(raw);
  for (const r of rows) {
    if (!r || !r.info) continue;
    const t = r.info;
    out.push(makeLead({
      cls: t.tags && t.tags.includes('ai') ? 'ai' : undefined,
      title: t.name || r.templateID || 'nuclei match',
      url: r.matched_at || r.host || '',
      param: extractMatch(r.matched_at || ''),
      source: 'nuclei',
      severity_hint: SEV[t.severity] || 'info',
      evidence: `${r.templateID || ''} ${r.type || ''} ${truncate(JSON.stringify(t.metadata || {}), 400)}`,
      tags: t.tags || [],
    }));
  }
  return out;
}

/** webfuzz report.json (our own scanner) */
function webfuzz(raw) {
  const out = [];
  const r = typeof raw === 'string' ? safeParse(raw) : raw;
  if (!r || !Array.isArray(r.findings)) return out;
  for (const f of r.findings) {
    out.push(makeLead({
      cls: mapCat(f.category, f.title),
      title: f.title,
      url: f.url,
      param: f.parameter,
      source: 'webfuzz',
      severity_hint: SEV[f.severity] || 'info',
      evidence: f.evidence,
      actor: guessActor(f),
    }));
  }
  return out;
}

/** ffuf -json */
function ffuf(raw) {
  const out = [];
  const r = typeof raw === 'string' ? safeParse(raw) : raw;
  const results = r && (r.results || r);
  if (!Array.isArray(results)) return out;
  for (const x of results) {
    if (!x || typeof x.url !== 'string') continue;
    out.push(makeLead({
      cls: 'recon',
      title: `content match: ${truncate(x.input && x.input.FUZZ, 40)}`,
      url: x.url,
      source: 'ffuf',
      severity_hint: 'low',
      evidence: `status=${x.status} len=${x.length} words=${x.words} lines=${x.lines}`,
    }));
  }
  return out;
}

/** httpx -json (single) or jsonl */
function httpx(raw) {
  const out = [];
  const rows = Array.isArray(raw) ? raw : parseJsonl(raw);
  for (const r of rows) {
    if (!r || (!r.url && !r.input)) continue;
    out.push(makeLead({
      cls: 'recon',
      title: `${r.status_code || '?'} ${r.method || 'GET'} ${r.title || ''}`.trim(),
      url: r.url || r.input,
      source: 'httpx',
      severity_hint: 'info',
      evidence: `status=${r.status_code} tech=${(r.tech || []).join(',')} cname=${(r.cname || []).join(',')} len=${r.content_length}`,
      tags: r.tech || [],
    }));
  }
  return out;
}

/** nuclei-template JSON (a template file) is not a finding; used for capability planning. */
function gitleaks(raw) {
  const out = [];
  const r = typeof raw === 'string' ? safeParse(raw) : raw;
  const rows = Array.isArray(r) ? r : Array.isArray(r && r.findings) ? r.findings : [];
  for (const f of rows) {
    out.push(makeLead({
      cls: 'secrets',
      title: `secret: ${f.RuleID || f.Rule || 'leak'}`,
      url: f.File || '',
      source: 'gitleaks',
      severity_hint: 'high',
      evidence: `${f.Description || ''} ${f.Commit || ''} ${f.File || ''}:${f.StartLine || ''}`.trim(),
    }));
  }
  return out;
}

/** katana / gospider — crawled endpoints */
function spider(raw) {
  const out = [];
  const rows = Array.isArray(raw) ? raw : parseJsonl(raw);
  for (const r of rows) {
    const url = typeof r === 'string' ? r : r && (r.request && r.request.endpoint) || r.url;
    if (!url) continue;
    out.push(makeLead({
      cls: 'recon',
      title: 'discovered endpoint',
      url,
      source: 'katana',
      severity_hint: 'info',
      evidence: typeof r === 'object' ? JSON.stringify(r).slice(0, 300) : '',
    }));
  }
  return out;
}

/**
 * Collapse a bulk crawl to unique *shapes* rather than every URL. A crawler
 * returning 37,870 endpoints is mostly the same handful of routes with
 * different ids and query values; storing each as a distinct lead buries the
 * actionable signal and bloats the knowledge base.
 * Keeps the first N distinct path patterns and records the true total.
 */
function dedupeCrawl(leads, opts = {}) {
  const maxPaths = opts.maxPaths || 60;
  const byShape = new Map();
  let total = 0;
  for (const l of leads) {
    total++;
    let shape;
    try {
      const u = new URL(l.url);
      // /product/123 and /product/456 are one shape; keep the query keys too.
      const path = u.pathname.replace(/\/(?:[0-9]+|[0-9a-f]{8,}|[0-9a-f-]{16,})(?=\/|$)/gi, '/:id');
      const keys = [...u.searchParams.keys()].sort().join(',');
      shape = `${u.host}${path}${keys ? '?' + keys : ''}`;
    } catch {
      shape = l.url;
    }
    if (!byShape.has(shape)) byShape.set(shape, { ...l, crawl_total: total, shape });
  }
  const kept = [...byShape.values()];
  return {
    leads: kept.slice(0, maxPaths),
    totalDiscovered: total,
    uniqueShapes: byShape.size,
    truncated: kept.length > maxPaths,
  };
}

/** arjun — parameter discovery (critical: supplies the injection surface) */
function arjun(raw) {
  const out = [];
  const r = typeof raw === 'string' ? safeParse(raw) : raw;
  const res = r && (r.results || r);
  if (!res) return out;
  // arjun emits BOTH shapes: an object map {url:{params:[..]}} and a flat
  // array of {url, params}. Accept either.
  const entries = Array.isArray(res)
    ? res.map((x) => [x && x.url, x])
    : Object.entries(res);
  for (const [url, obj] of entries) {
    if (!url) continue;
    const params = (obj && obj.params) || [];
    for (const p of params) {
      out.push(makeLead({
        cls: 'recon',
        title: `hidden parameter: ${p}`,
        url,
        param: p,
        source: 'arjun',
        severity_hint: 'low',
        evidence: `arjun discovered '${p}' on ${url}`,
        // Hidden params are prime injection surface — flag for correlation.
        chain_hints: ['injection'],
      }));
    }
  }
  return out;
}

/** generic HTTP response observation (our own probes, curl transcripts) */
function httpResponse(raw) {
  const o = typeof raw === 'string' ? safeParse(raw) : raw;
  if (!o || !o.url) return [];
  return [makeLead({
    cls: o.cls,
    title: o.title || `observed ${o.status}`,
    url: o.url,
    param: o.param,
    source: o.source || 'manual',
    severity_hint: SEV[o.severity] || 'info',
    evidence: o.evidence || `status=${o.status}`,
    identity: o.identity,
    actor: o.actor,
  })];
}

const NORMALIZERS = { nuclei, webfuzz, ffuf, httpx, gitleaks, spider, arjun, httpResponse };

/** Dispatch by tool name; unknown tools are ignored, never fatal. */
function ingest(tool, raw) {
  const fn = NORMALIZERS[tool];
  if (!fn) return [];
  try {
    return fn(raw) || [];
  } catch {
    return [];
  }
}

function mapCat(category, title) {
  const t = `${category || ''} ${title || ''}`;
  if (/idor|broken access/i.test(t)) return 'authz';
  if (/csrf/i.test(t)) return 'authz';
  if (/sql ?injection/i.test(t)) return 'injection';
  if (/xss/i.test(t)) return 'xss';
  if (/ssrf/i.test(t)) return 'ssrf';
  if (/traversal|lfi/i.test(t)) return 'traversal';
  if (/comment|header|cookie|cors|mixed/i.test(t)) return 'config';
  if (/form inventory/i.test(t)) return 'recon';
  return undefined; // let the classifier decide
}

function guessActor(f) {
  const e = String(f.evidence || '');
  if (/login|auth|password/i.test(e)) return 'authenticated';
  if (/anonymous|unauth/i.test(e)) return 'anonymous';
  return undefined;
}

function extractMatch(u) {
  const m = String(u).match(/[?&]([a-zA-Z_][\w.-]{1,40})=/);
  return m ? m[1] : undefined;
}

function parseJsonl(raw) {
  return String(raw).split('\n').map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
}

function safeParse(s) {
  try { return JSON.parse(s); } catch { return null; }
}

module.exports = { ...NORMALIZERS, ingest, NORMALIZERS, mapCat, parseJsonl, dedupeCrawl };
