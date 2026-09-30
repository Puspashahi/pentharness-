'use strict';
/**
 * Browser interaction phase: auto-click, auto-fill, auto-inject.
 *
 * This was the gap that made "one command finds everything" untrue. The
 * browser scanner existed separately and `--hunt` never called it, so the single
 * command a researcher actually types had no browser at all — no clicking
 * through a JS-rendered app, no form submission, no injection against a page
 * that only exists after login.
 *
 * It runs natively here rather than shelling out, for one decisive reason:
 * authentication. An external scanner cannot be handed a session easily, and
 * unauthenticated crawling only ever sees the login page. Every real
 * high-value surface — the dashboard, the settings page, the API calls behind
 * the UI — is behind auth, so an unauthenticated browser phase is nearly
 * worthless. Here the harvested session is reused directly.
 *
 * Safety: nothing state-changing is submitted. Destructive-looking forms
 * (delete/pay/publish/password/transfer) are recorded and skipped, matching
 * webfuzz's existing rule.
 */

const DESTRUCTIVE = /(delete|remove|destroy|drop|pay|purchase|checkout|buy|publish|transfer|send|withdraw|upload|import|invite|logout|signout|change.?password|update.?password|save)/i;

/** Read every interactive control on the page, with enough context to act. */
async function readControls(page) {
  return page.evaluate(() => {
    const txt = (el) => ((el.innerText || el.value || el.getAttribute('aria-label') || el.title || '')).trim().slice(0, 60);
    const visible = (el) => {
      const r = el.getBoundingClientRect();
      if (!(r.width > 0 && r.height > 0)) return false;
      const s = getComputedStyle(el);
      return s.visibility !== 'hidden' && s.display !== 'none' && s.opacity !== '0';
    };
    const out = { links: [], buttons: [], forms: [], inputs: [] };

    for (const a of document.querySelectorAll('a[href]')) {
      if (!visible(a)) continue;
      out.links.push({ href: a.href, text: txt(a) }).slice;
      out.links = out.links.slice(0, 200);
    }
    for (const b of document.querySelectorAll('button, input[type=submit], input[type=button], [role=button]')) {
      if (!visible(b)) continue;
      out.buttons.push({ text: txt(b), type: b.getAttribute('type') || '', tag: b.tagName.toLowerCase() }).slice;
      out.buttons = out.buttons.slice(0, 120);
    }
    for (const i of document.querySelectorAll('input, select, textarea')) {
      const t = (i.type || 'text').toLowerCase();
      if (['hidden', 'submit', 'button', 'image', 'reset', 'checkbox', 'radio', 'file'].includes(t)) continue;
      if (!visible(i)) continue;
      out.inputs.push({
        name: i.name || '', id: i.id || '', type: t,
        placeholder: i.placeholder || '', autocomplete: i.autocomplete || '',
      });
    }
    for (const f of document.querySelectorAll('form')) {
      if (!visible(f)) continue;
      out.forms.push({
        action: (() => { try { return new URL(f.getAttribute('action') || location.href, location.href).toString(); } catch { return f.action; } })(),
        method: (f.getAttribute('method') || 'GET').toUpperCase(),
        fields: [...f.querySelectorAll('input,select,textarea')]
          .filter((i) => i.name && !['submit', 'button', 'image', 'reset'].includes((i.type || '').toLowerCase()))
          .map((i) => ({ name: i.name, type: i.type || 'text' })),
      });
    }
    return out;
  }).catch(() => ({ links: [], buttons: [], forms: [], inputs: [] }));
}

/**
 * Injection payloads applied to a real page, and how each is judged.
 * Judgement is by side effect, never by reflection alone: a reflected payload
 * with no observable effect is the standard false positive.
 */
const INJECTIONS = [
  { id: 'xss-img', cls: 'xss', value: '<img src=x onerror=window.__phX=1>', field: ['q', 'search', 'name', 'message', 'comment', 'query', 'text', 'title'] },
  { id: 'xss-svg', cls: 'xss', value: '<svg onload=window.__phX=1>', field: ['q', 'search', 'name', 'message', 'comment', 'query'] },
  { id: 'sqli-quote', cls: 'sqli', value: "'", field: ['q', 'search', 'id', 'query', 'name', 'user'] },
  { id: 'sqli-taut', cls: 'sqli', value: "' OR '1'='1", field: ['q', 'search', 'id', 'query', 'user'] },
  { id: 'sqli-union', cls: 'sqli', value: "' UNION SELECT null,null--", field: ['q', 'search', 'id', 'query'] },
  { id: 'traversal', cls: 'traversal', value: '../../../../etc/passwd', field: ['file', 'path', 'doc', 'download', 'name', 'q'] },
  { id: 'ssti', cls: 'ssti', value: '{{7*7}}', field: ['q', 'search', 'name', 'message', 'template'] },
  { id: 'ssrf', cls: 'ssrf', value: 'http://127.0.0.1:9/ph', field: ['url', 'webhook', 'image', 'src', 'callback', 'target', 'link'] },
];

/** Escape a value for use inside a CSS attribute selector. */
function cssAttrEscape(v) {
  return String(v).replace(/["\\]/g, '\\$&');
}

/** Pick the injection whose field preference best matches a form. */
function pickInjection(fields = []) {
  const names = fields.map((f) => String(f.name || '').toLowerCase());
  for (const inj of INJECTIONS) {
    for (const want of inj.field) {
      if (names.some((n) => n === want || n.includes(want))) return inj;
    }
  }
  // Fall back to the first text-ish field with something injection-shaped.
  const generic = fields.find((f) => /text|search|url|query|name|input/i.test(`${f.name} ${f.type}`));
  return generic ? INJECTIONS[0] : null;
}

/**
 * Fill and submit a form, then judge the result.
 *
 * Returns a result object rather than throwing: a single broken form must not
 * abort the phase.
 */
async function testForm(page, form, opts = {}) {
  const result = { action: form.action, method: form.method, fields: form.fields.map((f) => f.name), skipped: null, injections: [] };
  if (!form.fields.length) { result.skipped = 'no fields'; return result; }

  // Never submit anything that looks state-changing or destructive.
  const fingerprint = `${form.action} ${form.method} ${form.fields.map((f) => f.name).join(' ')}`;
  if (!opts.allowStateChange && DESTRUCTIVE.test(fingerprint)) {
    result.skipped = 'destructive-looking form — recorded, never auto-submitted';
    return result;
  }

  // Baseline: the unmodified request, so any difference is attributable.
  let baseline = null;
  try {
    const resp = await page.request.get(form.action, { timeout: opts.timeout || 15000 }).catch(() => null);
    if (resp) baseline = { status: resp.status(), len: (await resp.text().catch(() => '')).length };
  } catch { /* baseline is best-effort */ }

  const inj = pickInjection(form.fields);
  if (!inj) { result.skipped = baseline ? 'no injectable field' : 'no injectable field'; result.baseline = baseline; return result; }

  const target = form.fields.find((f) => inj.field.some((w) => String(f.name).toLowerCase().includes(w)))
    || form.fields[0];

  const variants = [inj.value, inj.value + "')"];
  for (const value of variants) {
    try {
      // Clear every text field so the request is well-formed, then set the target.
      for (const f of form.fields) {
        // The selector string is built in Node, so the browser-only
        // CSS.escape helper is not available here; use a plain escape.
        const n = f.name ? cssAttrEscape(f.name) : '';
        const sel = n ? `input[name="${n}"], textarea[name="${n}"], select[name="${n}"]` : null;
        if (!sel) continue;
        const el = page.locator(sel).first();
        if (!(await el.count())) continue;
        await el.fill(f.name === target.name ? value : 'x', { timeout: 4000 }).catch(() => {});
      }
      await page.waitForTimeout(300);
      // Submit via the request API rather than clicking, so a destructive-looking
      // UI control cannot be triggered and the method is explicit.
      //
      // Playwright's APIRequestContext methods are synchronous in signature but
      // reject asynchronously, so `page.request.get(...).catch()` never attaches
      // to anything — the rejection escapes as an unhandled rejection and kills
      // the whole run. Wrap in Promise.resolve() first so the catch applies.
      const target2 = (() => {
        try { const u = new URL(form.action); u.searchParams.set(target.name, value); return u.toString(); } catch { return form.action; }
      })();
      const apiCall = form.method === 'POST'
        ? page.request.post(form.action, { form: Object.fromEntries(form.fields.map((f) => [f.name, f.name === target.name ? value : 'x'])) })
        : page.request.get(target2);
      let r = null;
      try {
        r = await Promise.resolve(apiCall).then((resp) => (resp && typeof resp.timeout === 'function' ? resp.timeout(opts.timeout || 15000) : resp)).catch(() => null);
      } catch { r = null; }
      if (r) {
        const text = await r.text().catch(() => '');
        const reflected = text.includes(value.slice(0, 18));
        const errSig = /SQLITE_ERROR|MYSQL|PostgreSQL|syntax error|ORA-\d+|jdbc|Exception|Traceback|<b>Fatal error|Uncaught/i.exec(text);
        // Classify by the evidence, not by which payload fired. The XSS probe
        // hits the same search form as the SQLi probe, so a database error
        // signature means the parameter is injectable even though an XSS payload
        // was sent. Reporting it as XSS would put the wrong CWE and the wrong
        // remediation in the report.
        const dbError = /SQLITE_ERROR|MYSQL|PostgreSQL|syntax error|ORA-\d+|jdbc|sqlite|mysql|pgsql/i.test(text);
        const effectiveCls = dbError ? 'sqli' : (inj.cls === 'xss' ? (reflected ? 'xss' : inj.cls) : inj.cls);
        result.injections.push({
          id: inj.id, cls: effectiveCls, payloadCls: inj.cls, field: target.name,
          status: r.status(), len: text.length, reflected: !!reflected,
          errorSignature: errSig ? errSig[0].slice(0, 60) : null,
          differsFromBaseline: baseline ? (r.status() !== baseline.status || Math.abs(text.length - baseline.len) > 12) : null,
          // Reflected alone is not a finding; error text or a length/status
          // change against the baseline is the evidence.
          verdict: (errSig || (baseline && (r.status() !== baseline.status || Math.abs(text.length - baseline.len) > 40)))
            ? 'candidate' : (reflected ? 'reflected-only' : 'no-effect'),
        });
      }
    } catch (e) {
      result.injections.push({ id: inj.id, cls: inj.cls, field: target.name, verdict: 'error', error: String(e.message || e).slice(0, 80) });
    }
  }
  result.baseline = baseline;
  return result;
}

/**
 * Crawl by clicking: start at the seed, follow same-host links, submit
 * non-destructive forms, and read controls on each page.
 *
 * @param opts {
 *   maxPages, maxDepth, timeout, storageState, extraHTTPHeaders,
 *   allowStateChange, collectInjected (array of absolute URLs to probe)
 * }
 */
async function crawl(page, seed, opts = {}) {
  const maxPages = opts.maxPages || 15;
  const maxDepth = opts.maxDepth || 2;
  const origin = (() => { try { return new URL(seed).origin; } catch { return ''; } })();

  const seen = new Set();
  const visited = [];
  const forms = [];
  const endpoints = new Set();
  const injected = [];

  const queue = [{ url: seed, depth: 0 }];
  while (queue.length && visited.length < maxPages) {
    const { url, depth } = queue.shift();
    if (!url || seen.has(url)) continue;
    seen.add(url);
    endpoints.add(url);

    let controls = null;
    try {
      const resp = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: opts.timeout || 20000 });
      if (resp && resp.status() >= 400) continue;
      await page.waitForLoadState('networkidle', { timeout: 6000 }).catch(() => {});
      controls = await readControls(page);
    } catch { continue; }

    visited.push({ url, depth, title: await page.title().catch(() => ''), controls: { links: controls.links.length, buttons: controls.buttons.length, forms: controls.forms.length, inputs: controls.inputs.length } });

    for (const f of controls.forms) {
      const r = await testForm(page, f, opts).catch((e) => ({ action: f.action, skipped: String(e.message || e).slice(0, 60) }));
      if (!r.skipped || !/destructive|no injectable/.test(r.skipped)) forms.push(r);
      for (const inj of r.injections || []) if (inj.verdict === 'candidate') injected.push({ ...inj, url: f.action });
      if (f.action) endpoints.add(f.action);
    }

    if (depth >= maxDepth) continue;
    for (const l of controls.links) {
      if (!l.href || !l.href.startsWith('http')) continue;
      // Scope: the seed host and its subdomains only.
      let h = '';
      try { h = new URL(l.href).hostname; } catch { continue; }
      const seedHost = (() => { try { return new URL(seed).hostname; } catch { return ''; } })();
      if (!(h === seedHost || h.endsWith(`.${seedHost}`))) continue;
      if (seen.has(l.href)) continue;
      queue.push({ url: l.href, depth: depth + 1 });
    }
  }

  return { visited, forms, endpoints: [...endpoints], injected, origin };
}

module.exports = { readControls, testForm, crawl, pickInjection, INJECTIONS, DESTRUCTIVE };
