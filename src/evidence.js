'use strict';
/**
 * Evidence hygiene.
 *
 * Every serious bug bounty framework I surveyed ships an evidence-hygiene
 * skill, and it exists for one reason: research reports get submitted with the
 * researcher's own live session in them. A pasted cookie header hands the
 * triager a working session on your account. A screenshot of a profile page
 * shows you real personal data that is not yours to redistribute. A HAR file
 * carries every request you made, including the authenticated ones.
 *
 * None of that is intentional and all of it is common, and it produces one of
 * two bad outcomes: a rejected report, or a compromised account that has
 * nothing to do with the vulnerability.
 *
 * So sanitization happens on the way *out*, automatically, before anything is
 * written to a report. It is deliberately conservative: over-redacting an
 * exploit payload would destroy the evidence, so payloads and the exact
 * requests that prove impact are preserved, and only *ambient* material —
 * credentials, PII, unrelated session data — is masked.
 *
 * What is never touched:
 *   - the attack request/response pair that demonstrates the vulnerability
 *   - payload strings, parameter names, and status codes
 *   - the vulnerability class and the reasoning
 */

/** Header names whose values are session or credential material. */
const SECRET_HEADERS = [
  'cookie', 'set-cookie', 'authorization', 'proxy-authorization', 'x-api-key',
  'x-auth-token', 'x-csrf-token', 'x-xsrf-token', 'x-amz-security-token',
  'x-access-token', 'x-session-id', 'x-csrfmiddlewaretoken', 'www-authenticate',
  'x-amz-credential', 'authentication',
];

/** Cookie names that must be masked regardless of the cookie header. */
const SECRET_COOKIES = [
  'session', 'sessionid', 'jsessionid', 'sid', 'sid_tt', 'phpsessid', 'asp.net_sessionid',
  'csrftoken', 'csrf_token', 'xsrf', '_csrf', 'remember_token', 'remember_me',
  'auth', 'auth_token', 'authorization', 'token', 'access_token', 'refresh_token',
  'jwt', 'id_token', 'mos_auth_token', 'mwa_session', 'mwa', 'sess', 's_inv',
  'connect.sid', 'laravel_session', 'django_sessionid', 'aws-target-session',
];

/** Query/body keys that commonly carry credentials. */
const SECRET_KEYS = [
  'password', 'passwd', 'pwd', 'pass', 'secret', 'token', 'access_token',
  'refresh_token', 'id_token', 'api_key', 'apikey', 'api-key', 'client_secret',
  'authorization', 'auth', 'session', 'sessionid', 'sid', 'csrf', 'csrftoken',
  'xsrf', 'key', 'private_key', 'credential', 'credentials', 'otp', 'code',
  'mfa_code', 'verification_code', 'pin',
];

const EMAIL_RX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const IPV4_RX = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const UUID_RX = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
const BEARER_RX = /\b(Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{8,}/gi;
const JWT_RX = /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g;
const AWSKEY_RX = /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g;
const GH_PAT_RX = /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g;
const SLACK_RX = /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g;
const PRIVATEKEY_RX = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g;
const LONGDIGIT_RX = /\b\d{13,19}\b/g;   // card-like, but only flagged for review

/**
 * Replace sensitive values in a header map.
 * Non-sensitive headers are preserved: `Content-Type`, `X-Powered-By`, and the
 * custom identification headers a program mandates are part of the evidence.
 */
function redactHeaders(headers = {}) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    const name = String(k).toLowerCase();
    if (SECRET_HEADERS.includes(name)) {
      out[k] = maskHeaderValue(String(k), String(v));
    } else if (name === 'user-agent' || name === 'referer' || name === 'origin') {
      out[k] = redactText(String(v));
    } else {
      out[k] = v;
    }
  }
  return out;
}

/**
 * Mask a header value while keeping its *shape*, because shape is evidence.
 * `Cookie: a=1; b=2` -> `Cookie: a=<redacted>; b=<redacted>`
 */
function maskHeaderValue(name, value) {
  const n = String(name).toLowerCase();
  if (n === 'cookie' || n === 'set-cookie') {
    // Preserve cookie names and flags; drop the values.
    return value
      .split(/;\s*/)
      .map((part) => {
        const [k, ...rest] = part.split('=');
        if (!rest.length) return k;
        const isSecret = SECRET_COOKIES.some((s) => k.trim().toLowerCase().includes(s));
        return `${k}=${isSecret ? '<redacted>' : redactText(rest.join('='))}`;
      })
      .join('; ');
  }
  // Keep the scheme so the reader can tell bearer from basic from token.
  const scheme = value.match(/^(\w+)\s+/);
  return scheme ? `${scheme[1]} <redacted>` : '<redacted>';
}

/** Mask secret-named keys in a query string or form body, preserving the key. */
function redactParams(input = '') {
  const s = String(input);
  // Query string / form-encoded.
  if (/[=&]/.test(s)) {
    return s
      .split(/([&?])/)
      .map((part) => {
        if (part === '&' || part === '?') return part;
        const i = part.indexOf('=');
        if (i < 0) return part;
        const key = part.slice(0, i);
        const val = part.slice(i + 1);
        return SECRET_KEYS.some((k) => decodeURIComponent(key).toLowerCase().includes(k))
          ? `${key}=<redacted>`
          : `${key}=${redactText(val)}`;
      })
      .join('');
  }
  return redactBody(s);
}

/**
 * Body-agnostic sanitiser: JSON if parseable (key-aware), otherwise
 * query/form-encoded, otherwise free text. Used for both request and response
 * bodies so neither can leak a credential that only its *key name* reveals.
 */
function redactBody(body = '', opts = {}) {
  const s = typeof body === 'string' ? body : JSON.stringify(body);
  try {
    const j = JSON.parse(s);
    return JSON.stringify(maskJson(j));
  } catch {
    // not JSON
  }
  if (/[=&]/.test(s)) return redactParams(s);
  return redactText(s, opts);
}

/** Recursively mask secret keys in a parsed JSON structure. */
function maskJson(obj, depth = 0) {
  if (depth > 12 || obj === null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map((v) => maskJson(v, depth + 1));
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (SECRET_KEYS.some((s) => k.toLowerCase() === s || k.toLowerCase().includes(s))) {
      out[k] = '<redacted>';
    } else if (typeof v === 'object') {
      out[k] = maskJson(v, depth + 1);
    } else {
      out[k] = redactText(String(v));
    }
  }
  return out;
}

/**
 * Redact free text: secrets and token formats.
 *
 * Deliberately does NOT touch these, because they are the evidence:
 *   - shell/SQL/JS payloads
 *   - parameter names, status codes, and URLs the report needs
 *
 * Emails, UUIDs and IPv4 addresses *are* masked, because in a screenshot paste
 * they are usually someone else's data rather than part of the exploit.
 */
function redactText(text = '', opts = {}) {
  let s = String(text);
  s = s.replace(PRIVATEKEY_RX, '-----BEGIN PRIVATE KEY-----<redacted>-----END PRIVATE KEY-----');
  s = s.replace(JWT_RX, '<redacted-jwt>');
  s = s.replace(GH_PAT_RX, '<redacted-token>');
  s = s.replace(SLACK_RX, '<redacted-token>');
  s = s.replace(AWSKEY_RX, '<redacted-key>');
  s = s.replace(BEARER_RX, (m) => `${m.split(/\s+/)[0]} <redacted>`);
  if (opts.maskEmail !== false) s = s.replace(EMAIL_RX, '<redacted-email>');
  if (opts.maskUuid !== false) s = s.replace(UUID_RX, '<redacted-uuid>');
  if (opts.maskIp !== false) s = s.replace(IPV4_RX, '<redacted-ip>');
  return s;
}

/**
 * Flag PII a human should review before submitting, without redacting it.
 * Some evidence is *about* the PII — a report showing that `/api/users` leaks
 * other users' emails is invalid if the emails are masked. So this returns
 * locations to look at, and the human decides.
 */
function reviewForPii(text = '') {
  const findings = [];
  const s = String(text);
  const push = (kind, rx, why) => {
    const m = s.match(rx);
    if (m && m.length) findings.push({ kind, count: m.length, examples: [...new Set(m)].slice(0, 3), why });
  };
  push('email', EMAIL_RX, 'may be a real user address; include only if the finding is about exposing it');
  push('card-like number', LONGDIGIT_RX, 'may be payment data; never submit raw');
  push('private ip', /\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b/g, 'internal address; often in scope as SSRF proof but not otherwise');
  push('bearer/basic token', BEARER_RX, 'live credential — must be redacted');
  push('jwt', JWT_RX, 'session token — must be redacted');
  return findings;
}

/**
 * Sanitize a whole request/response pair, preserving the parts that prove impact.
 *
 * @param pair { request:{method,url,headers,body}, response:{status,headers,body} }
 * @param opts  { maskEmail, maskUuid, maskIp }
 */
function sanitizeEvidence(pair = {}, opts = {}) {
  const out = {};
  if (pair.request) {
    out.request = {
      method: pair.request.method,
      url: redactText(pair.request.url, opts),
      headers: redactHeaders(pair.request.headers || {}),
      body: pair.request.body != null ? redactParams(pair.request.body) : pair.request.body,
    };
  }
  if (pair.response) {
    out.response = {
      status: pair.response.status,      // never masked: the status IS the proof
      headers: redactHeaders(pair.response.headers || {}),
      // A response body is just as likely to carry secrets as a request body —
      // an API echoing back an api_key is common. Route it through the same
      // key-aware path rather than free-text redaction, which only catches
      // tokens whose *format* is recognisable and misses {"api_key":"sk-..."}.
      body: pair.response.body != null ? redactBody(pair.response.body, opts) : pair.response.body,
    };
  }
  out.piiReview = reviewForPii([
    pair.request && pair.request.body, pair.response && pair.response.body,
    pair.request && JSON.stringify(pair.request.headers),
    pair.response && JSON.stringify(pair.response.headers),
  ].filter(Boolean).join('\n'));

  // The PII review deliberately keeps the matched values so a human can judge
  // whether they belong in the report. That makes the review block itself the
  // one place unredacted PII can survive, so it is held separately and excluded
  // from the sanitized artifact.
  return { evidence: out, piiReview: out.piiReview, sanitized: () => { const { piiReview, ...rest } = out; return rest; } };
}

/**
 * Audit a report for anything that must not be submitted.
 * Returns a blocking verdict, because the cost of missing one is an account
 * compromise rather than a rejected report.
 */
function audit(report = {}) {
  const text = JSON.stringify(report);
  const problems = [];
  const add = (severity, kind, detail) => problems.push({ severity, kind, detail });

  for (const m of text.match(AWSKEY_RX) || []) add('block', 'aws-key', m.slice(0, 8));
  for (const m of text.match(GH_PAT_RX) || []) add('block', 'github-token', m.slice(0, 6));
  for (const m of text.match(JWT_RX) || []) add('block', 'jwt', 'a JWT in a report is a live session token');
  for (const m of text.match(SLACK_RX) || []) add('block', 'slack-token', '');
  if (PRIVATEKEY_RX.test(text)) add('block', 'private-key', 'a private key must never be submitted');
  for (const m of text.match(BEARER_RX) || []) add('block', 'auth-header', 'a live credential in the evidence');

  // A cookie header that still carries a secret-named cookie with a real value.
  const cookieLeak = /"(?:cookie|set-cookie)"\s*:\s*"((?:(?!<redacted>)[^"])*)"/gi;
  for (const m of text.matchAll(cookieLeak)) {
    const v = m[1];
    const hit = SECRET_COOKIES.find((c) => new RegExp(`(?:^|;\\s*)${c}=([^;]+)`, 'i').test(v) && !/<redacted>/.test(v));
    if (hit) add('block', 'cookie-value', `cookie "${hit}" still has a real value`);
  }

  const emails = [...new Set(text.match(EMAIL_RX) || [])];
  if (emails.length) add('review', 'emails', `${emails.length} address(es); include only if the finding is about exposing them: ${emails.slice(0, 2).join(', ')}`);
  const uuids = [...new Set(text.match(UUID_RX) || [])];
  if (uuids.length) add('review', 'uuids', `${uuids.length} UUID(s) — often a real user's object id`);
  const ips = [...new Set(text.match(IPV4_RX) || [])];
  if (ips.length) add('review', 'ips', `${ips.length} IP(s)`);

  return {
    safe: problems.every((p) => p.severity !== 'block'),
    blockers: problems.filter((p) => p.severity === 'block'),
    review: problems.filter((p) => p.severity === 'review'),
  };
}

module.exports = {
  redactHeaders, maskHeaderValue, redactParams, redactBody, maskJson, redactText,
  reviewForPii, sanitizeEvidence, audit,
  SECRET_HEADERS, SECRET_COOKIES, SECRET_KEYS,
};
