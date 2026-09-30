'use strict';
/**
 * Program-mandated request headers.
 *
 * Bug bounty programs frequently require every request to carry an identifying
 * header so their team can distinguish authorized research from attack traffic.
 * MATLAB Online, for example:
 *
 *   X-Request-Purpose: BugcrowdResearch     (required)
 *   X-Bugcrowd-Ninja: <username>            (optional but recommended)
 *
 * Omitting it gets the researcher blocked, and — worse for a program — makes the
 * traffic indistinguishable from a real attack. So the headers are defined in
 * one place and injected everywhere: the Playwright contexts, the internal HTTP
 * context, and every external tool (httpx, katana, arjun, nuclei, webfuzz).
 *
 * Nothing is hardcoded to one program. Values come from flags, a recipe file, or
 * the environment, so the same harness works against any program with its own
 * header requirement.
 */

/** Reserved: never send these to a target even if a recipe asks. */
const FORBIDDEN_HOSTS = [
  // Features the MATLAB Online brief prohibits: service requests reach staff.
  /support|service[-_]?request|ticket|helpdesk/i,
];

/**
 * Paths/URLs the brief forbids, matched before any request is sent.
 *
 * Deliberately narrow. An earlier version blocked any path segment named
 * "help", which would have blocked MATLAB Online's entire documentation
 * (/help/matlab/ref/...) — that is the product's main content, not a support
 * channel. The prohibition is on *contacting people* (service requests,
 * feedback), not on reading documentation, so each pattern must name the
 * contact action specifically.
 */
const FORBIDDEN_PATTERNS = [
  // A service request opens a ticket that reaches MathWorks staff — prohibited.
  /\/(?:service[-_]?request|service_request|support[-_]?ticket)\b/i,
  /\/(?:api|account|profile)\/[^/?#]*(?:service[-_]?request|feedback)/i,
  // Contact/sales/support actions. `/support` and `/contact` as whole path
  // segments are channels into staff, unlike `/help/...` documentation.
  /\/(?:support|contact(?:-us)?|contact[-_]?sales|sales[-_]?enquiry|enquiry|enquir|feedback|submit[-_]?feedback)(?:[/?#]|$)/i,
  // Live-chat and callback widgets commonly front these.
  /\/(?:live[-_]?chat|chat[-_]?start|start[-_]?chat|callback[-_]?request)(?:[/?#]|$)/i,
];

class HeaderPolicy {
  /**
   * @param {object} opts
   *   headers   {object}   headers to send on every request
   *   throttle  {number}   max requests per minute for rate-limited paths
   *   dryRun    {boolean}  log headers instead of sending them
   */
  constructor(opts = {}) {
    this.headers = {};
    for (const [k, v] of Object.entries(opts.headers || {})) {
      const key = String(k).trim();
      const val = String(v).trim();
      if (key && val && !/[\r\n]/.test(key + val)) this.headers[key] = val;
    }
    this.throttlePerMin = Number(opts.throttle) || 0;
    this.dryRun = !!opts.dryRun;
    this.sent = 0;
    this.blocked = [];
    this._window = [];
  }

  get active() { return Object.keys(this.headers).length > 0; }

  /** Header list in the `Name: value` form every CLI tool expects. */
  asList() {
    return Object.entries(this.headers).map(([k, v]) => `${k}: ${v}`);
  }

  /** Extra flags to append to an external tool's argv. */
  flagsFor(bin) {
    if (!this.active) return [];
    const f = this.asList();
    switch (bin) {
      case 'httpx-pd':
      case 'httpx':
      case 'nuclei':
      case 'katana':
      case 'arjun':
      case 'ffuf': {
        // Each of these takes a repeatable -H in `Name: value` form.
        const out = [];
        for (const h of f) out.push('-H', h);
        return out;
      }
      default: return [];
    }
  }

  /** Playwright `extraHTTPHeaders`. */
  playwright() {
    return this.active ? { ...this.headers } : undefined;
  }

  /** Merge with per-request headers; policy headers win so they cannot be dropped. */
  merge(perRequest) {
    return { ...(perRequest || {}), ...this.headers };
  }

  /** Should this URL be touched at all? */
  isAllowed(url) {
    const u = String(url || '');
    for (const p of FORBIDDEN_PATTERNS) if (p.test(u)) { this.blocked.push({ url: u, why: 'matches a program-prohibited feature' }); return false; }
    return true;
  }

  /**
   * Consume one slot of the per-minute budget. Returns true when the caller may
   * proceed. Used for endpoints a program has explicitly rate-limited.
   */
  async take() {
    if (!this.throttlePerMin) return true;
    const now = Date.now();
    this._window = this._window.filter((t) => now - t < 60000);
    if (this._window.length >= this.throttlePerMin) {
      const wait = 60000 - (now - this._window[0]) + 250;
      await new Promise((r) => setTimeout(r, Math.max(0, wait)));
      this._window = [];
    }
    this._window.push(Date.now());
    this.sent++;
    return true;
  }

  describe() {
    if (!this.active) return 'no program headers configured';
    const keys = Object.keys(this.headers);
    const shown = keys.map((k) => (/ninja|token|key|auth|secret/i.test(k) ? `${k}: <redacted>` : `${k}: ${this.headers[k]}`));
    return shown.join(', ') + (this.throttlePerMin ? `  [throttle ${this.throttlePerMin}/min]` : '');
  }

  toJSON() {
    return { headers: Object.keys(this.headers), throttlePerMin: this.throttlePerMin, sent: this.sent, blocked: this.blocked.length };
  }
}

module.exports = { HeaderPolicy, FORBIDDEN_PATTERNS };
