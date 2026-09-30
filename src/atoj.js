'use strict';
/**
 * Account-takeover chain detection.
 *
 * The highest-severity outcomes in the disclosed set are chains, not single
 * bugs. The reported JWT walkthrough is the canonical shape:
 *
 *   leak the victim's internal ID  ->  forge a token carrying it
 *   -> change the victim's email   ->  request a password reset
 *   -> the reset link now arrives in the attacker's inbox  ->  full takeover
 *
 * Each link is individually low or medium. Together they are account takeover.
 * So the useful output is not "a bug was found" but "these capabilities exist
 * and compose into takeover".
 *
 * This module maps the *capabilities* a target exposes and reports which
 * takeover chains are reachable. It does not perform the takeover.
 */

const { makeLead } = require('./leads');

/**
 * The capability matrix. Each capability is something we can actually observe.
 * A chain is reachable when every step is present.
 */
const CAPABILITIES = {
  id_disclosure: {
    label: 'user ID disclosure',
    detect: [
      // Quoted or unquoted ownership keys carrying a value, in JSON, GraphQL
      // responses, or query strings.
      /["']?(?:user_?id|owner_?id|account_?id|member_?id|created_?by|author_?id)["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{3,}/i,
      // An id field whose value is a UUID (object references).
      /["']?id["']?\s*[:=]\s*["'][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}/i,
      // A GraphQL/user-listing response returning a bare id list.
      /\{[^{}]*"id"\s*:\s*"[^"]{3,}"[^{}]*\}/,
    ],
    why: 'internal identifiers are exposed in responses, so objects can be addressed directly',
  },
  email_change: {
    label: 'email/profile change reachable',
    detect: [
      /\b(update|change|set|modify)[_-]?(?:user|profile|account|email)\b/i,
      /\bprofileFormUpdateUser\b/i,
      /\bmutation\b[^\n]{0,80}\b(?:updateUser|updateProfile|changeEmail|setEmail)\b/i,
    ],
    why: 'an email can be changed; combined with a password reset this yields takeover',
  },
  password_reset: {
    label: 'password reset flow',
    detect: [
      /forgot[-_ ]?password|password[-_ ]?reset|reset[-_ ]?password/i,
      /\b(?:forgotPassword|sendResetLink|requestPasswordReset)\b/i,
    ],
    why: 'a reset flow exists; if the account email is attacker-controlled the link is captured',
  },
  email_identified_by_id: {
    label: 'reset keyed by user id rather than email',
    detect: [
      /reset[^\n]{0,60}(?:user_?id|uid)\b/i,
      /(?:user_?id|uid)\b[^\n]{0,40}reset/i,
    ],
    why: 'reset can be triggered for an arbitrary account by id, not only to the registered address',
  },
  jwt_weak: {
    label: 'JWT accepted without a valid signature',
    detect: [],
    why: 'forged tokens are accepted, so any claim can be asserted',
  },
  session_fixation: {
    label: 'session id accepted externally',
    detect: [/session_?id|sid|jsessionid/i],
    why: 'a caller-supplied session identifier may be honoured',
  },
  oauth_no_state: {
    label: 'OAuth flow without state/nonce',
    detect: [/\/oauth2?\/authorize[^\n]*/i],
    why: 'if state/nonce are absent the flow is vulnerable to CSRF and code interception',
  },
  totp_disclosure: {
    label: 'MFA/OTP material in responses',
    detect: [/\b(?:totp|otp_?secret|mfa_?secret|authenticator)\b/i],
    why: 'second-factor material is exposed, collapsing two-factor to one',
  },
  account_recovery_weak: {
    label: 'recovery answers or fallback weaker than the password',
    detect: [/recovery[_-]?(?:code|answer|phrase)|backup[_-]?code/i],
    why: 'a weaker recovery path undermines the primary credential',
  },
  excessive_tool_authority: {
    label: 'agent tool with model-controlled destination',
    detect: [/tools?\/list|mcpServers|modelcontextprotocol/i],
    why: 'a model-controlled path/command parameter turns any injected instruction into a host-side primitive',
  },
};

/** Observe capabilities from a corpus: captured responses, HTML, JS. */
function observe(corpus) {
  const text = Array.isArray(corpus) ? corpus.join('\n') : String(corpus || '');
  const found = new Set();
  for (const [key, cap] of Object.entries(CAPABILITIES)) {
    if (!cap.detect || !cap.detect.length) continue;
    if (cap.detect.some((rx) => rx.test(text))) found.add(key);
  }
  return found;
}

/**
 * The known takeover chains. Each names its steps; a chain is reachable when
 * all of its steps are present.
 */
const CHAINS = [
  {
    id: 'jwt-forgery-ato',
    title: 'JWT forgery -> identity change -> password reset -> account takeover',
    severity: 'critical',
    steps: ['jwt_weak', 'id_disclosure', 'email_change', 'password_reset'],
    impact: 'An attacker forges a token for a victim identity, changes the account email to one they control, requests a password reset, and receives the link. Full account takeover with no credential theft.',
  },
  {
    id: 'reset-by-id',
    title: 'Password reset addressed by user id -> reset link capture',
    severity: 'high',
    steps: ['id_disclosure', 'email_identified_by_id', 'password_reset'],
    impact: 'A reset can be triggered for an arbitrary account by identifier rather than to the registered address, and the response behaviour may leak the reset state or token.',
  },
  {
    id: 'id-disclosure-idor-chain',
    title: 'ID disclosure -> object-level authorization failure',
    severity: 'high',
    steps: ['id_disclosure'],
    impact: 'Exposed identifiers let an attacker address objects directly, converting every missing ownership check into a reachable data breach.',
  },
  {
    id: 'mfa-bypass',
    title: 'MFA material disclosure -> second factor collapse',
    severity: 'critical',
    steps: ['totp_disclosure'],
    impact: 'Exposed TOTP secrets or backup codes remove the second factor entirely.',
  },
  {
    id: 'recovery-bypass',
    title: 'Weak account recovery -> credential reset without the password',
    severity: 'high',
    steps: ['account_recovery_weak', 'password_reset'],
    impact: 'A recovery path weaker than the primary credential allows takeover without knowing the password.',
  },
  {
    id: 'oauth-no-state',
    title: 'OAuth without state/nonce -> login CSRF and code interception',
    severity: 'high',
    steps: ['oauth_no_state'],
    impact: 'Without state/nonce the flow is vulnerable to login CSRF and authorization-code interception.',
  },
  {
    id: 'ai-tool-authority',
    title: 'Poisoned tool metadata -> model-controlled host primitive -> takeover',
    severity: 'critical',
    steps: ['excessive_tool_authority', 'id_disclosure'],
    impact: 'An agent that connects to a server exposing a tool with a model-controlled path, command or outbound-URL parameter will follow any instruction embedded in that server\'s metadata. Combined with an exposed identifier, the agent can be steered to a specific victim record. This is the shape behind the disclosed IDE and MCP configuration RCE families.',
  },
];

/** Which chains are reachable given the observed capabilities. */
function reachableChains(observed) {
  const have = observed instanceof Set ? observed : new Set(observed);
  const out = [];
  for (const c of CHAINS) {
    const missing = c.steps.filter((s) => !have.has(s));
    if (!missing.length) {
      out.push({ ...c, complete: true, missing: [] });
    } else if (missing.length <= 1) {
      out.push({ ...c, complete: false, missing });
    }
  }
  return out.sort((a, b) => (b.complete - a.complete) || (a.steps.length - b.steps.length));
}

/** Turn reachable chains into leads, with the missing step called out. */
function toLeads(chains, meta = {}) {
  const leads = [];
  for (const c of chains) {
    if (!c.complete) continue;
    const capText = c.steps.map((s) => `${CAPABILITIES[s] ? CAPABILITIES[s].label : s} (${s})`).join(' -> ');
    leads.push(makeLead({
      cls: 'authn',
      title: `ATO CHAIN reachable: ${c.title}`,
      url: meta.url || '',
      source: 'atoj',
      severity_hint: c.severity,
      confidence: 'confirmed',
      evidence: `All required capabilities observed: ${capText}. ${c.impact}`,
      proof_needed: [
        'demonstrate each link individually before chaining them',
        'use test accounts only — do not complete a real takeover',
        'report the chain as one finding with the narrative, not as separate bugs',
      ],
      chain_hints: ['authz', 'business'],
    }));
  }
  return leads;
}

module.exports = { CAPABILITIES, CHAINS, observe, reachableChains, toLeads };
