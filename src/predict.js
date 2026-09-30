'use strict';
/**
 * Parameter → vulnerability-class prediction.
 *
 * Experienced hunters do not fuzz a target with a wordlist; they read the
 * parameter name and immediately know which bug lives behind it. This is
 * documented field knowledge, not guesswork:
 *
 *   url=, src=, dest=, feed=, webhook=      → SSRF
 *   file=, page=, template=, path=, include= → LFI / RFI
 *   id=, user_id=, order=, invoice=, doc=    → IDOR / BOLA
 *   redirect=, next=, returnTo=, goto=       → open redirect
 *   q=, search=, name=, title=, comment=     → XSS / SSTI / SQLi
 *   cmd=, exec=, shell=, ping=, host=        → command injection
 *
 * Predicting the class lets the harness *prioritise* and *pick the right
 * mutation set*, instead of running every probe against every parameter. The
 * market data justifies the ordering: authorization flaws are rising while
 * commodity XSS/SQLi decline, so authz-shaped parameters get tested first and
 * hardest.
 */

/** name pattern → [classes] with weights. Ordered most-specific first. */
const SIGNATURES = [
  // --- command injection (most severe, most specific) ---
  [/\b(cmd|cmdline|command|exec|execute|shell|sh|bash|powershell|ping|nslookup|host|hostname|ip|eval|script|run)\b/i, ['injection'], 95, 'command injection'],

  // --- SSRF: anything that takes a URL ---
  [/\b(url|uri|src|source|dest|destination|feed|webhook|callback|proxy|target|out|redirect_url|return_url|endpoint|host|domain|site|fetch|load|img|image|avatar|track|pixel)\b/i, ['ssrf'], 88, 'SSRF'],

  // --- LFI / RFI ---
  [/\b(file|filename|filepath|path|page|template|include|includes|inc|doc|document|folder|dir|directory|root|view|load|read|open|download|attachment|asset|resource|layout|theme|module|plugin|locale|lang|config|setting)\b/i, ['traversal'], 82, 'LFI/RFI'],

  // --- IDOR / BOLA: the highest-yield class in the current market ---
  [/\b(id|ids|uid|user_id|userid|user|account|account_id|profile|customer|customer_id|member|member_id|order|order_id|invoice|invoice_id|doc|document_id|record|object|asset_id|group_id|team_id|org_id|tenant_id|workspace|project_id|ticket|ticket_id|thread|post|comment_id|message_id|file_id|folder_id|parent|parent_id|child|node|ref|reference|key|uuid|guid|token_ref)\b/i, ['authz'], 92, 'IDOR/BOLA'],

  // --- mass assignment / privilege fields ---
  [/\b(role|roles|is_admin|admin|is_staff|staff|superuser|super|permission|permissions|scope|scopes|level|privilege|group|groups|tenant|org|organization|owner|ownership|verified|is_verified|active|status|state|plan|tier|subscription|balance|credit|quota|price|amount|discount)\b/i, ['authz', 'business'], 80, 'mass assignment / privilege field'],

  // --- authn / session ---
  [/\b(token|jwt|bearer|session|sid|auth|password|passwd|pwd|pass|secret|otp|code|otp_code|mfa|2fa|remember|csrf|xsrf|nonce|state|otp|pin|recovery|reset_token|api_key|apikey|access_token|refresh_token)\b/i, ['authn'], 84, 'auth/session control'],

  // --- open redirect ---
  [/\b(redirect|redirect_url|return|return_to|returnto|returnurl|return_url|next|next_url|goto|go|to|dest|destination|continue|forward|target|out|outbound|redir|redirect_uri|check|checkout_url)\b/i, ['xss'], 70, 'open redirect'],

  // --- injection sinks by reflected text ---
  [/\b(q|query|search|s|keyword|kw|term|text|name|title|subject|comment|message|body|content|description|notes?|label|category|tags?|username|nickname|display_name|first_name|last_name|email|phone|address|bio|about|review|feedback|reply|slug)\b/i, ['xss', 'injection'], 72, 'reflected input'],

  // --- template / expression sinks ---
  [/\b(template|tpl|view|render|theme|layout|partial|include|expr|expression|formula|calc|calculate|filter|sort|order_by|group_by|column|field|select|where|query|sql|raw|json|xml|yaml|data|payload|body|obj|object|struct)\b/i, ['injection'], 70, 'expression/template sink'],

  // --- batching (rate-limit / authz-cache bypass) ---
  [/\b(ids|bulk|batch|many|list|items|records|objects|rows|entries|all|multi|filter\[|where\[)\b/i, ['authz', 'business'], 74, 'batch/bulk operation'],
];

/** Content types that make XXE reachable regardless of parameter name. */
const XML_TYPES = /xml|soap|svg|docx|xlsx|pptx|zip|multipart\/form-data/i;

const NOISE_PARAMS = new Set(['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'gclid', 'fbclid', 'ref', 'referrer', '_ga', 'session_id_analytics', 'lang', 'locale', 'theme', 'page_size', 'per_page', 'limit', 'offset', 'cursor', 'sort', 'order', 'format', 'callback', '_', 't', 'v', 'nocache']);

/**
 * Predict which vulnerability classes a parameter should be tested against.
 * @returns {{param, classes, score, reason, sink, is_noise}}
 */
function predict(paramName, ctx = {}) {
  const name = String(paramName || '');
  if (!name) return { param: name, classes: [], score: 0, reason: 'no name', sink: null, is_noise: false };
  if (NOISE_PARAMS.has(name.toLowerCase())) {
    return { param: name, classes: [], score: 0, reason: 'analytics/pagination noise', sink: null, is_noise: true };
  }

  let best = null;
  for (const [rx, classes, score, reason] of SIGNATURES) {
    // Match on whole tokens so `host_id` matches the IDOR rule, not SSRF,
    // and `file_id` does not silently become SSRF.
    const m = name.match(new RegExp(`(?:^|[^a-z0-9])(${rx.source})(?:$|[^a-z0-9])`, 'i'));
    if (m) {
      // tokenised match is stronger than a substring match
      const exact = new RegExp(`^(?:${rx.source})$`, 'i').test(name);
      const s = exact ? score : score - 8;
      if (!best || s > best.score) best = { classes, score: s, reason, exact };
    }
  }

  let sink = null;
  if (best) sink = best.reason;
  // Content-type can add XXE regardless of the parameter name.
  if (ctx.contentType && XML_TYPES.test(ctx.contentType)) {
    const c = ['injection'];
    if (!best || best.score < 78) {
      return { param: name, classes: c, score: 74, reason: 'XML-capable content type (XXE reachable)', sink: 'xml body', is_noise: false };
    }
    best.classes = [...new Set([...best.classes, 'injection'])];
  }
  // A numeric-looking id in a path segment is an object reference even if the
  // name is opaque: /api/v1/order/88213
  if (!best && ctx.fromPath && /^\d+$/.test(ctx.value || '')) {
    return { param: name, classes: ['authz'], score: 70, reason: 'numeric object reference in path', sink: 'path segment', is_noise: false };
  }

  if (!best) return { param: name, classes: [], score: 0, reason: 'no signature match', sink: null, is_noise: false };
  return { param: name, classes: best.classes, score: best.score, reason: best.reason, sink, is_noise: false, exact: best.exact };
}

/** Rank a set of parameters by expected yield. */
function rank(params, ctx = {}) {
  return (params || [])
    .map((p) => (typeof p === 'string' ? predict(p, ctx) : predict(p.name || p.param, { ...ctx, ...p })))
    .filter((r) => !r.is_noise)
    .sort((a, b) => b.score - a.score);
}

/**
 * Which mutation set to run for a given predicted class. Running the injection
 * payload battery against a `page=` parameter is wasted time and extra noise;
 * running traversal against `redirect=` is the same.
 */
function mutationPlan(classes) {
  const set = new Set();
  for (const c of classes || []) {
    switch (c) {
      case 'authz': set.add('identity-swap'); set.add('object-swap'); set.add('method-matrix'); set.add('field-injection'); set.add('version-downgrade'); break;
      case 'injection': set.add('sqli-error'); set.add('sqli-boolean'); set.add('sqli-time'); set.add('xss-context'); set.add('ssti'); break;
      case 'ssrf': set.add('ssrf-scheme'); set.add('ssrf-internal'); set.add('oob-callback'); break;
      case 'traversal': set.add('traversal-relative'); set.add('traversal-absolute'); set.add('nullbyte'); break;
      case 'xss': set.add('xss-context'); set.add('open-redirect'); break;
      case 'authn': set.add('session-fixation'); set.add('token-lifetime'); set.add('password-reset'); break;
      case 'business': set.add('negative-value'); set.add('limit-bypass'); set.add('state-skip'); set.add('race'); break;
      default: break;
    }
  }
  return [...set];
}

module.exports = { predict, rank, mutationPlan, SIGNATURES, NOISE_PARAMS, XML_TYPES };
