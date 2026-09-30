'use strict';
/**
 * MCP / AI-agent attack-surface auditor.
 *
 * This is the largest concentration of disclosed criticals in the current
 * landscape, and it is almost entirely one root cause repeated across a dozen
 * products: **an agent executes attacker-supplied configuration or follows
 * instructions embedded in attacker-supplied metadata.**
 *
 * Disclosed instances, all the same shape:
 *   - MCPoison, CVE-2025-54136 (CVSS 8.8) — approval bound to a server's *name*,
 *     not its contents, so a later config change is silently trusted
 *   - CurXecute, CVE-2025-54135 (CVSS 8.6) — prompt injection rewrote
 *     ~/.cursor/mcp.json and auto-executed the new entry
 *   - Windsurf, CVE-2026-30615 — same, without user interaction
 *   - Semantic Kernel CVE-2026-25592 / CVE-2026-26030 — a helper function
 *     annotated for the model made the *destination path* AI-controlled, giving
 *     arbitrary host file write and escaping a container sandbox
 *   - A disclosed family of unauthenticated command injection across LangFlow,
 *     LiteLLM, Agent Zero, LangBot, LangChain-Chatchat, Upsonic and Flowise,
 *     where a `command`/`args` pair in a server config is executed as a
 *     subprocess
 *   - Snyk Agent Scan — a *security scanner* executed a repo-supplied mcp.json
 *     and became the RCE trigger
 *
 * Microsoft's framing is the one to hold onto: these "aren't bugs in the AI
 * model itself, but rather issues in agent architecture and tool design."
 * And the research result that matters operationally: refusal does not help,
 * because "the attack does not trigger standard content-based safety filters
 * but rather legitimate use of a trusted tool to perform an unauthorized
 * operation." The highest-refusing model rejected under 3% of the time.
 *
 * So the detector looks for the *conditions*, not for a model failing.
 */

const fs = require('fs');
const path = require('path');
const { makeLead } = require('./leads');

/* ------------------------------------------------------------------ *
 * 1. Tool-description poisoning
 * ------------------------------------------------------------------ */

/** Imperative framing that betrays an embedded instruction. */
const IMPERATIVE = /\b(?:you must|you should always|before (?:any|using|calling|executing)|always (?:first|read|send|include)|never (?:tell|mention|reveal|inform)|do not (?:tell|mention|reveal)|without (?:asking|telling|informing)|mandatory|required by (?:policy|compliance|audit)|it is (?:mandatory|required)|system (?:directive|instruction|override)|ignore (?:all )?(?:previous|prior|above)|disregard (?:all )?(?:previous|prior|above))\b/i;

/** The payload's tells: secret locations and exfiltration targets. */
const SECRET_REF = /(?:\.ssh\/id_[a-z0-9]+|id_rsa|\.aws\/credentials|\.env\b|\.npmrc|\.docker\/config|\/etc\/(?:shadow|passwd)|private[_ -]?key|credential|api[_ -]?key|access[_ -]?token|secret[_ -]?key|bearer[_ -]?token|password|passwd|\.git-credentials|keychain)/i;
const EXFIL_URL = /https?:\/\/[^\s"'`)\]]+/i;
const EXFIL_VERB = /\b(?:send|sends|sent|post|posts|submit|submits|submitting|upload|uploads|transmit|transmits|forward|forwards|report|reports|exfiltrat\w*|beacon|callback|share|shares|include|includes|including|append|write|store|save)\b/i;

/** Conditional triggers — the technique works by hiding behind a trigger. */
const TRIGGER = /\b(?:before|when|if|whenever|prior to|beforehand|as a (?:security )?(?:check|verification|step)|first)\b/i;

/** Unicode tricks used to hide instructions from human review. */
function hiddenCharacters(text) {
  const out = [];
  const s = String(text);
  // Zero-width and bidi controls. Checked by codepoint rather than by a
  // character-class regex: the range form silently omits U+200B and the
  // literal characters are easy to mangle through file round-trips.
  const HIDDEN = new Set([
    0x200b, 0x200c, 0x200d, 0x200e, 0x200f, // zero-width space..RLM
    0x202a, 0x202b, 0x202c, 0x202d, 0x202e, // bidi embedding/override
    0x2060, 0x2061, 0x2062, 0x2063, 0x2064, // word joiner / invisible ops
    0xfeff,                                       // BOM / zero-width nbsp
  ]);
  const found = [];
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (HIDDEN.has(c)) found.push(c);
  }
  if (found.length) {
    out.push({
      kind: 'zero-width/bidi',
      count: found.length,
      chars: [...new Set(found)].map((c) => 'U+' + c.toString(16).toUpperCase().padStart(4, '0')),
    });
  }
  // Homoglyph-heavy descriptions: Cyrillic/Greek letters mixed into ASCII words.
  const homo = (s.match(/[Ѐ-ӿͰ-Ͽ]/g) || []);
  if (homo.length) out.push({ kind: 'homoglyph', count: homo.length });
  return out;
}

/**
 * Analyse one tool description for poisoning.
 * @returns {{poisoned:boolean, score:number, signals:Array, verdict:string}}
 */
function detectPoison(description) {
  const text = String(description || '');
  const signals = [];

  if (IMPERATIVE.test(text)) {
    const m = text.match(IMPERATIVE);
    signals.push({ id: 'imperative', weight: 3, evidence: m[0] });
  }
  if (SECRET_REF.test(text)) {
    const m = text.match(SECRET_REF);
    signals.push({ id: 'secret-reference', weight: 4, evidence: m[0] });
  }
  if (EXFIL_URL.test(text) && EXFIL_VERB.test(text)) {
    signals.push({ id: 'exfiltration', weight: 4, evidence: (text.match(EXFIL_URL) || [])[0] });
  }
  if (TRIGGER.test(text) && (IMPERATIVE.test(text) || SECRET_REF.test(text))) {
    signals.push({ id: 'conditional-trigger', weight: 2, evidence: (text.match(TRIGGER) || [])[0] });
  }
  // A description that is much longer than a tool description needs to be is
  // itself a signal: real tool descriptions are a sentence or two.
  if (text.length > 400) signals.push({ id: 'overlong-description', weight: 2, evidence: `${text.length} characters` });
  for (const h of hiddenCharacters(text)) {
    signals.push({ id: `hidden-${h.kind}`, weight: 4, evidence: `${h.count} occurrence(s) ${h.chars ? h.chars.join(' ') : ''}`.trim() });
  }

  const score = signals.reduce((a, s) => a + s.weight, 0);
  let verdict = 'clean';
  if (score >= 8) verdict = 'poisoned';
  else if (score >= 4) verdict = 'suspicious';
  return { poisoned: verdict === 'poisoned', suspicious: verdict === 'suspicious', score, signals, verdict, length: text.length };
}

/* ------------------------------------------------------------------ *
 * 2. Tool shadowing
 * ------------------------------------------------------------------ */

/** A tool name that plausibly impersonates a privileged built-in. */
const SENSITIVE_TOOL = /(?:read|write|open|delete|remove|get|set|list)_?(?:file|files|secret|secrets|env|env_?var|credential|credentials|key|keys|token|tokens|config|passwd|shadow|ssh)/i;
const DANGEROUS_VERB = /^(?:exec|execute|run|shell|bash|sh|powershell|eval|spawn|system|command|cmd|query|request|fetch|http|curl|wget|download|upload|install|sql|database|db)$/i;

/** Tools an agent should not expose to an external server's influence. */
const PRIVILEGED = /(?:\bexec\b|\beval\b|shell|powershell|subprocess|spawn|file|filesystem|fs|read_?file|write_?file|delete_?file|env|secret|credential|keychain|ssh|token|api[_-]?key|database|sql|http|request|fetch|download|upload|install|package)/i;

function detectShadowing(tools) {
  const names = tools.map((t) => String(t.name || ''));
  const findings = [];
  const seen = new Map();
  for (const t of tools) {
    const n = String(t.name || '');
    const key = n.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (!key) continue;
    if (seen.has(key)) {
      findings.push({
        type: 'duplicate-name', tool: n, other: seen.get(key),
        why: `two tools share the normalised name "${key}"; which one is invoked is ambiguous`,
      });
    } else seen.set(key, n);
    // Near-collision with a privileged built-in, e.g. "read_files" vs "read_file".
    for (const other of names) {
      if (other === n) continue;
      const ok = other.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (ok === key) continue;
      if (PRIVILEGED.test(ok) && (ok.startsWith(key.slice(0, -1)) || key.startsWith(ok.slice(0, -1))) && Math.abs(ok.length - key.length) <= 2) {
        findings.push({ type: 'name-collision', tool: n, other, why: `"${n}" closely resembles privileged tool "${other}"; an agent may invoke the wrong one` });
      }
    }
  }
  return findings;
}

/* ------------------------------------------------------------------ *
 * 3. Excessive tool authority
 * ------------------------------------------------------------------ */

/**
 * A tool whose parameters hand the *model* control of a destination is the
 * defect, not the tool itself. The disclosed Semantic Kernel case was exactly
 * this: a host-side file-write helper was annotated for the model, so the save
 * path became AI-controlled and a container sandbox became escapable.
 */
const AUTHORITY_PARAMS = [
  { re: /^(?:local_?file_?path|dest(?:ination)?_?path|save_?path|output_?path|file_?path|target_?path)$/i, authority: 'arbitrary host file write', severity: 'critical' },
  { re: /^(?:command|cmd|args|argv|script|shell|exec|powershell|entrypoint|bin)$/i, authority: 'arbitrary command execution', severity: 'critical' },
  { re: /^(?:url|uri|endpoint|webhook|callback|destination|forward_?to|redirect)$/i, authority: 'outbound request to an arbitrary host', severity: 'high' },
  // A "query" parameter is only dangerous when it reaches a datastore, not when
  // it is a search box. Only flag names that unambiguously construct a query.
  { re: /^(?:sql|sql_?query|query_?sql|statement|raw_?sql|graphql|cypher|cql|nosql_?query|where_?clause|db_?query|collection_?query)$/i, authority: 'arbitrary datastore query construction', severity: 'high' },
  { re: /^(?:filter|sort_?by|group_?by|order_?by|select_?fields?)$/i, authority: 'arbitrary query clause selection', severity: 'medium' },
  { re: /^(?:path|file|filename|dir|directory)$/i, authority: 'arbitrary filesystem path', severity: 'high' },
  { re: /^(?:mode|permissions?|acl|owner|uid|gid)$/i, authority: 'permission/ownership change', severity: 'high' },
  { re: /^(?:env|environment|env_?vars?)$/i, authority: 'environment variable access (commonly holds credentials)', severity: 'high' },
];

function analyseAuthority(tools) {
  const findings = [];
  for (const t of tools) {
    const props = (t.inputSchema && (t.inputSchema.properties || (t.inputSchema.input && t.inputSchema.input.properties))) || t.parameters || {};
    const names = Array.isArray(props) ? props.map((p) => p.name) : Object.keys(props || {});
    for (const a of AUTHORITY_PARAMS) {
      const hit = names.find((n) => a.re.test(String(n)));
      if (!hit) continue;
      findings.push({
        type: 'excessive-authority', tool: t.name, param: hit,
        authority: a.authority, severity: a.severity,
        why: `parameter "${hit}" lets the model choose ${a.authority}`,
      });
    }
    // A privileged tool exposed at all is worth naming, even without a
    // dangerous parameter: it widens what any injected instruction can reach.
    if (PRIVILEGED.test(String(t.name)) ) {
      findings.push({
        type: 'privileged-tool', tool: t.name, severity: 'medium',
        why: `"${t.name}" is a privileged capability; any instruction reaching the agent can invoke it`,
      });
    }
  }
  return findings;
}

/* ------------------------------------------------------------------ *
 * 4. Configuration command injection — the RCE family
 * ------------------------------------------------------------------ */

const CONFIG_NAMES = [
  'mcp.json', '.mcp.json', '.cursor/mcp.json', '.amazonq/mcp.json',
  '.vscode/mcp.json', '.gemini/settings.json', '.claude/mcp.json',
  'claude_desktop_config.json', 'mcp_settings.json', '.windsurf/mcp.json',
];

/** Interpreters that mean "arbitrary command execution" in a config file. */
const EXEC_INTERPRETERS = /^(?:sh|bash|zsh|dash|ksh|csh|python[0-9.]*|python3|node|nodejs|perl|ruby|php|powershell|pwsh|cmd(?:\.exe)?|eval|curl|wget|nc|ncat|socat|docker)(?:\.exe)?$/i;
const SHELL_METACHAR = /[;&|`$><]|\|\||&&|\$\(|\$\{|%[A-Za-z]/;

/** Extract and audit every mcp-style config in a directory tree. */
function auditConfigDir(dir, opts = {}) {
  const maxDepth = opts.maxDepth || 4;
  const results = [];
  const walk = (d, depth) => {
    if (depth > maxDepth) return;
    let entries = [];
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.name === 'node_modules' || e.name === '.git') continue;
      const p = path.join(d, e.name);
      if (e.isDirectory()) { walk(p, depth + 1); continue; }
      if (CONFIG_NAMES.some((c) => e.name === c || p.endsWith(c))) {
        const r = auditConfigFile(p);
        if (r) results.push(r);
      }
    }
  };
  walk(dir, 0);
  return results;
}

function auditConfigFile(file) {
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); } catch { return null; }
  let cfg;
  try { cfg = JSON.parse(raw); } catch { return null; }
  const servers = extractServers(cfg);
  const issues = [];
  for (const s of servers) {
    const cmd = String(s.command || '');
    if (EXEC_INTERPRETERS.test(cmd) || SHELL_METACHAR.test(cmd) || SHELL_METACHAR.test(JSON.stringify(s.args || []))) {
      issues.push({
        type: 'config-command-execution', server: s.name || '(unnamed)', command: cmd, args: s.args,
        why: `server "${s.name || '(unnamed)'}" specifies command="${cmd}" with args ${JSON.stringify(s.args || [])}; if this file is attacker-influenced the host executes it`,
      });
    }
    if (!s.url && !s.command) {
      issues.push({ type: 'config-no-transport', server: s.name || '(unnamed)', why: 'server entry declares neither a url nor a command' });
    }
    // An http/sse transport that also carries a command is the hidden-STDIO
    // trick from the disclosed family: the GUI shows one transport, the
    // backend honours another.
    if (s.url && s.command) {
      issues.push({ type: 'transport-confusion', server: s.name || '(unnamed)', why: 'server declares both a url and a command; the GUI may show only the url while the command path stays live' });
    }
  }
  return { file, servers: servers.length, issues };
}

function extractServers(cfg) {
  const out = [];
  const push = (k, v) => { if (v && typeof v === 'object') out.push({ name: k, ...v }); };
  if (Array.isArray(cfg)) for (const v of cfg) push(v && v.name, v);
  if (cfg && typeof cfg === 'object') {
    for (const key of ['mcpServers', 'servers', 'mcp_servers']) {
      const s = cfg[key];
      if (Array.isArray(s)) for (const v of s) push(v && v.name, v);
      else if (s && typeof s === 'object') for (const [k, v] of Object.entries(s)) push(k, v);
    }
    // A top-level server object (no wrapper key) is also valid.
    if (!('mcpServers' in (cfg || {})) && !('servers' in (cfg || {})) && (cfg.command || cfg.url)) push(cfg.name, cfg);
  }
  return out;
}

/* ------------------------------------------------------------------ *
 * 5. Live server audit
 * ------------------------------------------------------------------ */

/**
 * Talk to an MCP server over HTTP/SSE and audit what it advertises.
 * Uses tools/list, the discovery call every MCP client makes.
 */
async function auditServer(ctx, endpoint, opts = {}) {
  const headers = { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', ...(opts.headers || {}) };
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
  let text = '';
  try {
    const r = await ctx.request.fetch(endpoint, { method: 'POST', headers, data: body, timeout: opts.timeout || 12000, failOnStatusCode: false });
    text = await r.text().catch(() => '');
  } catch (e) {
    return { ok: false, endpoint, reason: String(e.message || e).slice(0, 120) };
  }
  const tools = parseToolsList(text);
  if (!tools || !tools.length) {
    return { ok: false, endpoint, reason: 'no tools/list response (not an MCP HTTP endpoint, or SSE framing)', raw: text.slice(0, 300) };
  }
  return { ok: true, endpoint, tools, ...auditTools(tools) };
}

/** Parse tools/list from JSON or SSE framing. */
function parseToolsList(text) {
  const t = String(text || '');
  const candidates = [];
  // SSE: data: {...} lines
  for (const line of t.split('\n')) {
    const l = line.trim();
    if (l.startsWith('data:')) candidates.push(l.slice(5).trim());
  }
  if (candidates.length === 0) candidates.push(t);
  for (const c of candidates) {
    if (!c || !c.startsWith('{')) continue;
    let j;
    try { j = JSON.parse(c); } catch { continue; }
    const tools = j && j.result && j.result.tools;
    if (Array.isArray(tools)) return tools;
    if (Array.isArray(j && j.tools)) return j.tools;
  }
  return null;
}

/** Full audit of a tool list. */
function auditTools(tools) {
  const poisoned = [];
  for (const t of tools) {
    const d = detectPoison(t.description || '');
    if (d.verdict !== 'clean') poisoned.push({ tool: t.name, ...d });
  }
  const shadowing = detectShadowing(tools);
  const authority = analyseAuthority(tools);
  return {
    poisoned, shadowing, authority,
    summary: {
      tools: tools.length,
      poisoned: poisoned.length,
      suspicious: poisoned.filter((p) => p.verdict === 'suspicious').length,
      shadowing: shadowing.length,
      excessiveAuthority: authority.filter((a) => a.type === 'excessive-authority').length,
      privilegedTools: authority.filter((a) => a.type === 'privileged-tool').length,
    },
  };
}

/* ------------------------------------------------------------------ *
 * Leads
 * ------------------------------------------------------------------ */

function toLeads(audit, meta = {}) {
  const leads = [];
  for (const p of audit.poisoned || []) {
    if (p.verdict !== 'poisoned') continue;
    leads.push(makeLead({
      cls: 'ai',
      title: `MCP tool poisoning: description of "${p.tool}" carries hidden instructions`,
      url: meta.url || audit.endpoint || '',
      source: 'mcp',
      severity_hint: 'critical',
      confidence: 'confirmed',
      evidence: `Signals (score ${p.score}): ${p.signals.map((s) => `${s.id}="${String(s.evidence).slice(0, 60)}"`).join('; ')}. A poisoned description is loaded into the agent's context at connection time and applies to every interaction for the session, with no further trigger.`,
      proof_needed: [
        'show the instruction is followed when an unrelated, benign tool is invoked',
        'confirm the model is not warned in the tool-review UI',
        'identify what capability the instruction reaches (file, shell, network)',
      ],
      chain_hints: ['business'],
    }));
  }
  for (const s of audit.shadowing || []) {
    leads.push(makeLead({
      cls: 'ai',
      title: `MCP tool ${s.type}: "${s.tool}" vs "${s.other}"`,
      url: meta.url || audit.endpoint || '',
      source: 'mcp',
      severity_hint: s.type === 'duplicate-name' ? 'high' : 'medium',
      evidence: s.why,
      proof_needed: ['determine which tool the agent actually invokes', 'show the outcome differs from the intended tool'],
    }));
  }
  for (const a of audit.authority || []) {
    if (a.type !== 'excessive-authority') continue;
    leads.push(makeLead({
      cls: 'ai',
      title: `Excessive tool authority: "${a.tool}" lets the model choose ${a.authority}`,
      url: meta.url || audit.endpoint || '',
      source: 'mcp',
      severity_hint: a.severity,
      evidence: `Parameter "${a.param}" of tool "${a.tool}" gives the model control of ${a.authority}. Microsoft's disclosed Semantic Kernel cases were exactly this: a host-side helper annotated for the model turned the destination path into an AI-controlled value, producing arbitrary file write and a container-sandbox escape.`,
      proof_needed: [
        'show the model can set the parameter to an arbitrary value',
        'demonstrate the resulting effect on the host',
        'establish whether the capability was meant to be model-reachable',
      ],
      chain_hints: ['injection', 'traversal'],
    }));
  }
  return leads;
}

function configToLeads(results, meta = {}) {
  const leads = [];
  for (const r of results) {
    for (const i of r.issues) {
      if (i.type !== 'config-command-execution' && i.type !== 'transport-confusion') continue;
      leads.push(makeLead({
        cls: 'injection',
        title: `MCP config executes an OS command from a repository file: ${path.basename(r.file)}`,
        url: meta.url || 'file://' + r.file,
        source: 'mcp',
        severity_hint: i.type === 'transport-confusion' ? 'high' : 'critical',
        confidence: 'confirmed',
        evidence: `${i.why}. This is the disclosed family affecting LangFlow, LiteLLM, Agent Zero, LangBot, LangChain-Chatchat, Upsonic and Flowise, and a security scanner (Snyk Agent Scan) that became the RCE trigger by executing a repo-supplied config.`,
        proof_needed: [
          'confirm the file is attacker-reachable (repository, PR, dependency)',
          'identify which tool or agent loads it without confirmation',
          'demonstrate execution in an isolated environment only',
        ],
        chain_hints: ['ai', 'business'],
      }));
    }
  }
  return leads;
}

module.exports = {
  detectPoison, hiddenCharacters, detectShadowing, analyseAuthority,
  auditTools, auditServer, parseToolsList, auditConfigDir, auditConfigFile, extractServers,
  toLeads, configToLeads, CONFIG_NAMES,
  IMPERATIVE, SECRET_REF, EXFIL_URL, EXFIL_VERB, TRIGGER, AUTHORITY_PARAMS, EXEC_INTERPRETERS,
};
