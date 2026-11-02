'use strict';

/**
 * WebSocket surface analysis.
 *
 * Static analysis identifies message handlers, authorization signals, origin
 * checks, and sensitive message types. Runtime replay remains caller-owned.
 */
const { makeLead } = require('./leads');

const MESSAGE_HANDLER = /(?:onmessage|addEventListener\s*\(\s*['"]message['"]|message\s*=>|message\s*:\s*function)/gi;
const SENSITIVE_MESSAGE = /(admin|role|permission|token|password|secret|balance|transfer|delete|invite|file|upload|execute|subscribe)/i;
const ORIGIN_CHECK = /(?:origin|Origin)\s*(?:===|!==|==|!=|\.includes\s*\()/i;
const AUTH_CHECK = /(authorization|bearer|session|token|jwt|cookie|csrf|role|permission|isAuthenticated)/i;
const SEND_CALL = /\.(?:send|emit)\s*\(/i;

function analyze(source, meta = {}) {
  const text = String(source || '');
  const messages = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (MESSAGE_HANDLER.test(lines[i])) {
      messages.push({
        line: i + 1,
        context: lines.slice(Math.max(0, i - 1), Math.min(lines.length, i + 4)).join('\n').slice(0, 800),
      });
    }
    MESSAGE_HANDLER.lastIndex = 0;
  }
  const sensitive = [...new Set((text.match(/["'`](?:admin|role|permission|token|password|secret|balance|transfer|delete|invite|upload|execute|subscribe)[^"'`]*/gi) || []).map(String))].slice(0, 30);
  const hasHandler = messages.length > 0;
  const hasOrigin = ORIGIN_CHECK.test(text);
  const hasAuth = AUTH_CHECK.test(text);
  const hasSend = SEND_CALL.test(text);
  const findings = [];
  if (hasHandler && !hasOrigin) findings.push({
    kind: 'missing-origin-check',
    severity: 'medium',
    evidence: 'message handler found without an origin comparison',
    proof_needed: ['capture a real WebSocket handshake', 'send a message from an unauthorized origin in a sandbox', 'show a privileged response or state change'],
  });
  if (hasHandler && !hasAuth) findings.push({
    kind: 'missing-message-authorization',
    severity: 'medium',
    evidence: 'message handler found without an obvious authentication/authorization check',
    proof_needed: ['identify the protected message type', 'replay it under an unauthorized identity', 'show the server rejects the message'],
  });
  if (sensitive.length && hasHandler) findings.push({
    kind: 'sensitive-message-surface',
    severity: 'low',
    evidence: `sensitive message labels observed: ${sensitive.join(', ')}`,
    proof_needed: ['map each message to a server-side action', 'compare authorized and unauthorized responses'],
  });
  return {
    source: meta.source || 'input',
    handlers: messages,
    sensitiveMessages: sensitive,
    signals: { hasHandler, hasOrigin, hasAuth, hasSend },
    findings,
    leads: findings.map((f) => makeLead({
      cls: 'authz',
      title: `WebSocket ${f.kind}`,
      url: meta.url || '',
      source: 'websocket',
      severity_hint: f.severity,
      evidence: f.evidence,
      proof_needed: f.proof_needed,
      tags: ['websocket', 'modern-app'],
    })),
  };
}

function compareMessages(a = [], b = []) {
  const left = new Set(a.map((x) => JSON.stringify(x)));
  const right = new Set(b.map((x) => JSON.stringify(x)));
  return {
    onlyLeft: [...left].filter((x) => !right.has(x)).map(JSON.parse),
    onlyRight: [...right].filter((x) => !left.has(x)).map(JSON.parse),
  };
}

module.exports = { analyze, compareMessages, MESSAGE_HANDLER, SENSITIVE_MESSAGE, ORIGIN_CHECK, AUTH_CHECK };
