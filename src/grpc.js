'use strict';

/**
 * Lightweight protobuf contract analysis. It parses service/rpc declarations
 * without executing calls or requiring protoc, making it safe for discovery
 * and test planning.
 */
const { makeLead } = require('./leads');

const SERVICE = /\bservice\s+([A-Za-z_]\w*)\s*\{([\s\S]*?)\}/g;
const RPC = /\brpc\s+([A-Za-z_]\w*)\s*\(\s*(?:stream\s+)?([.\w]+)\s*\)\s*returns\s*\(\s*(?:stream\s+)?([.\w]+)\s*\)/g;
const META_AUTH = /(authorization|bearer|token|oauth|api[_-]?key|metadata)/i;
const SENSITIVE = /(admin|delete|update|create|transfer|password|secret|token|role|permission|balance|payment|upload)/i;

function parseProto(source) {
  const text = String(source || '');
  const services = [];
  let sm;
  while ((sm = SERVICE.exec(text))) {
    const methods = [];
    RPC.lastIndex = 0;
    let rm;
    while ((rm = RPC.exec(sm[2]))) {
      methods.push({
        name: rm[1],
        request: rm[2],
        response: rm[3],
        streaming: /\bstream\s+/.test(rm[0]),
      });
    }
    services.push({ name: sm[1], methods });
  }
  return services;
}

function analyze(source, meta = {}) {
  const services = parseProto(source);
  const methods = services.flatMap((s) => s.methods.map((m) => ({ ...m, service: s.name })));
  const findings = [];
  for (const m of methods) {
    if (SENSITIVE.test(m.name) && !META_AUTH.test(source)) {
      findings.push({
        kind: 'sensitive-rpc-without-auth-signal',
        service: m.service,
        method: m.name,
        severity: 'medium',
        evidence: `${m.service}.${m.name} looks sensitive but the proto contains no obvious auth metadata declaration`,
        proof_needed: ['capture the RPC metadata under two identities', 'verify server-side authorization', 'confirm the method is not intentionally public'],
      });
    }
  }
  return {
    source: meta.source || 'input',
    services,
    methods,
    findings,
    leads: findings.map((f) => makeLead({
      cls: 'authz',
      title: `gRPC ${f.kind}: ${f.service}.${f.method}`,
      url: meta.url || '',
      source: 'grpc',
      severity_hint: f.severity,
      evidence: f.evidence,
      proof_needed: f.proof_needed,
      tags: ['grpc', 'modern-app'],
    })),
  };
}

module.exports = { parseProto, analyze, SERVICE, RPC };
