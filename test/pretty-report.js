'use strict';
const assert = require('assert');
const P = require('../src/pretty-report');

const output = P.renderLocal({
  target: '/tmp/app',
  safety: 'local-only; no network requests; values redacted',
  secrets: { findings: [{ kind: 'github-token', confidence: 0.98, evidence: 'provider pattern matched; value redacted' }] },
  javascript: { leads: [{ title: 'Client-side role gate', evidence: 'static signal only' }] },
  grpc: { results: [{ findings: [{ kind: 'sensitive-rpc-without-auth-signal', evidence: 'static contract signal' }] }] },
});

assert.match(output, /CANDIDATE/);
assert.match(output, /REVIEW/);
assert.match(output, /Why:/);
assert.match(output, /Next:/);
assert.match(output, /pattern match is not a vulnerability/);
console.log('pretty report: ok');
