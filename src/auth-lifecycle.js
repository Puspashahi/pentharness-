'use strict';

/**
 * Authentication/session lifecycle observations. Network execution is injected
 * by the caller so this module remains deterministic and cannot bypass MFA or
 * recovery controls.
 */
function classifyCookie(cookie = {}) {
  const name = String(cookie.name || '');
  return {
    name,
    sessionLike: /session|sid|auth|token|jwt|remember/i.test(name),
    secure: cookie.secure === true,
    httpOnly: cookie.httpOnly === true,
    sameSite: cookie.sameSite || null,
  };
}

function compareSession(before = {}, after = {}) {
  const b = before.session || before.cookie || '';
  const a = after.session || after.cookie || '';
  return {
    rotated: Boolean(b && a && b !== a),
    invalidated: Boolean(b && after.oldSessionAccepted === false),
    oldSessionAccepted: after.oldSessionAccepted,
  };
}

function analyzeLifecycle(observations = {}) {
  const issues = [];
  const login = compareSession(observations.preLogin, observations.postLogin);
  if (observations.preLogin && observations.postLogin && !login.rotated) {
    issues.push({ kind: 'session-fixation', evidence: 'session identifier did not rotate across login', proof_needed: ['capture pre-login and post-login identifiers', 'prove the pre-login identifier was attacker-controlled'] });
  }
  const logout = observations.logout;
  if (logout && logout.oldSessionAccepted === true) {
    issues.push({ kind: 'logout-invalidation', evidence: 'old session remained accepted after logout', proof_needed: ['replay the old session after logout', 'confirm logout completed for the same account'] });
  }
  const refresh = observations.refresh;
  if (refresh && refresh.reused === true && refresh.rotated === false) {
    issues.push({ kind: 'refresh-token-reuse', evidence: 'refresh token was accepted repeatedly without rotation', proof_needed: ['perform two refreshes with the same token', 'confirm both responses issue valid sessions'] });
  }
  return { login, issues };
}

module.exports = { classifyCookie, compareSession, analyzeLifecycle };
