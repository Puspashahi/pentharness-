'use strict';

const EXIT_CODES = Object.freeze({
  CLEAN: 0,
  FINDINGS: 10,
  INCOMPLETE: 11,
  POLICY_BLOCKED: 12,
  INFRASTRUCTURE_FAILURE: 13,
});

function classify({ findings = 0, coverageComplete = true, policyBlocked = false, infrastructureFailure = false } = {}) {
  if (infrastructureFailure) return { status: 'infrastructure-failure', exitCode: EXIT_CODES.INFRASTRUCTURE_FAILURE };
  if (policyBlocked) return { status: 'policy-blocked', exitCode: EXIT_CODES.POLICY_BLOCKED };
  if (!coverageComplete) return { status: 'incomplete', exitCode: EXIT_CODES.INCOMPLETE };
  if (findings > 0) return { status: 'findings', exitCode: EXIT_CODES.FINDINGS };
  return { status: 'clean', exitCode: EXIT_CODES.CLEAN };
}

module.exports = { EXIT_CODES, classify };
