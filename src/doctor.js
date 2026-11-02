'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

function commandVersion(command, args = ['--version']) {
  const result = spawnSync(command, args, { encoding: 'utf8', timeout: 5000 });
  if (result.error || result.status !== 0) return null;
  return String(result.stdout || result.stderr || '').trim().split(/\r?\n/)[0] || null;
}

function semverMajor(version) {
  const match = String(version || '').match(/v?(\d+)/);
  return match ? Number(match[1]) : null;
}

function check(name, status, detail, required = false) {
  return { name, status, detail, required };
}

function run({ root = process.cwd(), requirePython = false, requireGo = false } = {}) {
  const checks = [];
  const nodeMajor = semverMajor(process.version);
  checks.push(check('node', nodeMajor >= 18 ? 'ok' : 'fail', `${process.version} (requires >=18)`, true));

  for (const [name, required] of [['python', requirePython], ['go', requireGo], ['git', false]]) {
    const version = commandVersion(name, name === 'python' ? ['--version'] : ['version']);
    checks.push(check(name, version ? 'ok' : (required ? 'fail' : 'warn'), version || 'not installed', required));
  }

  let playwright = false;
  try { require.resolve('playwright', { paths: [root] }); playwright = true; } catch {}
  checks.push(check('playwright', playwright ? 'ok' : 'warn', playwright ? 'installed' : 'not installed; browser suites will skip'));

  const browserCandidates = [
    process.env.PLAYWRIGHT_BROWSERS_PATH && path.join(process.env.PLAYWRIGHT_BROWSERS_PATH, 'chromium'),
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/usr/bin/google-chrome',
  ].filter(Boolean);
  const browser = browserCandidates.find((candidate) => fs.existsSync(candidate));
  checks.push(check('browser', browser ? 'ok' : 'warn', browser || 'no Chromium executable detected'));

  const writable = (() => {
    try {
      fs.accessSync(root, fs.constants.R_OK | fs.constants.W_OK);
      return true;
    } catch { return false; }
  })();
  checks.push(check('workspace-permissions', writable ? 'ok' : 'fail', writable ? `${root} is readable and writable` : `${root} is not readable and writable`, true));

  const external = ['curl', 'bash'];
  for (const command of external) {
    const version = commandVersion(command);
    checks.push(check(command, version ? 'ok' : 'warn', version || 'not installed'));
  }

  const failed = checks.filter((item) => item.required && item.status === 'fail');
  return {
    schemaVersion: 1,
    tool: 'pentharness-doctor',
    safety: 'offline diagnostics; no target or external network requests',
    platform: { os: os.platform(), arch: os.arch(), cwd: root },
    checks,
    ok: failed.length === 0,
    exitCode: failed.length ? 2 : 0,
  };
}

function format(report) {
  const lines = [`${report.tool}: ${report.ok ? 'ok' : 'failed'}`];
  for (const item of report.checks) lines.push(`  ${item.status.padEnd(4)} ${item.name.padEnd(22)} ${item.detail}`);
  return lines.join('\n');
}

module.exports = { run, format, commandVersion };
