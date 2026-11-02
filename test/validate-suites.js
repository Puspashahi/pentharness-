'use strict';
/**
 * Suite runner. No framework — plain node so this runs anywhere.
 *
 * Runs every deterministic suite in its own process with a hard timeout, so one
 * hung suite cannot stall the run and a crash cannot take the rest with it.
 *
 * Two suites are excluded by default because they reach the public internet and
 * their runtime is not under our control:
 *
 *   oauth-oob.js  waits on a real interactsh callback
 *   priorart.js   queries the Exploit-DB API
 *
 * Run them deliberately with `node test/validate-suites.js --online`.
 */
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const DIR = __dirname;
const SUITE_TIMEOUT_MS = 120000;

const ONLINE = ['oauth-oob.js', 'priorart.js'];
const OPTIONAL_BROWSER = ['browser.js', 'two-step-login.js'];
const HAS_PLAYWRIGHT = (() => {
  try { require.resolve('playwright'); return true; } catch { return false; }
})();

// Fixture servers, not suites. Each file ends at server.listen() and runs
// forever by design, so it is driven by hand against the browser phases
// (or a real engagement) rather than asserted against. Running them here
// would hang the suite runner.
const FIXTURES = ['graphql-app.js', 'multiuser-app.js'];

// Everything else in test/ is deterministic and offline. Derived from the
// directory so a newly added suite is picked up without editing this file.
const OFFLINE = fs.readdirSync(DIR)
  .filter((f) => f.endsWith('.js') && f !== path.basename(__filename)
    && !ONLINE.includes(f) && !FIXTURES.includes(f))
  .sort();

function run(file) {
  return new Promise((resolve) => {
    const full = path.join(DIR, file);
    if (!fs.existsSync(full)) return resolve({ file, status: 'missing', passed: 0, failed: 0 });

    const child = spawn(process.execPath, [full], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '', done = false;

    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      child.kill('SIGKILL');
      resolve({ file, status: 'timeout', passed: 0, failed: 0, detail: `${SUITE_TIMEOUT_MS / 1000}s` });
    }, SUITE_TIMEOUT_MS);

    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('close', (code) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      const m = /(\d+) passed, (\d+) failed/.exec(out);
      resolve({
        file,
        status: code === 0 ? 'ok' : 'fail',
        passed: m ? +m[1] : 0,
        failed: m ? +m[2] : (code === 0 ? 0 : 1),
        detail: code === 0 ? '' : (err.split('\n').find((l) => /Error|error/.test(l)) || '').slice(0, 90),
      });
    });
  });
}

async function main() {
  const online = process.argv.includes('--online');
  const suites = online ? OFFLINE.concat(ONLINE) : OFFLINE;

  let passed = 0, failed = 0;
  const bad = [];
  const skipped = [];

  for (const f of suites) {
    if (OPTIONAL_BROWSER.includes(f) && !HAS_PLAYWRIGHT) {
      skipped.push(`${f} (Playwright not installed)`);
      console.log(`  skip ${f} (Playwright not installed; install with npm install)`);
      continue;
    }
    const r = await run(f);
    passed += r.passed;
    failed += r.failed;
    if (r.status !== 'ok') bad.push(r);
    const tally = r.passed || r.failed ? ` (${r.passed}/${r.passed + r.failed})` : '';
    console.log(`  ${r.status === 'ok' ? 'ok  ' : 'FAIL'} ${f}${tally}${r.detail ? '  ' + r.detail : ''}`);
  }

  for (const r of bad) if (r.status !== 'ok') console.log(`  FAIL ${r.file}  ${r.status}`);

  console.log(`\n${passed} passed, ${failed} failed across ${suites.length} suites`);
  if (!online) console.log(`skipped ${ONLINE.length} online suites (--online to include): ${ONLINE.join(', ')}`);
  if (skipped.length) console.log(`skipped ${skipped.length} environment suites: ${skipped.join(', ')}`);

  process.exit(failed || bad.length ? 1 : 0);
}

main();