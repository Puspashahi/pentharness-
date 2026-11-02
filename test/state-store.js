'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { StateStore } = require('../src/state-store');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pentharness-state-'));
const file = path.join(dir, 'run.json');

async function main() {
  const store = new StateStore(file, { defaultState: { phase: 'init' } });
  assert.deepStrictEqual(store.load().state, { phase: 'init' });
  const first = await store.checkpoint('discover', { cursor: 3 });
  assert.strictEqual(first.revision, 1);
  assert.deepStrictEqual(store.load().state.checkpoints.discover, { cursor: 3 });
  const second = await store.update((state) => ({ ...state, phase: 'execute' }));
  assert.strictEqual(second.revision, 2);
  assert.strictEqual(store.load().state.phase, 'execute');

  fs.copyFileSync(file, `${file}.bak`);
  fs.writeFileSync(file, '{"broken":');
  assert.strictEqual(store.load().state.phase, 'execute');

  const migrated = new StateStore(path.join(dir, 'old.json'), {
    schemaVersion: 2,
    defaultState: {},
    migrations: { 1: (state) => ({ ...state, migrated: true }) },
  });
  const old = {
    schemaVersion: 1,
    revision: 1,
    updatedAt: new Date().toISOString(),
    state: { phase: 'old' },
  };
  const { checksum } = require('../src/state-store');
  old.checksum = checksum(old);
  fs.writeFileSync(migrated.file, JSON.stringify(old));
  assert.strictEqual(migrated.load().state.migrated, true);

  console.log('state-store: ok');
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
