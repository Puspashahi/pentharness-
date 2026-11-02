'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const SCHEMA_VERSION = 1;

function canonical(value) {
  return JSON.stringify(value);
}

function checksum(envelope) {
  const { checksum: ignored, ...unsigned } = envelope;
  return crypto.createHash('sha256').update(canonical(unsigned)).digest('hex');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

class StateStore {
  constructor(file, { schemaVersion = SCHEMA_VERSION, defaultState = {}, migrations = {}, lockTimeoutMs = 5000 } = {}) {
    this.file = path.resolve(file);
    this.backup = `${this.file}.bak`;
    this.lock = `${this.file}.lock`;
    this.schemaVersion = schemaVersion;
    this.defaultState = defaultState;
    this.migrations = migrations;
    this.lockTimeoutMs = lockTimeoutMs;
  }

  async acquireLock() {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const started = Date.now();
    while (true) {
      try {
        fs.mkdirSync(this.lock);
        fs.writeFileSync(path.join(this.lock, 'owner'), `${process.pid}\n`, 'utf8');
        return;
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
        const stat = fs.statSync(this.lock);
        if (Date.now() - stat.mtimeMs > this.lockTimeoutMs) {
          fs.rmSync(this.lock, { recursive: true, force: true });
          continue;
        }
        if (Date.now() - started >= this.lockTimeoutMs) throw new Error(`state lock timeout: ${this.file}`);
        await sleep(10);
      }
    }
  }

  releaseLock() {
    fs.rmSync(this.lock, { recursive: true, force: true });
  }

  parse(raw, source) {
    const envelope = JSON.parse(raw);
    if (!envelope || typeof envelope !== 'object' || !envelope.state) {
      throw new Error(`invalid state envelope: ${source}`);
    }
    if (envelope.checksum !== checksum(envelope)) throw new Error(`state checksum mismatch: ${source}`);
    let version = envelope.schemaVersion;
    let state = envelope.state;
    while (version < this.schemaVersion) {
      const migrate = this.migrations[version];
      if (typeof migrate !== 'function') throw new Error(`missing state migration: ${version}->${version + 1}`);
      state = migrate(state);
      version++;
    }
    if (version !== this.schemaVersion) throw new Error(`unsupported state schema: ${version}`);
    return { revision: envelope.revision, updatedAt: envelope.updatedAt, state };
  }

  readFile(file) {
    return this.parse(fs.readFileSync(file, 'utf8'), file);
  }

  load() {
    if (!fs.existsSync(this.file) && !fs.existsSync(this.backup)) {
      return { revision: 0, updatedAt: null, state: structuredClone(this.defaultState) };
    }
    try {
      return this.readFile(this.file);
    } catch (primaryError) {
      if (!fs.existsSync(this.backup)) throw primaryError;
      const recovered = this.readFile(this.backup);
      fs.copyFileSync(this.backup, this.file);
      return recovered;
    }
  }

  save(state) {
    const current = fs.existsSync(this.file) ? this.load() : { revision: 0 };
    const envelope = {
      schemaVersion: this.schemaVersion,
      revision: current.revision + 1,
      updatedAt: new Date().toISOString(),
      state,
    };
    envelope.checksum = checksum(envelope);
    const temp = `${this.file}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    fs.writeFileSync(temp, JSON.stringify(envelope, null, 2) + '\n', { encoding: 'utf8', mode: 0o600 });
    const fd = fs.openSync(temp, 'r');
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    if (fs.existsSync(this.file)) fs.copyFileSync(this.file, this.backup);
    fs.renameSync(temp, this.file);
    return { revision: envelope.revision, updatedAt: envelope.updatedAt, state };
  }

  async update(mutator) {
    await this.acquireLock();
    try {
      const current = this.load();
      const next = await mutator(structuredClone(current.state), current);
      return this.save(next);
    } finally {
      this.releaseLock();
    }
  }

  async checkpoint(phase, data = {}) {
    return this.update((state) => ({
      ...state,
      phase,
      checkpoints: { ...(state.checkpoints || {}), [phase]: data },
    }));
  }
}

module.exports = { StateStore, SCHEMA_VERSION, checksum };
