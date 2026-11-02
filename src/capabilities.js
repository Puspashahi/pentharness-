'use strict';

const STATES = new Set(['supported', 'planned', 'executed', 'proven', 'unsupported', 'not-tested']);

class CapabilityMatrix {
  constructor(entries = []) {
    this.entries = [];
    for (const entry of entries) this.add(entry);
  }

  add({ id, area, state = 'not-tested', evidence = null, reason = null } = {}) {
    if (!id || !area) throw new TypeError('capability id and area are required');
    if (!STATES.has(state)) throw new Error(`invalid capability state: ${state}`);
    this.entries.push({ id: String(id), area: String(area), state, evidence, reason });
    return this;
  }

  byState() {
    return this.entries.reduce((out, entry) => {
      (out[entry.state] ||= []).push(entry);
      return out;
    }, {});
  }

  toJSON() {
    return { schemaVersion: 1, states: [...STATES], capabilities: this.entries.slice(), summary: Object.fromEntries(Object.entries(this.byState()).map(([k, v]) => [k, v.length])) };
  }
}

function fromManifest(manifest) {
  const matrix = new CapabilityMatrix();
  for (const scenario of manifest.scenarios || []) {
    matrix.add({
      id: scenario.id,
      area: scenario.class,
      state: scenario.status === 'executable' ? 'supported' : 'planned',
      reason: scenario.status === 'executable' ? null : 'fixture and oracle are not implemented yet',
    });
  }
  return matrix;
}

module.exports = { STATES, CapabilityMatrix, fromManifest };
