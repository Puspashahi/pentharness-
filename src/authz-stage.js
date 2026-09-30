/**
 * Extract the identity/authz/enumeration stage of the hunt pipeline.
 * Kept in its own module so `hunt.js` stays readable and this stage can be run
 * standalone against a live target with credentials.
 */
'use strict';

const path = require('path');
const fs = require('fs');

const AM = require('./authmatrix');
const EN = require('./enumerate');
const ID = require('./identity');
const { makeLead } = require('./leads');
const { readCapture } = require('./capture-io');

/**
 * Provision identities from credentials, then run the authorization matrix and
 * object enumeration. This is the $78,000 pattern automated: log in as two
 * accounts, replay the same routes, diff, then walk adjacent object IDs.
 *
 * @param pw playwright module
 * @param opts { target, loginUrl, accounts:{userA:{u,p},userB:{u,p}}, stateDir, out, log }
 * @returns {{leads:Array, notes:string[], identities:object, matrixRows:number}}
 */
async function runAuthzStage(pw, opts) {
  const { target, loginUrl, accounts, stateDir } = opts;
  const out = { leads: [], notes: [], identities: {}, matrixRows: 0, enumeration: [] };
  // Map a harness identity id to the account name it authenticated as, so
  // ownership markers like alice@corp.test can be recognised as ours.
  const labelFor = (id) => {
    const a = (accounts && accounts[id]) || {};
    if (a.username) return String(a.username).split('@')[0].toLowerCase();
    return String(id).replace(/^user/i, '').toLowerCase();
  };
  if (!pw) { out.notes.push('playwright unavailable — cannot authenticate; supply --identity capture files instead'); return out; }
  if (!accounts || Object.keys(accounts).length < 2) {
    out.notes.push('two accounts required (--user-a/--pass-a and --user-b/--pass-b) for the authorization matrix');
    return out;
  }

  const browser = await pw.chromium.launch({ headless: opts.headful ? false : true });
  try {
    // 1. Provision both identities.
    const prov = await ID.provision(browser, loginUrl, accounts, path.join(stateDir, 'captures'), { baseUrl: target, headful: opts.headful, mode: opts.mode, oauth: opts.oauth, selectors: opts.selectors, routes: opts.routes, headerPolicy: opts.headerPolicy });
    out.identities = prov.identities;
    out.notes.push(...prov.notes);
    if (prov.usable.length < 2) { await browser.close().catch(() => {}); return out; }

    // 2. Load captures and run the cross-identity matrix.
    const sets = prov.usable.map((id) => ({ id, data: readCapture(path.join(stateDir, 'captures', `${id}.jsonl`), id) }));
    const all = sets.flatMap((s) => s.data.map((d) => ({ ...d, identity: d.identity || s.id })));
    out.matrixRows = all.length;

    // Ownership markers, excluding markers seen under multiple identities (leaked/shared).
    const own = new Map();
    for (const r of all) {
      if (r.status < 200 || r.status >= 300) continue;
      const m = AM.ownershipMarkers(r.body);
      if (!m.ids.size && !m.emails.size) continue;
      let a = own.get(r.identity); if (!a) { a = { ids: new Set(), emails: new Set() }; own.set(r.identity, a); }
      m.ids.forEach((x) => a.ids.add(x)); m.emails.forEach((x) => a.emails.add(x));
    }
    // count distinct identities per marker
    const markerHolders = new Map();
    for (const [id, agg] of own) for (const mk of [...agg.ids, ...agg.emails]) { if (!markerHolders.has(mk)) markerHolders.set(mk, new Set()); markerHolders.get(mk).add(id); }
    const ownMarkers = new Map();
    for (const [id, agg] of own) {
      const set = { ids: new Set(), emails: new Set() };
      for (const mk of [...agg.ids, ...agg.emails]) { if ((markerHolders.get(mk) || new Set()).size > 1) continue; if (/^[^\s@]+@[^\s@]+$/.test(mk)) set.emails.add(mk); else set.ids.add(mk); }
      if (set.ids.size || set.emails.size) ownMarkers.set(id, set);
    }

    // 3. Diff every identity pair on the same request shape.
    const byReq = new Map();
    for (const r of all) { const k = `${r.method} ${r.url}`; if (!byReq.has(k)) byReq.set(k, []); byReq.get(k).push(r); }
    for (const [k, obs] of byReq) {
      for (let i = 0; i < obs.length; i++) for (let j = 0; j < obs.length; j++) {
        if (i === j) continue;
        const owner = obs[i], other = obs[j];
        if (owner.identity === other.identity) continue;
        if (owner.status < 200 || owner.status >= 300 || other.status < 200 || other.status >= 300) continue;
        const xid = AM.isCrossIdentityDisclosure(owner.body, other.body, other.identity, ownMarkers.get(other.identity));
        if (!xid.proven) continue;
        out.leads.push(makeLead({
          cls: 'authz',
          title: `PROVEN cross-identity disclosure: ${other.identity} read an object owned by ${owner.identity}`,
          url: k.slice(k.indexOf(' ') + 1),
          source: 'authmatrix', severity_hint: 'high', confidence: 'confirmed',
          evidence: `${xid.reason}. Observed on ${k}.`,
          proof_needed: ['curl reproduction with each identity cookie', 'confirm the object is not intentionally shared'],
        }));
      }
    }

    // 4. Object enumeration (the $78k "counter going up by one").
    // It must run AS the owning identity: an unauthenticated probe would just
    // collect 401s and prove nothing. For each identity we take the object URLs
    // it legitimately holds and walk the adjacent IDs under its own session.
    for (const s of prov.usable) {
      const ownRows = sets.find((x) => x.id === s).data;
      const seeds = [...new Set(ownRows.filter((r) => r.status === 200 && EN.idParamOf(r.url)).map((r) => r.url))]
        .slice(0, Math.ceil((opts.maxEnumTargets || 8) / prov.usable.length));
      if (!seeds.length) continue;
      const storage = prov.identities[s].storage;
      const ctx = await browser.newContext({ storageState: storage, ignoreHTTPSErrors: true, extraHTTPHeaders: (opts.headerPolicy && opts.headerPolicy.active) ? opts.headerPolicy.playwright() : undefined });
      for (const seed of seeds) {
        const res = await EN.enumerate(ctx, seed, { maxSamples: opts.enumSamples || 12, identityLabel: labelFor(s) });
        out.enumeration.push({ identity: s, seed, ok: res.ok, why: res.why, reachable: res.reachable, probes: res.probes, blastRadius: res.blastRadius });
        const lead = EN.toLead(seed, res, { identity: s });
        if (lead) { lead.identity = s; out.leads.push(lead); }
      }
      await ctx.close().catch(() => {});
      if (seeds.length) out.notes.push(`enumeration: ${seeds.length} object URL(s) walked as ${s}`);
    }

  } catch (e) {
    out.notes.push('authz stage error: ' + (e.stack||e.message||e).split('\n').slice(0,3).join(' | '));
  } finally {
    await browser.close().catch(() => {});
  }
  return out;
}

module.exports = { runAuthzStage };
