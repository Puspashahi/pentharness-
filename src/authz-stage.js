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
/**
 * Cross-identity matrix over already-loaded capture rows.
 *
 * Shared by both provisioning paths — fresh logins and pre-captured files — so
 * a header-authenticated target gets exactly the same analysis a password-login
 * target gets. Object enumeration is deliberately left out: it needs a live
 * browser context, which a capture file does not have.
 */
async function matrixFromRows({ out, usable, labelFor, maxEnumTargets }) {
  const all = usable.flatMap((s) => s.data);
  out.matrixRows = all.length;

  // Ownership markers per identity, excluding markers seen under more than one
  // identity (those are shared/leaked, and treating them as "owned" is what
  // makes a tool report a user reading their own record as an attack).
  const own = new Map();
  for (const r of all) {
    if (r.status < 200 || r.status >= 300) continue;
    const m = AM.ownershipMarkers(r.body);
    if (!m.ids.size && !m.emails.size) continue;
    let a = own.get(r.identity);
    if (!a) { a = { ids: new Set(), emails: new Set() }; own.set(r.identity, a); }
    m.ids.forEach((x) => a.ids.add(x));
    m.emails.forEach((x) => a.emails.add(x));
  }
  const holders = new Map();
  for (const [id, agg] of own) {
    for (const mk of [...agg.ids, ...agg.emails]) {
      if (!holders.has(mk)) holders.set(mk, new Set());
      holders.get(mk).add(id);
    }
  }
  const ownMarkers = new Map();
  for (const [id, agg] of own) {
    const set = { ids: new Set(), emails: new Set() };
    for (const mk of [...agg.ids, ...agg.emails]) {
      if ((holders.get(mk) || new Set()).size > 1) continue;
      if (/^[^\s@]+@[^\s@]+$/.test(mk)) set.emails.add(mk); else set.ids.add(mk);
    }
    if (set.ids.size || set.emails.size) ownMarkers.set(id, set);
  }

  // Diff every identity pair on the same request shape.
  const byReq = new Map();
  for (const r of all) {
    const k = `${r.method} ${r.url}`;
    if (!byReq.has(k)) byReq.set(k, []);
    byReq.get(k).push(r);
  }
  const seen = new Set();
  for (const [k, obs] of byReq) {
    for (let i = 0; i < obs.length; i++) {
      for (let j = 0; j < obs.length; j++) {
        if (i === j) continue;
        const owner = obs[i], other = obs[j];
        if (owner.identity === other.identity) continue;
        if (owner.status < 200 || owner.status >= 300 || other.status < 200 || other.status >= 300) continue;
        const xid = AM.isCrossIdentityDisclosure(owner.body, other.body, other.identity, ownMarkers.get(other.identity));
        if (!xid.proven) continue;
        // Same class + same endpoint, discovered from both directions, is one
        // finding — not two.
        const key = `${k}|${owner.identity}|${other.identity}`;
        if (seen.has(key)) continue;
        seen.add(key);
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
  }
  // ---- function-level authorization (BFLA) --------------------------------
  //
  // The pairwise diff above deliberately skips same-identity pairs (a user
  // reading their own record is not an attack). But the mirror case is a real
  // finding: the SAME identity hitting the SAME url twice and getting a
  // different authorization outcome means the decision is driven by something
  // the client controls — a header, a role field, a method override. That is
  // broken function-level authorization regardless of how many identities you
  // have, and it is invisible to a cross-identity-only check.
  const byIdentityUrl = new Map();
  for (const r of all) {
    const k = `${r.identity}|${r.method} ${r.url}`;
    if (!byIdentityUrl.has(k)) byIdentityUrl.set(k, []);
    byIdentityUrl.get(k).push(r);
  }
  const clsOf = (s) => (s >= 500 ? 5 : s >= 400 ? 4 : s >= 300 ? 3 : s >= 200 ? 2 : 0);
  for (const [k, rows] of byIdentityUrl) {
    if (rows.length < 2) continue;
    const classes = new Set(rows.map((r) => clsOf(r.status)));
    if (classes.size < 2) continue;
    const denied = rows.find((r) => r.status >= 400);
    const allowed = rows.find((r) => r.status >= 200 && r.status < 300);
    if (!denied || !allowed) continue;
    const [ident, req] = k.split('|');
    // Only a success carries the privileged payload worth reporting.
    if (!/flag|secret|token|admin|role|key|password|session|balance/i.test(allowed.body || '')) continue;
    out.leads.push(makeLead({
      cls: 'authz',
      title: `PROVEN broken function-level authorization: ${ident} was denied ${req} and then granted it by client-supplied input`,
      url: req.slice(req.indexOf(' ') + 1),
      source: 'authmatrix',
      severity_hint: 'high',
      confidence: 'confirmed',
      evidence: `Same identity, same route: ${denied.status} then ${allowed.status}. The authorization decision changes with a client-controlled value, so the client can grant itself the privileged response. Denied body: ${String(denied.body || '').slice(0, 80)}. Granted body: ${String(allowed.body || '').slice(0, 120)}.`,
      proof_needed: ['replay with and without the privilege-asserting header/field', 'confirm the program does not intend the client to assert its own role'],
    }));
  }

  out.notes.push(`authz: ${out.leads.length} finding(s) across ${byReq.size} request shape(s)`);
  return out;
}

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

  // Pre-captured identities (`--identity userA=file userB=file`). These need no
  // browser and no credentials, which is what makes them the only option for
  // header-authenticated targets and for replaying captured traffic.
  const captures = opts.captures || {};
  const captureIds = Object.keys(captures);
  if (captureIds.length >= 2) {
    const sets = captureIds.map((id) => ({
      id,
      data: readCapture(captures[id], id).map((r) => ({ ...r, identity: r.identity || id })),
    }));
    const usable = sets.filter((s) => s.data.length);
    if (usable.length >= 2) {
      out.identities = Object.fromEntries(usable.map((s) => [s.id, 'captured']));
      out.notes.push(`authz: using ${usable.length} pre-captured identities (${usable.map((s) => s.id).join(', ')})`);
      return await matrixFromRows({ ...opts, out, usable, labelFor });
    }
    out.notes.push(`authz: ${captureIds.length} capture(s) supplied but under ${usable.length} had usable rows`);
  }

  if (!pw) { out.notes.push('playwright unavailable — cannot authenticate; supply --identity capture files instead'); return out; }
  if (!accounts || Object.keys(accounts).length < 2) {
    out.notes.push('authz: SKIPPED — needs 2 identities. Either --user-a/--pass-a, or two --identity capture files.');
    return out;
  }

  const browser = await pw.chromium.launch({ headless: opts.headful ? false : true });
  try {
    // 1. Provision both identities.
    const prov = await ID.provision(browser, loginUrl, accounts, path.join(stateDir, 'captures'), { baseUrl: target, headful: opts.headful, mode: opts.mode, oauth: opts.oauth, selectors: opts.selectors, routes: opts.routes, headerPolicy: opts.headerPolicy, reuseStorage: opts.reuseStorage, reuseIdentity: opts.reuseIdentity });
    out.identities = prov.identities;
    out.notes.push(...prov.notes);
    if (prov.usable.length < 2) { await browser.close().catch(() => {}); return out; }

    // 2-3. Shared cross-identity matrix over the provisioned captures.
    await matrixFromRows({
      out,
      usable: prov.usable.map((id) => ({ id, data: readCapture(path.join(stateDir, 'captures', `${id}.jsonl`), id) })),
      labelFor,
    });

    // 4. Object enumeration (the $78k "counter going up by one").
    // It must run AS the owning identity: an unauthenticated probe would just
    // collect 401s and prove nothing. For each identity we take the object URLs
    // it legitimately holds and walk the adjacent IDs under its own session.
    for (const s of prov.usable) {
      const ownRows = readCapture(path.join(stateDir, 'captures', `${s}.jsonl`), s);
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
