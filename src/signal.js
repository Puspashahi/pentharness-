'use strict';
/**
 * Signal-based confirmation.
 *
 * Long before any of this was automated, IntelOligarch's "The Hacker's
 * Handbook" described a discipline most scanners skip: before reporting, look
 * for the *side effects* of the vulnerability. A successful exploit changes
 * state the tester can observe, and that observable change is what separates a
 * confirmed finding from a hopeful one.
 *
 *   signal 0 — no side effect observed          -> not vulnerable
 *   signal 3 — a side effect occurred           -> vulnerable
 *   signal 9 — cannot tell, need a side channel  -> untestable this way
 *
 * The value is negative. Most false positives are signal 0: the payload was
 * reflected, the scanner said "vulnerable", and nothing actually happened.
 * Recording the side channel first, *before* attacking, prevents the classic
 * trap of trying to prove a bug by inventing evidence for it after the fact.
 *
 * This module refuses to emit `signal 3` without a recorded observation, which
 * is the entire point.
 */

const SIGNAL = { NONE: 0, LOW: 1, MEDIUM: 2, STRONG: 3, UNKNOWN: 9 };

const SIGNAL_NAMES = {
  0: 'no side effect — treat as not vulnerable',
  1: 'weak signal — inconclusive, needs a stronger side channel',
  2: 'moderate signal — plausible, unconfirmed',
  3: 'side effect observed — vulnerable',
  9: 'cannot determine without a side channel',
};

/** Side channels by vulnerability class. Chosen so the effect is observable. */
const SIDE_CHANNELS = {
  sqli: [
    { id: 'db-content', hint: 'a value from another table appears in the response' },
    { id: 'union-columns', hint: 'the column count matches a UNION probe and the shape changes' },
    { id: 'time', hint: 'consistent, repeatable latency delta against a control query' },
    { id: 'error-based', hint: 'a database error string appears that the control request does not produce' },
  ],
  xss: [
    { id: 'dialog', hint: 'an alert/confirm dialog fires in a real browser' },
    { id: 'dom-node', hint: 'the injected node exists as a parsed element, not escaped text' },
    { id: 'cookie-write', hint: 'document.cookie becomes settable where it was not before' },
    { id: 'callback', hint: 'an out-of-band beacon fires from the rendered page' },
  ],
  ssrf: [
    { id: 'dns', hint: 'a DNS lookup for a unique hostname is observed' },
    { id: 'http', hint: 'an HTTP request to a unique host arrives' },
    { id: 'metadata', hint: 'cloud metadata content is echoed back' },
    { id: 'port', hint: 'a port that is closed to the tester answers from inside the network' },
  ],
  cmdi: [
    { id: 'dns', hint: 'a DNS lookup carrying a unique token resolves' },
    { id: 'sleep', hint: 'a sleep payload delays the response repeatably' },
    { id: 'file', hint: 'a file the tester seeded is created on the server' },
    { id: 'output', hint: 'command output appears in the response' },
  ],
  idor: [
    { id: 'other-user-data', hint: 'a response contains data owned by a different identity' },
    { id: 'other-user-marker', hint: 'the other identity\'s marker (email, name, id) appears' },
    { id: 'write', hint: 'a write under identity A is visible when read as identity B' },
  ],
  rce: [
    { id: 'dns', hint: 'a unique hostname resolves from the target' },
    { id: 'file', hint: 'a file appears on disk' },
    { id: 'whoami', hint: 'identity/hostname output confirms code execution' },
  ],
};

/**
 * Define the observation plan BEFORE attacking.
 *
 * @returns {{cls, channels, confirmIf, refuteIf}}
 */
function plan(cls) {
  const channels = SIDE_CHANNELS[String(cls).toLowerCase()] || SIDE_CHANNELS.sqli;
  return {
    cls,
    channels,
    // Written down first so the test cannot be retrofitted to the result.
    confirmIf: `at least one side channel fires: ${channels.map((c) => c.id).join(' | ')}`,
    refuteIf: 'the control request and the attack request produce no observable difference',
    note: 'record the side channel before testing; if none is available, the class is untestable this way',
  };
}

/**
 * Classify an observation into a signal.
 *
 * @param obs {
 *   control:  what the unmodified request did
 *   attack:   what the attack request did
 *   channels: which side channels were watched
 *   fired:    which actually fired
 *   reproducible: did it fire twice?
 *   blocked:  was the payload visibly blocked/filtered (waf, sanitize)?
 * }
 */
function classify(obs = {}) {
  const { channels = [], fired = [], reproducible = false, blocked = false } = obs;

  if (blocked) {
    return {
      signal: SIGNAL.NONE,
      name: SIGNAL_NAMES[0],
      why: 'the payload was observably blocked or sanitised, so no vulnerable path was exercised',
      action: 'not vulnerable via this vector (a blocked payload is not a finding)',
    };
  }

  if (!fired.length) {
    return {
      signal: SIGNAL.NONE,
      name: SIGNAL_NAMES[0],
      why: 'no watched side channel produced an effect; control and attack were indistinguishable',
      action: 'refute — do not report this as a finding',
      // This is the most valuable output of the module.
      confidenceNote: 'a reflected payload with no side effect is the standard false positive',
    };
  }

  if (!reproducible) {
    return {
      signal: SIGNAL.LOW,
      name: SIGNAL_NAMES[1],
      why: 'a channel fired once but did not reproduce; this is usually noise or a race',
      action: 'retry 3x; if it still does not reproduce, refute',
    };
  }

  // Weight strong channels above weak ones.
  const strong = fired.some((f) => /dialog|callback|other-user|whoami|metadata|port|file|db-content/.test(f));
  const weakOnly = fired.every((f) => /sleep|time|error-based/.test(f));

  if (weakOnly) {
    return {
      signal: SIGNAL.MEDIUM,
      name: SIGNAL_NAMES[2],
      why: 'only a timing or error channel fired, reproducibly; that is suggestive but has benign explanations',
      action: 'strengthen with a content or OOB channel before reporting',
    };
  }

  // Validate the reported channel against the plan BEFORE deciding strength.
  // This ordering matters: an earlier version checked strength first and only
  // validated membership on the non-weak branch, so a legitimate `dialog` on
  // an XSS plan was reported as signal 9 ("unrecognised") purely because of the
  // branch it happened to take.
  //
  // Accept both shapes for `channels`: `plan()` returns objects ({id, hint}),
  // while callers naturally pass a bare array of ids. Mapping `c => c.id` over
  // an array of strings yields [undefined], which silently rejected every real
  // channel and was the actual cause of the false signal 9.
  const defined = channels.map((c) => (c && typeof c === 'object' ? c.id : c)).filter(Boolean);
  const unknown = defined.length ? fired.filter((f) => !defined.includes(f)) : [];
  if (unknown.length) {
    return {
      signal: SIGNAL.UNKNOWN,
      name: SIGNAL_NAMES[9],
      why: `reported effect(s) ${unknown.join(', ')} are not among the side channels defined for this class`,
      action: 'verify the observation before trusting it',
    };
  }

  return {
    signal: SIGNAL.STRONG,
    name: SIGNAL_NAMES[3],
    why: `side channel(s) ${fired.join(', ')} fired reproducibly — the vulnerability changed observable state`,
    action: 'reportable; include the control-vs-attack pair as evidence',
    evidenceNeeded: ['the unmodified control request and its response', 'the attack request and the observed side effect'],
  };
}

/** Render the plan for a report or a run log. */
function describe(cls) {
  const p = plan(cls);
  return {
    ...p,
    readable: `To confirm ${cls}: watch for ${p.channels.map((c) => `${c.id} (${c.hint})`).join('; ')}.\n`
      + `Confirm if: ${p.confirmIf}.\nRefute if: ${p.refuteIf}.`,
  };
}

module.exports = { SIGNAL, SIGNAL_NAMES, SIDE_CHANNELS, plan, classify, describe };
