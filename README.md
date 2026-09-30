# pentharness

A deterministic harness for authorized penetration testing. It maps a target,
reads the JavaScript it actually serves, drives a real browser, proves or
refutes every claim, and refuses to ship anything it cannot demonstrate.

The design principle is that **a lead is not a finding**. Most automated
pentesting produces volume; this produces a short list of things that survive
adversarial refutation, plus an honest statement of what was never tested.

> **Authorized targets only.** You must own the target or have written
> permission. Non-destructive by default: no destructive payloads, no data
> exfiltration, no persistence, no denial-of-service. See `POLICY.md`.

---

## Quick start

```bash
npm install playwright
npx playwright install chromium
ln -s "$PWD/src/cli.js" /usr/local/bin/pentharness

pentharness https://target.tld --hunt
```

That single command runs the full pipeline. It reads JavaScript, clicks through
the app, injects payloads, enumerates subdomains, checks for takeover, probes,
and gates every result.

---

## What one command actually does

```
subs        subdomain enumeration, scope-gated before any request
takeover    dangling CNAME check on third-party targets
auth        authenticate FIRST, so every later phase is logged in
map         httpx / katana / arjun -> knowledge base
js          capture the app's real bundles, extract endpoints and secrets
browser     click through the app, submit forms, inject, judge by side effect
predict     rank parameters by predicted vulnerability class
execute     real payloads with evidence capture
prove       layered oracles + adversarial refutation
authz       two identities diffed, sequential-ID enumeration
protocols   GraphQL / JWT / cache / MCP / postMessage
correlate   composable attack chains
gate        proof gate + coverage gate -> findings.json
change      what is new since last run, and what was never probed
```

Ordering matters here. Authentication runs **before** discovery, because an
anonymous crawl only ever sees the login page — no application JavaScript, no
authenticated endpoints, no forms beyond sign-in. On a real target that
difference is the difference between finding nothing and finding something.

---

## Use

```bash
# unauthenticated
pentharness https://target.tld --hunt

# two real accounts — the highest-yield class
pentharness https://target.tld --hunt \
  --login https://target.tld/login/ \
  --user-a alice@corp.test --pass-a pw \
  --user-b bob@corp.test   --pass-b pw

# via Okta/Azure/Google, credentials out of shell history
pentharness https://target.tld --hunt --recipe ./target.recipe.json

# a bug bounty program that mandates an identification header
pentharness https://target.tld --hunt \
  --research-header 'X-Request-Purpose: BugcrowdResearch' \
  --ninja your_username \
  --scope target.tld --throttle-per-min 25
```

### recipe.json

```json
{
  "startUrl": "https://target.tld/login/",
  "appOrigin": "https://target.tld",
  "headers": { "X-Request-Purpose": "BugcrowdResearch" },
  "accounts": {
    "userA": { "username": "alice@corp.test", "password": "..." },
    "userB": { "username": "bob@corp.test",   "password": "..." }
  },
  "selectors": {
    "ssoButton": ["Continue with Okta"],
    "userField": ["#username"]
  },
  "routes": ["/account", "/orders", "/settings"]
}
```

`*.recipe.json` is gitignored. Commit `recipe.example.json` instead.

---

## Flags

| Flag | Meaning |
|---|---|
| `--hunt` | One-command run: the whole pipeline |
| `--login URL` | Where to authenticate |
| `--user-a/--pass-a` `--user-b/--pass-b` | Two identities for the authorization matrix |
| `--recipe FILE` | Accounts, selectors, routes and headers from JSON |
| `--oauth` | Drive an IdP flow rather than a plain form |
| `--identity id=file` | Pre-captured traffic, skips login |
| `--scope HOST` | Declare program scope (repeatable) |
| `--domain D` | Enumerate subdomains of D rather than the given host |
| `--skip-subs` `--skip-takeover` `--skip-browser` `--skip-js` `--skip-change` | Turn off a phase |
| `--max-subs N` `--max-takeover N` `--max-browser-pages N` | Bound a phase |
| `--research-header 'N: V'` | Program-mandated header (repeatable) |
| `--ninja USER` | Bugcrowd's optional identifying header |
| `--throttle-per-min N` | Rate limit, for programs that require it |
| `--oob-poll-ms N` | How long to wait for out-of-band callbacks |
| `--oob-off` | Timing oracle only; no callback infrastructure |
| `--build-prior-art` | Index disclosed exploits from Exploit-DB + the CVE API |
| `--ask-prior-art tomcat:rce` | What has been exploited in the wild for this product/class |
| `--cves FILE` | CVE applicability with exclusion reasoning |
| `--prior-art FILE` | Duplicate vs novel-chain triage |
| `--sanitize FILE` | Redact evidence before submitting |
| `--diff-only` | What changed since the last run; sends no requests |
| `--phase list` | Run individual phases |

### Phases

`recon` `scan` `jslogic` `prioritise` `authz` `prove` `ingest` `correlate`
`queue` `gate` `report`

---

## Capabilities

| Capability | Status |
|---|---|
| Injection differentials (SQLi, XSS) | real, proven |
| Broken access control / IDOR | real; needs two identities |
| Sequential-ID enumeration | real, with blast-radius scaling |
| JavaScript analysis incl. minified | real; source maps fetched when published |
| Browser auto-click, form submit, injection | real; judged by side effect, not reflection |
| Subdomain enumeration | real, scope-gated before any request |
| Subdomain takeover, 26 fingerprints | real, read-only DNS + GET |
| Change detection across runs | real; reports what is new and what was untested |
| GraphQL introspection + resolver authz | real |
| JWT mutation | real |
| Cache poisoning | real |
| OAuth / OIDC / SSO login | real, recipe-driven |
| postMessage origin trust | real |
| MCP / AI-agent tool surface | real |
| Blind SSRF / command injection | real, via interactsh callbacks |
| Prior-art index (47k exploits) | real, public data |
| Evidence redaction + pre-submission audit | real |
| Remote shell / RCE / exploitation | **not present, by design** |
| CAPTCHA / MFA / passkey bypass | **not attempted**; detected and reported |

Challenges are detected and reported by name, never worked around. A stalled
login names the page it stopped on, so the fix is a selector change rather than
a guess.

---

## What it will not do

- **No exploitation or shell.** Probes only.
- **No CAPTCHA, MFA, or passkey bypass.** Detected, then reported.
- **No state-changing form submission.** Forms matching delete/pay/publish/
  transfer are recorded and never auto-submitted.
- **No out-of-scope requests.** Scope is enforced before any request is made.
- **No resource claiming.** Takeover checks are read-only. Claiming a resource is
  your deliberate decision.

---

## Output

Written to `state/<target>/`:

| File | Contents |
|---|---|
| `findings.json` | what survived the proof gate |
| `hunt.json` | phase-by-phase run log, including what changed |
| `coverage.json` | what was and was not tested |
| `leads.json` | everything found, proven or not |
| `snapshots/` | surface history for change detection |
| `captures/<id>.jsonl` | per-identity route replay |
| `evidence/*.sanitized.json` | redacted evidence, safe to submit |

`findings.json` is the contract consumed by the reporting chain. Coverage is
always stated. If the run was partial, the report says so rather than implying
the target is clean.

---

## Honesty rules

Enforced in code, not just documented:

1. **No claim without provenance.** Every finding cites the observation behind it.
2. **Refute before shipping.** Candidates are attacked; survivors are marked.
3. **Coverage is explicit.** Unmet thresholds report `INCOMPLETE`.
4. **One identity cannot prove authorization.** It says so instead of degrading
   into a guess.
5. **Discovery is not exercise.** Crawled paths count as *endpoints*, not
   *pages*. Conflating them would let the coverage gate pass on discovery alone.
6. **External dependency failure is not proof.** If a third-party OOB service
   rate-limits, that is reported as a miss, never as success.
7. **Untested surface is not a clean result.** Endpoints never probed are
   reported separately from endpoints that were tested and found fine.
8. **A live host is not a takeover.** Pointing at a CDN is normal configuration;
   only a de-provisioned resource is a finding.

---

## Tests

```bash
npm test
```

428 tests across 22 suites. Each corresponds to a real defect found and fixed
during development — parse-shape bugs, a closed browser context handed to a later
phase, a false blocker detector that rejected a reachable login, a timing oracle
that returned `p=1.000` on a genuine 96% gap, a takeover fingerprint that called
a live host vulnerable, and parameter discovery that reported zero on a target
full of injectable endpoints.

The suite includes a live out-of-band callback test that skips cleanly when the
public interactsh instance rate-limits, so it stays deterministic.

---

## Layout

```
src/cli.js           phases, flags, orchestration
src/hunt.js          the one-command pipeline
src/subdomains.js    enumeration + scope enforcement
src/takeover.js      26 service fingerprints, read-only
src/change.js        snapshot, diff, prioritise
src/headerpolicy.js  program-mandated headers, throttle, prohibited paths
src/identity.js      form login, two-step flows, storage state
src/oauth.js         IdP redirect chain, consent, honest blocking
src/jscapture.js     live JS capture, minified handling, source maps
src/browser.js       auto-click, auto-fill, auto-inject
src/prober.js        payload execution + evidence capture
src/validators.js    layered oracles + adversarial refutation
src/gate.js          proof gate -> findings.json
src/coverage.js      coverage ledger
src/suppress.js      suppressed vs filtered ledger
src/authmatrix.js    ownership-aware authorization matrix
src/authz-stage.js   dual-identity diffing
src/enumerate.js     sequential-ID enumeration
src/graphql.js       introspection + resolver authz
src/jwt.js           token mutation
src/cache.js         canary cache poisoning
src/mcp.js           MCP tool poisoning / config audit
src/postmessage.js   origin trust analysis
src/protocol-stage.js  graphql / jwt / cache / ato orchestration
src/jslogic.js       client-side auth logic
src/atoj.js          account-takeover chain assembly
src/oob.js           interactsh client + timing oracle
src/predict.js       param -> vulnerability class
src/knowledge.js     compounding target knowledge base
src/leads.js         lead store
src/normalize.js     tool output adapters
src/priorart.js      disclosed-exploit index
src/cvematch.js      CVE applicability with exclusion reasoning
src/duptriage.js     duplicate vs novel-chain
src/signal.js        side-channel confirmation discipline
src/evidence.js      redaction + pre-submission audit
src/capture-io.js    capture read/write
src/correlate.js     chain composition
src/oracle.js        browser XSS execution helpers

test/                22 suites, 428 tests
```

---

## Scope

Authorized testing only. Non-destructive. No exploitation, shell, persistence or
evasion capability, and none should be added without reassessing the threat
model. `POLICY.md` in the `pentest-harness` skill directory holds the full rules.
