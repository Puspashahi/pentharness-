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
tenant      multi-tenant relationship and cross-boundary authorization hypotheses
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
| `--tenant-model FILE` | JSON relationship records for the multi-tenant graph |
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

`recon` `scan` `jslogic` `secrets` `tenant` `prioritise` `authz` `prove`
`ingest` `correlate` `queue` `gate` `report`

---

## Capabilities

| Capability | Status |
|---|---|
| Injection differentials (SQLi, XSS) | real, proven |
| Broken access control / IDOR | real; needs two identities |
| Multi-tenant relationship graph | real; candidate generation with contradiction tracking |
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
9. **One differential is not proof.** Injection timing and boolean-response
   findings require repeated, stable control and probe samples; transient
   latency or dynamic response lengths remain hypotheses/refutations.
10. **Secret regex matches are leads, not leaks.** Values are never stored in
    findings; placeholders and low-entropy generic assignments are filtered,
    and live validation remains required.

## P0 stateful testing

`src/workflow.js` models observed application workflows and generates bounded
skip, reorder, duplicate, and replay mutations. `src/race.js` measures
concurrent response outcomes, duplicate acceptance, idempotency-key presence,
and optional before/after state snapshots. State-changing race tests require
explicit `allowStateChange: true`; both modules produce hypotheses, not
automatic findings.

The next stateful primitives are `src/differential.js` for semantic response
comparisons, `src/api-sequence.js` for OpenAPI lifecycle planning, and
`src/auth-lifecycle.js` for session fixation, logout invalidation, and refresh
token observations. Their network execution remains caller-controlled so MFA,
CAPTCHA, recovery, and other controls are never bypassed automatically.

Modern protocol coverage now includes `src/websocket.js` for WebSocket message
handler/origin/authorization surface analysis and `src/grpc.js` for lightweight
`.proto` service, streaming RPC, sensitive-method, and auth-metadata analysis.
These are static planning signals until authorized replay confirms behavior.

## Bash automation

Use `scripts/pentharness.sh local-scan PATH` for a bounded, local-only scan
combining secret detection, JavaScript authorization analysis, and gRPC
`.proto` analysis. Use `scripts/pentharness.sh secrets PATH` for the focused
redaction-safe scanner. The `hunt` subcommand is the only wrapper path that
delegates to network testing, and it still requires an explicit target and
the harness safety controls.

Local scans default to a human-readable report with `CONFIRMED`, `CANDIDATE`,
and `REVIEW` labels, the reason for each signal, and the next proof step.
Use `PENTHARNESS_JSON=1` for machine-readable JSON. Static matches are never
described as confirmed vulnerabilities.

The Bash wrapper also exposes the tenant phase:

```bash
scripts/pentharness.sh tenant https://target.test \
  --model ./tenant-records.json \
  --identity alice=./alice.jsonl \
  --identity bob=./bob.jsonl
```

Recon limits can be set with `--max-targets N`, `--timeout-ms N`, and
`--workdir PATH`; all remain scope-gated.

## Metamorphic testing

Metamorphic cases test an explicit behavioral relation when no single expected
response is available. Cases require repeated stable samples and produce
candidates or holds, never automatic findings:

```bash
scripts/pentharness.sh metamorphic https://target.test --cases ./cases.json
```

Supported relations include `presentation-invariance`,
`read-order-invariance`, `permission-revocation`, and
`logout-invalidation`. A case file is either an array or `{ "cases": [...] }`.
Each side should contain at least two equivalent observations:

```json
{
  "cases": [{
    "id": "logout-check",
    "relation": "logout-invalidation",
    "before": [
      { "status": 200, "body": "{\"id\":\"owned\"}" },
      { "status": 200, "body": "{\"id\":\"owned\"}" }
    ],
    "after": [
      { "status": 401, "body": "signed out" },
      { "status": 401, "body": "signed out" }
    ]
  }]
}
```

The CLI writes `metamorphic.json` under the target state directory and feeds
violations into the normal business-logic lead queue.

## OpenAPI planning

Generate a bounded, read-first API plan without sending requests:

```bash
scripts/pentharness.sh openapi https://target.test --spec ./openapi.json
# or: pentharness https://target.test --phase openapi --openapi ./openapi.json
```

The plan writes `state/<target>/openapi-plan.json`, including request templates,
parameter examples, lifecycle sequences, destructive-operation warnings, and a
SHA-256 provenance fingerprint of the source specification. Read-only sequences
are marked replay-safe; state-changing and delete operations require explicit
approval and are never executed by this phase.

## Python companion

Node.js remains the browser and orchestration layer. A dependency-free Python
companion performs passive API-schema analysis:

```bash
scripts/pentharness.sh python-api ./openapi.json
python3 test/python_api.py
```

It inventories operations, reports schema inconsistencies and explicitly
anonymous state-changing routes as candidates, and attaches a SHA-256 source
fingerprint. It never makes network requests or promotes schema observations
to findings without runtime proof.

## Multi-tenant relationship modeling

The `tenant` phase models users, tenants, projects, resources, roles,
invitations, and shares from a researcher-supplied JSON record set:

```bash
node src/cli.js https://target.test --phase tenant --tenant-model ./tenant-records.json
```

It writes `tenant-graph.json`, identifies cross-tenant access hypotheses, and
tracks contradictory access observations. These remain authorization leads until
the same request is reproduced with a foreign-tenant identity and the response
is proven to contain protected data. The model accepts either an array of
records or `{ "records": [...] }`.

For runtime proof, provide captures for the modeled identities:

```bash
node src/cli.js https://target.test \
  --phase tenant \
  --tenant-model ./tenant-records.json \
  --identity alice=./alice.jsonl \
  --identity bob=./bob.jsonl
```

The phase compares identical requests, requires successful responses from both
identities, and requires owner markers in the foreign response. Explicit share
edges are skipped as permitted access. Runtime evidence is still emitted as an
authorization lead for the central proof gate; it is never promoted directly
to a finding.

## Scope-aware recon pipeline

`scripts/pentharness.sh recon example.com --scope example.com` optionally
chains `subfinder`, `uncover`, `dnsx`, `httpx`, `katana`, and `nuclei` when
installed. It requires an explicit matching scope, skips unavailable tools,
keeps outputs in a bounded working directory, and labels all scanner output as
recon evidence/leads rather than confirmed vulnerabilities.

Unavailable recon tools are reported as skipped rather than treated as clean
results, and structured output is filtered for out-of-scope hosts before it is
passed to later stages.

---

## Tests

```bash
npm test
```

The offline suite is discovered automatically from `test/`, so new regression
suites do not require a runner edit. Browser suites are skipped with an explicit
message when Playwright is not installed; online suites remain opt-in with
`npm run test:online`. Each test corresponds to a real defect or safety
invariant, including parse-shape bugs, closed browser contexts, false login
blockers, unstable timing oracles, takeover false positives, and parameter
discovery misses.

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
src/tenant-graph.js  multi-tenant relationship graph and proof hypotheses
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
src/recon-pipeline.js optional scope-aware recon toolchain
src/secrets.js       redaction-safe secret detection
src/workflow.js      stateful workflow mutation planning
src/race.js          bounded race-condition analysis
src/differential.js  semantic response comparison
src/api-sequence.js  OpenAPI lifecycle sequence planning
src/auth-lifecycle.js session lifecycle observations
src/websocket.js     WebSocket surface analysis
src/grpc.js          gRPC/protobuf contract analysis
src/pretty-report.js human-readable confidence/proof output
src/metamorphic.js   stable behavioral-relation evaluator
src/openapi.js       OpenAPI request and lifecycle planner
python/pentharness_api.py  dependency-free Python API analyzer

test/                deterministic regression suites, plus optional browser and
                     online suites, including OpenAPI, metamorphic, and tenant proof tests
```

---

## Scope

Authorized testing only. Non-destructive. No exploitation, shell, persistence or
evasion capability, and none should be added without reassessing the threat
model. `POLICY.md` in the `pentest-harness` skill directory holds the full rules.
