# pentharness

A deterministic harness for authorized penetration testing. It maps a target,
executes real probes, **proves or refutes every claim**, chains composable
weaknesses, and refuses to ship anything it cannot demonstrate.

The design principle is that **a lead is not a finding**. Most automated
pentesting produces volume; this produces a short list of things that survive
adversarial refutation, plus an honest statement of what was never tested.

> **Authorized targets only.** You must own the target or have written
> permission. Non-destructive by default: no destructive payloads, no data
> exfiltration, no persistence, no denial-of-service. See `POLICY.md`.

---

## Why this exists

Running a frontier model against their own codebase, HackerOne found that
*"a run that examined only part of a codebase can produce findings that look
just as complete as those from a run that covered all of it"* — so they built a
mechanism to fail runs that didn't review enough surface before reporting.

That failure mode is the whole problem. A partial scan that reads as complete is
worse than no scan, because it manufactures false confidence. This harness makes
coverage explicit and will not sign off a report it did not measure.

Three consequences show up in every design decision:

- **Provenance over probability.** A finding ships with the observation that
  produced it, and survives an adversarial re-test.
- **Refutation is mandatory.** Every candidate is attacked before it is trusted.
- **Silence is not safety.** `0 findings` and `did not test enough` are reported
  as different things, always.

---

## Install

```bash
git clone <your-fork-url> pentharness
cd pentharness

# Playwright provides the browser used for login, XSS confirmation and replay.
npm install playwright
npx playwright install chromium
```

Optional but recommended — `interactsh-client` enables real out-of-band
callbacks for blind SSRF and blind command injection. Without it the harness
falls back to a timing oracle that needs no external service.

```bash
# install from https://github.com/projectdiscovery/interactsh/releases
```

Link it onto your `PATH`:

```bash
ln -s "$PWD/src/cli.js" /usr/local/bin/pentharness
chmod +x src/cli.js
```

If Playwright lives outside this tree, point at it:

```bash
export PLAYWRIGHT_MODULE=/path/to/node_modules/playwright
```

---

## Use

The whole thing is one command. Target URL goes first.

```bash
pentharness https://target.tld --hunt
```

**Full run with two accounts** — this is what finds access-control bugs, the
highest-yield class by a wide margin:

```bash
pentharness https://target.tld --hunt \
  --login https://target.tld/login/ \
  --user-a 'alice@corp.test' --pass-a 'pw' \
  --user-b 'bob@corp.test'   --pass-b 'pw' \
  --oob-poll-ms 15000
```

**The same run without credentials in your shell history** — recommended:

```bash
cp recipe.example.json target.recipe.json
$EDITOR target.recipe.json          # fill in both accounts
chmod 600 target.recipe.json
pentharness https://target.tld --hunt --recipe ./target.recipe.json
```

`*.recipe.json` is gitignored. The example is not.

**Access control only**, when you already have captures:

```bash
pentharness https://target.tld --phase authz,correlate,queue \
  --identity userA=./cap-userA.jsonl --identity userB=./cap-userB.jsonl
```

---

## Commands

| Flag | Meaning |
|---|---|
| `--hunt` | One-command run: map → predict → execute → prove → chain → gate |
| `--login URL` | Where to authenticate |
| `--user-a/--pass-a` | First identity |
| `--user-b/--pass-b` | Second identity |
| `--recipe FILE` | Accounts + selectors + routes from JSON; use instead of password flags |
| `--oauth` | Drive an IdP flow rather than a plain form |
| `--identity id=file` | Pre-captured traffic, skips login |
| `--phase list` | Run phases individually (below) |
| `--from tool.json` | Ingest another tool's output |
| `--js PATH` | Local JS bundles for client-side auth-logic review |
| `--oob-poll-ms N` | How long to wait for out-of-band callbacks |
| `--oob-off` | Timing oracle only; no callback infrastructure |
| `--oob-server URL` | Use a specific interactsh server |
| `--concurrency N` | Parallel probes |
| `--skip-protocols` | Skip GraphQL/JWT/cache |
| `--max-pages N` | Cap crawl breadth |
| `--answer FILE` | LLM adjudication input for the queue |

### Phases

`recon` map with httpx/nuclei/katana/arjun → knowledge base ·
`scan` webfuzz + nuclei → leads ·
`prioritise` rank params by predicted class →
`authz` dual-identity diffing → the authorization matrix ·
`prove` validators + adversarial refutation ·
`correlate` candidate chains · `queue` bounded attention queue ·
`gate` proof gate + coverage gate → `findings.json` ·
`report` all of the above in order

---

## What it actually does

| Capability | Status |
|---|---|
| Injection differentials (SQLi, XSS) | real, proven against fixtures |
| Broken access control / IDOR | real, proven; needs 2 identities |
| Sequential-ID enumeration | real, with blast-radius scaling |
| GraphQL introspection + resolver authz | real |
| JWT mutation (alg confusion, `kid`, weak secret) | real |
| Cache poisoning | real |
| OAuth / OIDC / SSO login | real, recipe-driven |
| Blind SSRF / command injection | real, via interactsh callbacks |
| postMessage origin trust | real |
| MCP / AI-agent tool surface | real (static config audit + live `tools/list`) |
| Remote shell / RCE / exploitation | **not present, by design** |
| CAPTCHA / MFA / passkey bypass | **not attempted**; detected and reported |

It detects challenges and reports them by name rather than working around them.
A stalled login says which page stopped the flow, so the fix is a selector change
instead of a guess.

---

## Output

Written to `state/<target>/`:

| File | Contents |
|---|---|
| `findings.json` | what survived the proof gate |
| `coverage.json` | what was and was not tested |
| `leads.json` | everything found, proven or not |
| `hunt.json` | phase-by-phase run log |
| `captures/<id>.jsonl` | per-identity route replay |

`findings.json` is the contract consumed by the reporting chain. Coverage is
always stated. If the run was partial, the report says so rather than
implying the target is clean.

---

## Honesty rules

These are enforced in code, not just documented:

1. **No claim without provenance.** Every finding cites the observation behind it.
2. **Refute before shipping.** Candidates are attacked; survivors are marked.
3. **Coverage is explicit.** `minPages`, `minEndpoints`, `minIdentities` must be
   met or the run reports `INCOMPLETE`.
4. **One identity cannot prove authorization.** It reports that instead of
   degrading into a guess.
5. **Discovery is not exercise.** Crawler-discovered paths count as *endpoints*,
   not *pages*. Conflating them would let the coverage gate pass on discovery
   alone.
6. **External dependency failure is not proof.** If a third-party OOB service
   rate-limits, the harness reports the miss instead of claiming success.

---

## Tests

```bash
npm test          # 251 tests
node test/oauth-oob.js
```

Each test corresponds to a real defect found and fixed during development —
parse-shape bugs, regex gaps, closed-context errors, false blockers, and a timing
oracle that returned `p=1.000` on a genuine 96% gap. The suite includes a live
out-of-band callback test that skips cleanly when the public interactsh instance
rate-limits, so it stays deterministic.

---

## Layout

```
src/cli.js          phases, flags, orchestration
src/hunt.js         the one-command pipeline
src/leads.js        lead store
src/normalize.js    tool output adapters
src/knowledge.js    compounding target knowledge base
src/predict.js      param -> vulnerability class
src/prober.js       payload execution + evidence capture
src/validators.js   layered oracles + adversarial refutation
src/gate.js         proof gate, severity, findings.json
src/coverage.js     coverage ledger
src/suppress.js     suppressed vs filtered ledger
src/authmatrix.js   ownership-aware authorization matrix
src/identity.js     form login, storage state, replay
src/oauth.js        IdP redirect chain, consent, honest blocking
src/enumerate.js    sequential-ID enumeration
src/graphql.js      introspection + resolver authz
src/jwt.js          token mutation
src/cache.js        canary cache poisoning
src/mcp.js          MCP tool poisoning / config audit
src/postmessage.js  origin trust analysis
src/jslogic.js      client-side auth logic
src/atoj.js         account-takeover chain assembly
src/oob.js          interactsh client + timing oracle
test/               8 suites, 251 tests
```

---

## Scope

Authorized testing only. Non-destructive. It will detect CAPTCHA, MFA and
WebAuthn and will stop rather than bypass them. It contains no exploitation,
shell, persistence or evasion capability, and none should be added without
reassessing the threat model.

`POLICY.md` in the `pentest-harness` skill directory holds the full rules.
