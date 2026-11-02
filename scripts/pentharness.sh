#!/usr/bin/env bash
set -euo pipefail

# Safe local orchestrator. Network activity is delegated to the explicit
# `hunt` command; local analysis commands never contact targets.
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_BIN="${NODE_BIN:-node}"
TARGET="${2:-.}"
OUT="${PENTHARNESS_OUT:-}"
JSON_MODE="${PENTHARNESS_JSON:-0}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/pentharness.sh local-scan PATH [OUT.json]
  scripts/pentharness.sh secrets PATH
  scripts/pentharness.sh jslogic PATH
  scripts/pentharness.sh grpc PATH
  scripts/pentharness.sh tenant TARGET --model FILE --identity id=FILE [--identity id=FILE]
  scripts/pentharness.sh metamorphic TARGET --cases FILE
  scripts/pentharness.sh openapi TARGET --spec FILE
  scripts/pentharness.sh python-api SPEC
  scripts/pentharness.sh python-corpus CAPTURE.jsonl [CAPTURE.jsonl ...]
  scripts/pentharness.sh hunt https://target.tld [extra pentharness args...]

Commands:
  local-scan  Run secrets, JavaScript logic, and .proto analysis locally.
  secrets     Run the redaction-safe secret scanner.
  jslogic     Run client-side authorization analysis through the CLI.
  grpc        Analyze .proto files without making network requests.
  tenant      Build and optionally prove a multi-tenant model from captures.
  metamorphic Evaluate explicit behavioral relations from observed JSON.
  openapi     Build safe, provenance-hashed API plans from an OpenAPI JSON file.
  python-api  Analyze an OpenAPI JSON document with the Python companion.
  python-corpus Compare captured API responses across identities.
  recon       Run an optional scope-aware recon toolchain (requires --scope).
  hunt        Delegate an explicitly requested authorized hunt to the CLI.

Environment:
  PENTHARNESS_MAX_FILES / PENTHARNESS_MAX_BYTES bound local scanning.
  PENTHARNESS_OUT sets the output file for local-scan.
  PENTHARNESS_JSON=1 emits machine-readable JSON instead of the human report.
USAGE
}

die() {
  printf 'pentharness: %s\n' "$*" >&2
  exit 2
}

[[ $# -ge 1 ]] || { usage; exit 2; }
COMMAND="$1"
cd "$ROOT"

case "$COMMAND" in
  secrets)
    [[ -e "$TARGET" ]] || die "path does not exist: $TARGET"
    exec "$ROOT/scripts/pentharness-secrets.sh" "$TARGET"
    ;;
  jslogic)
    [[ -e "$TARGET" ]] || die "path does not exist: $TARGET"
    exec "$NODE_BIN" "$ROOT/src/cli.js" placeholder.invalid --phase jslogic --js "$TARGET"
    ;;
  grpc)
    [[ -e "$TARGET" ]] || die "path does not exist: $TARGET"
    TARGET="$TARGET" MAX_FILES="${PENTHARNESS_MAX_FILES:-1000}" MAX_BYTES="${PENTHARNESS_MAX_BYTES:-4194304}" \
      "$NODE_BIN" - <<'NODE'
const fs = require('fs');
const path = require('path');
const G = require('./src/grpc');
const P = require('./src/pretty-report');
const maxFiles = Number(process.env.MAX_FILES);
const maxBytes = Number(process.env.MAX_BYTES);
const root = path.resolve(process.env.TARGET);
const files = [];
function walk(p, depth = 0) {
  if (files.length >= maxFiles || depth > 6) return;
  let st;
  try { st = fs.statSync(p); } catch { return; }
  if (st.isFile()) {
    if (st.size <= maxBytes && /\.proto$/i.test(p)) files.push(p);
    return;
  }
  if (!st.isDirectory() || /(?:^|[/\\])(?:\.git|node_modules|vendor|dist|build)(?:[/\\]|$)/.test(p)) return;
  for (const e of fs.readdirSync(p, { withFileTypes: true })) walk(path.join(p, e.name), depth + 1);
}
walk(root);
const results = files.map((file) => {
  const analysis = G.analyze(fs.readFileSync(file, 'utf8'), { source: file, path: file });
  return { file, services: analysis.services, findings: analysis.findings };
});
process.stdout.write(JSON.stringify({ tool: 'pentharness-grpc', files: results.length, results }, null, 2) + '\n');
NODE
    ;;
  local-scan)
    [[ -e "$TARGET" ]] || die "path does not exist: $TARGET"
    OUT="${3:-$OUT}"
    TARGET="$TARGET" OUT="${OUT:-}" JSON_MODE="$JSON_MODE" MAX_FILES="${PENTHARNESS_MAX_FILES:-1000}" MAX_BYTES="${PENTHARNESS_MAX_BYTES:-4194304}" \
      "$NODE_BIN" - <<'NODE'
const fs = require('fs');
const path = require('path');
const S = require('./src/secrets');
const W = require('./src/jslogic');
const G = require('./src/grpc');
const P = require('./src/pretty-report');
const target = path.resolve(process.env.TARGET);
const secrets = S.scanPath(target, { maxFiles: Number(process.env.MAX_FILES), maxBytes: Number(process.env.MAX_BYTES) });
const js = W.scanPath(target);
const files = S.walkFiles(target, { maxFiles: Number(process.env.MAX_FILES), maxBytes: Number(process.env.MAX_BYTES) })
  .filter((f) => /\.proto$/i.test(f));
const grpc = files.map((file) => ({ file, ...G.analyze(fs.readFileSync(file, 'utf8'), { path: file }) }));
const report = {
  tool: 'pentharness-local-scan',
  target,
  safety: 'local-only; no network requests; values redacted',
  secrets: { files: secrets.files, findings: secrets.findings },
  javascript: { files: js.files, leads: js.leads },
  grpc: { files: grpc.length, results: grpc.map((r) => ({ file: r.file, services: r.services, findings: r.findings })) },
};
const text = JSON.stringify(report, null, 2) + '\n';
if (process.env.OUT) fs.writeFileSync(path.resolve(process.env.OUT), text, { mode: 0o600 });
if (process.env.JSON_MODE === '1') process.stdout.write(text);
else process.stdout.write(P.renderLocal(report));
NODE
    ;;
  hunt)
    [[ -n "${2:-}" ]] || die "hunt requires a target URL"
    shift 2
    exec "$NODE_BIN" "$ROOT/src/cli.js" "$TARGET" --hunt "$@"
    ;;
  recon)
    [[ -n "${2:-}" ]] || die "recon requires a root domain"
    shift 2
    SCOPE=""
    MAX_TARGETS=""
    TIMEOUT_MS=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --scope) [[ -n "${2:-}" ]] || die "--scope requires a domain"; SCOPE="$2"; shift 2 ;;
        --workdir) [[ -n "${2:-}" ]] || die "--workdir requires a path"; WORKDIR="$2"; shift 2 ;;
        --max-targets) [[ -n "${2:-}" ]] || die "--max-targets requires a number"; MAX_TARGETS="$2"; shift 2 ;;
        --timeout-ms) [[ -n "${2:-}" ]] || die "--timeout-ms requires a number"; TIMEOUT_MS="$2"; shift 2 ;;
        *) die "unknown recon option '$1'" ;;
      esac
    done
    [[ -n "$SCOPE" ]] || die "recon requires explicit --scope"
    TARGET="$TARGET" SCOPE="$SCOPE" WORKDIR="${WORKDIR:-}" MAX_TARGETS="${MAX_TARGETS:-}" TIMEOUT_MS="${TIMEOUT_MS:-}" \
      "$NODE_BIN" - <<'NODE'
const R = require('./src/recon-pipeline');
(async () => {
    const opts = {
      ...(process.env.WORKDIR ? { workdir: process.env.WORKDIR } : {}),
      ...(process.env.MAX_TARGETS ? { maxTargets: Number(process.env.MAX_TARGETS) } : {}),
      ...(process.env.TIMEOUT_MS ? { timeoutMs: Number(process.env.TIMEOUT_MS) } : {}),
    };
  const result = await R.run(process.env.TARGET, [process.env.SCOPE], opts);
  process.stdout.write(JSON.stringify({
    tool: 'pentharness-recon',
    policy: 'scope-filtered; scanner matches are recon leads only',
    ...result,
  }, null, 2) + '\n');
  if (!result.ok) process.exitCode = 2;
})();
NODE
    ;;
  tenant)
    [[ -n "${2:-}" ]] || die "tenant requires a target URL"
    shift 2
    MODEL=""
    ARGS=()
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --model) [[ -n "${2:-}" ]] || die "--model requires a JSON file"; MODEL="$2"; shift 2 ;;
        --identity) [[ -n "${2:-}" ]] || die "--identity requires id=file"; ARGS+=(--identity "$2"); shift 2 ;;
        *) die "unknown tenant option '$1'" ;;
      esac
    done
    [[ -n "$MODEL" ]] || die "tenant requires --model FILE"
    [[ -e "$MODEL" ]] || die "tenant model does not exist: $MODEL"
    exec "$NODE_BIN" "$ROOT/src/cli.js" "$TARGET" --phase tenant --tenant-model "$MODEL" "${ARGS[@]}"
    ;;
  metamorphic)
    [[ -n "${2:-}" ]] || die "metamorphic requires a target URL"
    shift 2
    CASES=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --cases) [[ -n "${2:-}" ]] || die "--cases requires a JSON file"; CASES="$2"; shift 2 ;;
        *) die "unknown metamorphic option '$1'" ;;
      esac
    done
    [[ -n "$CASES" ]] || die "metamorphic requires --cases FILE"
    [[ -e "$CASES" ]] || die "metamorphic cases do not exist: $CASES"
    exec "$NODE_BIN" "$ROOT/src/cli.js" "$TARGET" --phase metamorphic --metamorphic "$CASES"
    ;;
  openapi)
    [[ -n "${2:-}" ]] || die "openapi requires a target URL"
    shift 2
    SPEC=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --spec) [[ -n "${2:-}" ]] || die "--spec requires a JSON file"; SPEC="$2"; shift 2 ;;
        *) die "unknown openapi option '$1'" ;;
      esac
    done
    [[ -n "$SPEC" ]] || die "openapi requires --spec FILE"
    [[ -e "$SPEC" ]] || die "OpenAPI spec does not exist: $SPEC"
    exec "$NODE_BIN" "$ROOT/src/cli.js" "$TARGET" --phase openapi --openapi "$SPEC"
    ;;
  python-api)
    [[ -n "${2:-}" ]] || die "python-api requires an OpenAPI JSON file"
    command -v "${PYTHON_BIN:-python3}" >/dev/null 2>&1 || die "python3 is required for python-api"
    [[ -e "$2" ]] || die "OpenAPI JSON does not exist: $2"
    exec "${PYTHON_BIN:-python3}" "$ROOT/python/pentharness_api.py" --json < "$2"
    ;;
  python-corpus)
    [[ $# -ge 2 ]] || die "python-corpus requires at least one JSONL capture"
    command -v "${PYTHON_BIN:-python3}" >/dev/null 2>&1 || die "python3 is required for python-corpus"
    for capture in "${@:2}"; do [[ -e "$capture" ]] || die "capture does not exist: $capture"; done
    exec "${PYTHON_BIN:-python3}" "$ROOT/python/pentharness_corpus.py" "${@:2}"
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    die "unknown command '$COMMAND' (use help)"
    ;;
esac
