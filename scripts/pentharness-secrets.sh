#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-.}"
MAX_FILES="${PENTHARNESS_MAX_FILES:-1000}"
MAX_BYTES="${PENTHARNESS_MAX_BYTES:-4194304}"

if [[ ! -e "$TARGET" ]]; then
  printf 'target does not exist: %s\n' "$TARGET" >&2
  exit 2
fi

TARGET="$(realpath "$TARGET")"
cd "$ROOT"
TARGET="$TARGET" MAX_FILES="$MAX_FILES" MAX_BYTES="$MAX_BYTES" \
  node - <<'NODE'
const secrets = require('./src/secrets');
const result = secrets.scanPath(process.env.TARGET, {
  maxFiles: Number(process.env.MAX_FILES),
  maxBytes: Number(process.env.MAX_BYTES),
});
process.stdout.write(JSON.stringify({
  tool: 'pentharness-secret-scan',
  files: result.files,
  findings: result.findings,
}, null, 2) + '\n');
NODE
