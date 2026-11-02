#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

printf 'ghp_abcdefghijklmnopqrstuvwxyz01\napi_key="changeme"\n' > "$TMP/app.js"
cat > "$TMP/service.proto" <<'PROTO'
service Admin { rpc DeleteUser (DeleteRequest) returns (Reply); }
PROTO

chmod +x "$ROOT/scripts/pentharness.sh" "$ROOT/scripts/pentharness-secrets.sh"
output="$(PENTHARNESS_JSON=1 "$ROOT/scripts/pentharness.sh" local-scan "$TMP")"
grep -q '"tool": "pentharness-local-scan"' <<<"$output"
grep -q '"github-token"' <<<"$output"
! grep -q 'abcdefghijklmnopqrstuvwxyz01' <<<"$output"
grep -q '"DeleteUser"' <<<"$output"

secret_output="$("$ROOT/scripts/pentharness.sh" secrets "$TMP/app.js")"
grep -q '"github-token"' <<<"$secret_output"
! grep -q 'abcdefghijklmnopqrstuvwxyz01' <<<"$secret_output"

printf 'bash wrapper: ok\n'
