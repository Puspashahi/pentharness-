#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

printf 'ghp_abcdefghijklmnopqrstuvwxyz01\napi_key="changeme"\n' > "$TMP/app.js"
cat > "$TMP/service.proto" <<'PROTO'
service Admin { rpc DeleteUser (DeleteRequest) returns (Reply); }
PROTO
printf '%s\n' '[{"userId":"alice","tenantId":"org-a","resourceId":"invoice-a","owner":true},{"userId":"bob","tenantId":"org-b","resourceId":"invoice-a"}]' > "$TMP/tenant.json"
printf '%s\n' '{"cases":[{"id":"logout","relation":"logout-invalidation","before":[{"status":200,"body":"{\"id\":\"x\"}"},{"status":200,"body":"{\"id\":\"x\"}"}],"after":[{"status":200,"body":"{\"id\":\"x\"}"},{"status":200,"body":"{\"id\":\"x\"}"}]}]}' > "$TMP/metamorphic.json"
printf '%s\n' '{"openapi":"3.0.3","paths":{"/health":{"get":{"operationId":"health"}}}}' > "$TMP/openapi.json"

chmod +x "$ROOT/scripts/pentharness.sh" "$ROOT/scripts/pentharness-secrets.sh"
output="$(PENTHARNESS_JSON=1 "$ROOT/scripts/pentharness.sh" local-scan "$TMP")"
grep -q '"tool": "pentharness-local-scan"' <<<"$output"
grep -q '"github-token"' <<<"$output"
! grep -q 'abcdefghijklmnopqrstuvwxyz01' <<<"$output"
grep -q '"DeleteUser"' <<<"$output"

tenant_output="$("$ROOT/scripts/pentharness.sh" tenant https://target.test --model "$TMP/tenant.json")"
grep -q 'tenant:' <<<"$tenant_output"
grep -q 'hypothesis' <<<"$tenant_output"

metamorphic_output="$("$ROOT/scripts/pentharness.sh" metamorphic https://target.test --cases "$TMP/metamorphic.json")"
grep -q 'metamorphic:' <<<"$metamorphic_output"

openapi_output="$("$ROOT/scripts/pentharness.sh" openapi https://target.test --spec "$TMP/openapi.json")"
grep -q 'openapi:' <<<"$openapi_output"

python_api_output="$("$ROOT/scripts/pentharness.sh" python-api "$TMP/openapi.json")"
grep -q 'pentharness-python-api' <<<"$python_api_output"

printf '%s\n' '{"url":"https://target.test/me","status":200,"body":"{\"id\":1}"}' > "$TMP/alice.jsonl"
printf '%s\n' '{"url":"https://target.test/me","status":200,"body":"{\"id\":2}"}' > "$TMP/bob.jsonl"
python_corpus_output="$("$ROOT/scripts/pentharness.sh" python-corpus "$TMP/alice.jsonl" "$TMP/bob.jsonl")"
grep -q 'pentharness-python-corpus' <<<"$python_corpus_output"

go_evidence_output="$("$ROOT/scripts/pentharness.sh" go-evidence "$TMP/alice.jsonl" "$TMP/bob.jsonl")"
grep -q 'pentharness-go-evidence' <<<"$go_evidence_output"
grep -q '"duplicateEvidence": 0' <<<"$go_evidence_output"
printf '%s\n' "$go_evidence_output" > "$TMP/go-report.json"
contract_output="$("$ROOT/scripts/pentharness.sh" contract "$TMP/go-report.json")"
grep -q '"valid": \[\]' <<<"$contract_output"

replay_output="$("$ROOT/scripts/pentharness.sh" replay https://target.test --capture alice="$TMP/alice.jsonl" --scope target.test)"
grep -q 'pentharness-replay-plan' <<<"$replay_output"

secret_output="$("$ROOT/scripts/pentharness.sh" secrets "$TMP/app.js")"
grep -q '"github-token"' <<<"$secret_output"
! grep -q 'abcdefghijklmnopqrstuvwxyz01' <<<"$secret_output"

printf 'bash wrapper: ok\n'
