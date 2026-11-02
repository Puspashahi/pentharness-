#!/usr/bin/env python3
"""Dependency-free API schema analysis for pentharness.

This module is intentionally passive: it reads OpenAPI JSON/YAML-shaped data
already supplied by the operator and emits bounded candidates, never findings.
"""
from __future__ import annotations

import hashlib
import json
import sys
from typing import Any, Dict, Iterable, List


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}


def load_document(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        return json.loads(value)
    raise ValueError("expected an OpenAPI JSON object or JSON string")


def operations(document: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    for path, item in (document.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            yield {
                "id": operation.get("operationId") or f"{method.upper()} {path}",
                "method": method.upper(),
                "path": path,
                "operation": operation,
                "parameters": list(item.get("parameters") or []) + list(operation.get("parameters") or []),
            }


def _security(document: Dict[str, Any], operation: Dict[str, Any]) -> Any:
    return operation.get("security", document.get("security"))


def analyze(value: Any) -> Dict[str, Any]:
    document = load_document(value)
    findings: List[Dict[str, Any]] = []
    inventory: List[Dict[str, Any]] = []
    global_security = document.get("security")

    for item in operations(document):
        op = item["operation"]
        method = item["method"]
        parameters = item["parameters"]
        path_names = {part[1:-1] for part in item["path"].split("/") if part.startswith("{") and part.endswith("}")}
        declared_path = {p.get("name") for p in parameters if isinstance(p, dict) and p.get("in") == "path"}
        missing_path = sorted(path_names - declared_path)
        security = _security(document, op)
        entry = {
            "id": item["id"],
            "method": method,
            "path": item["path"],
            "stateChanging": method not in {"GET", "HEAD", "OPTIONS"},
            "securityDeclared": security is not None,
            "parameterCount": len(parameters),
        }
        inventory.append(entry)

        if missing_path:
            findings.append({
                "kind": "schema-inconsistency",
                "confidence": "candidate",
                "operation": item["id"],
                "path": item["path"],
                "reason": "path template variables are not declared as path parameters",
                "details": {"missing": missing_path},
                "proof_needed": ["confirm the live route and generated client behavior"],
            })
        if method in {"POST", "PUT", "PATCH", "DELETE"} and security == []:
            findings.append({
                "kind": "authorization-review",
                "confidence": "candidate",
                "operation": item["id"],
                "path": item["path"],
                "reason": "state-changing operation explicitly declares anonymous access",
                "details": {"security": []},
                "proof_needed": ["replay with an unauthenticated session and verify intended public behavior"],
            })
        if method in {"POST", "PUT", "PATCH"} and not op.get("requestBody"):
            findings.append({
                "kind": "schema-review",
                "confidence": "candidate",
                "operation": item["id"],
                "path": item["path"],
                "reason": "state-changing operation has no documented request body",
                "details": {},
                "proof_needed": ["capture the live request before treating undocumented input as a defect"],
            })

    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return {
        "schemaVersion": 1,
        "tool": "pentharness-python-api",
        "format": document.get("openapi") or document.get("swagger") or "unknown",
        "title": (document.get("info") or {}).get("title"),
        "safety": "passive schema analysis; no network requests; candidates require runtime proof",
        "operations": inventory,
        "findings": findings,
        "provenance": {"algorithm": "sha256", "digest": hashlib.sha256(canonical).hexdigest()},
    }


def main(argv: List[str]) -> int:
    if len(argv) > 2 or (len(argv) == 2 and argv[1] not in {"-", "--json"}):
        print("usage: pentharness_api.py [--json|-]", file=sys.stderr)
        return 2
    raw = sys.stdin.read() if len(argv) == 1 or argv[1] == "-" else sys.stdin.read()
    try:
        result = analyze(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"pentharness-python-api: invalid JSON: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
