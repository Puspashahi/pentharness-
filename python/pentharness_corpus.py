#!/usr/bin/env python3
"""Passive differential analysis for captured API responses."""
from __future__ import annotations

import hashlib
import json
import sys
from collections import defaultdict
from typing import Any, Dict, Iterable, List


def rows_from_text(text: str, identity: str) -> Iterable[Dict[str, Any]]:
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict) or not row.get("url"):
            continue
        row = dict(row)
        row.setdefault("identity", identity)
        row["_line"] = line_no
        yield row


def _json_body(body: Any) -> Any:
    if not isinstance(body, str):
        return body
    try:
        return json.loads(body)
    except (TypeError, json.JSONDecodeError):
        return body


def semantic_body(body: Any) -> Any:
    value = _json_body(body)
    if isinstance(value, dict):
        return {k: semantic_body(v) for k, v in sorted(value.items()) if k.lower() not in {"timestamp", "updatedat", "requestid", "traceid"}}
    if isinstance(value, list):
        return [semantic_body(v) for v in value]
    return value


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def analyze(rows: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    usable = 0
    for row in rows:
        if not row.get("url"):
            continue
        usable += 1
        key = f"{str(row.get('method', 'GET')).upper()} {row['url']}"
        normalized = dict(row)
        normalized["semanticBody"] = semantic_body(row.get("body", ""))
        normalized["bodyDigest"] = _digest(normalized["semanticBody"])
        grouped[key].append(normalized)

    candidates = []
    comparisons = 0
    for request, observations in grouped.items():
        by_identity: Dict[str, Dict[str, Any]] = {}
        for observation in observations:
            by_identity.setdefault(str(observation.get("identity", "unknown")), observation)
        identities = sorted(by_identity)
        for index, left_id in enumerate(identities):
            for right_id in identities[index + 1:]:
                left, right = by_identity[left_id], by_identity[right_id]
                comparisons += 1
                status_differs = left.get("status") != right.get("status")
                body_differs = left.get("bodyDigest") != right.get("bodyDigest")
                if not status_differs and not body_differs:
                    continue
                candidates.append({
                    "kind": "identity-differential",
                    "confidence": "candidate",
                    "request": request,
                    "identities": [left_id, right_id],
                    "differences": {
                        "status": status_differs,
                        "semanticBody": body_differs,
                    },
                    "observations": [
                        {"identity": left_id, "status": left.get("status"), "bodyDigest": left["bodyDigest"], "line": left["_line"]},
                        {"identity": right_id, "status": right.get("status"), "bodyDigest": right["bodyDigest"], "line": right["_line"]},
                    ],
                    "reason": "the same request produced identity-dependent behavior",
                    "proof_needed": [
                        "replay the exact request with both identities",
                        "confirm the divergence is not an intended role or ownership distinction",
                        "compare sanitized bodies and ownership markers",
                    ],
                })

    return {
        "schemaVersion": 1,
        "tool": "pentharness-python-corpus",
        "safety": "passive capture analysis; no network requests; differences are candidates only",
        "rows": usable,
        "requestGroups": len(grouped),
        "comparisons": comparisons,
        "candidates": candidates,
    }


def main(argv: List[str]) -> int:
    if len(argv) < 2:
        print("usage: pentharness_corpus.py CAPTURE.jsonl [CAPTURE.jsonl ...]", file=sys.stderr)
        return 2
    rows = []
    for filename in argv[1:]:
        try:
            with open(filename, encoding="utf-8") as handle:
                rows.extend(rows_from_text(handle.read(), filename))
        except OSError as exc:
            print(f"pentharness-python-corpus: {exc}", file=sys.stderr)
            return 2
    print(json.dumps(analyze(rows), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
