#!/usr/bin/env python3
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "python"))
from pentharness_api import analyze
from pentharness_corpus import analyze as analyze_corpus, rows_from_text


class ApiAnalyzerTests(unittest.TestCase):
    def test_inventory_and_provenance(self):
        result = analyze({
            "openapi": "3.0.3",
            "info": {"title": "Accounts"},
            "paths": {"/users/{id}": {"get": {"operationId": "getUser"}}},
        })
        self.assertEqual(result["operations"][0]["id"], "getUser")
        self.assertEqual(result["findings"][0]["kind"], "schema-inconsistency")
        self.assertEqual(len(result["provenance"]["digest"]), 64)

    def test_explicit_anonymous_write_is_candidate_not_finding(self):
        result = analyze({
            "openapi": "3.0.3",
            "paths": {"/users": {"post": {"security": [], "requestBody": {"content": {}}}}},
        })
        self.assertEqual(result["findings"][0]["kind"], "authorization-review")
        self.assertEqual(result["findings"][0]["confidence"], "candidate")
        self.assertIn("proof_needed", result["findings"][0])

    def test_capture_differential_requires_identity_comparison(self):
        rows = list(rows_from_text(
            '{"method":"GET","url":"https://api.test/me","status":200,"body":"{\\"id\\":1}"}',
            "alice",
        )) + list(rows_from_text(
            '{"method":"GET","url":"https://api.test/me","status":200,"body":"{\\"id\\":2}"}',
            "bob",
        ))
        result = analyze_corpus(rows)
        self.assertEqual(result["comparisons"], 1)
        self.assertEqual(result["candidates"][0]["kind"], "identity-differential")
        self.assertEqual(result["candidates"][0]["confidence"], "candidate")

    def test_capture_differential_ignores_volatile_fields(self):
        rows = list(rows_from_text(
            '{"url":"https://api.test/ping","status":200,"body":"{\\"timestamp\\":1,\\"ok\\":true}"}',
            "alice",
        )) + list(rows_from_text(
            '{"url":"https://api.test/ping","status":200,"body":"{\\"timestamp\\":2,\\"ok\\":true}"}',
            "bob",
        ))
        self.assertEqual(analyze_corpus(rows)["candidates"], [])


if __name__ == "__main__":
    unittest.main()
