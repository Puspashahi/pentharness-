#!/usr/bin/env python3
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "python"))
from pentharness_api import analyze


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


if __name__ == "__main__":
    unittest.main()
