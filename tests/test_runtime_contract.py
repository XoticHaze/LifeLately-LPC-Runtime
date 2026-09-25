import json
import unittest
from pathlib import Path

from scripts.runtime_contract_check import load, validate

class RuntimeContractTests(unittest.TestCase):
    def test_registry_and_smoke_manifest_pass(self):
        receipt = validate(
            load("runtime/capabilities.v1.json"),
            load("fixtures/runtime_smoke.v1.json"),
        )
        self.assertEqual("PASS", receipt["result"])
        self.assertEqual(13, receipt["capability_count"])
        self.assertEqual(6, receipt["probe_count"])

    def test_public_smoke_manifest_is_synthetic(self):
        smoke = json.loads(Path("fixtures/runtime_smoke.v1.json").read_text())
        self.assertEqual("SYNTHETIC_NON_PHI", smoke["data_class"])

if __name__ == "__main__":
    unittest.main()
