import unittest

from scripts.runtime_readiness_check import load, validate

class RuntimeReadinessTests(unittest.TestCase):
    def test_preactivation_manifest_is_valid_but_not_ready(self):
        receipt = validate(load("runtime/public_bindings.v1.json"))
        self.assertEqual("PREACTIVATION", receipt["result"])
        self.assertEqual(6, receipt["binding_count"])
        self.assertEqual(0, receipt["enabled_count"])
        self.assertEqual([], receipt["errors"])

if __name__ == "__main__":
    unittest.main()
