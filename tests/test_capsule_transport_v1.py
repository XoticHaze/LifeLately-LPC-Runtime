import unittest

from capsules.transport_v1 import generate_recipient_keypair, open_capsule, seal, sha256_bytes

class CapsuleTransportTests(unittest.TestCase):
    def setUp(self):
        self.payload = b"synthetic private source payload"
        self.source_hash = sha256_bytes(self.payload)
        self.private_b64, self.public_b64, _ = generate_recipient_keypair()

    def _sealed(self):
        return seal(
            self.payload,
            recipient_public_b64=self.public_b64,
            run_id="run-123",
            capability="SITE_BUILD_TEST",
            data_class="PRIVATE_NON_PHI",
            source_sha256=self.source_hash,
        )

    def test_roundtrip_is_run_and_capability_bound(self):
        envelope, ciphertext = self._sealed()
        restored = open_capsule(
            envelope, ciphertext,
            recipient_private_b64=self.private_b64,
            expected_run_id="run-123",
            expected_capability="SITE_BUILD_TEST",
            expected_source_sha256=self.source_hash,
        )
        self.assertEqual(self.payload, restored)

    def test_wrong_run_id_fails_closed(self):
        envelope, ciphertext = self._sealed()
        with self.assertRaisesRegex(RuntimeError, "run_id mismatch"):
            open_capsule(
                envelope, ciphertext,
                recipient_private_b64=self.private_b64,
                expected_run_id="different-run",
                expected_capability="SITE_BUILD_TEST",
                expected_source_sha256=self.source_hash,
            )

    def test_wrong_capability_fails_closed(self):
        envelope, ciphertext = self._sealed()
        with self.assertRaisesRegex(RuntimeError, "capability mismatch"):
            open_capsule(
                envelope, ciphertext,
                recipient_private_b64=self.private_b64,
                expected_run_id="run-123",
                expected_capability="SITE_DEPLOY",
                expected_source_sha256=self.source_hash,
            )

    def test_tamper_fails_closed(self):
        envelope, ciphertext = self._sealed()
        tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
        with self.assertRaisesRegex(RuntimeError, "ciphertext digest mismatch"):
            open_capsule(
                envelope, tampered,
                recipient_private_b64=self.private_b64,
                expected_run_id="run-123",
                expected_capability="SITE_BUILD_TEST",
                expected_source_sha256=self.source_hash,
            )

    def test_phi_class_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "forbidden capsule data_class"):
            seal(
                self.payload,
                recipient_public_b64=self.public_b64,
                run_id="run-123",
                capability="SITE_BUILD_TEST",
                data_class="PHI",
                source_sha256=self.source_hash,
            )

if __name__ == "__main__":
    unittest.main()
