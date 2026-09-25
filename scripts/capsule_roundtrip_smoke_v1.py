from __future__ import annotations

import json
import os
from pathlib import Path

from capsules.transport_v1 import (
    assemble_chunks,
    chunk_ciphertext,
    generate_recipient_keypair,
    open_capsule,
    seal,
    sha256_bytes,
)

def main() -> int:
    run_id = os.environ.get("GITHUB_RUN_ID", "local-smoke")
    capability = "SITE_BUILD_TEST"
    payload = json.dumps({
        "fixture": "life-lately-private-source-smoke",
        "data_class": "PRIVATE_NON_PHI",
        "content": "synthetic private source bytes for capsule transport proof",
    }, sort_keys=True).encode("utf-8")
    source_sha256 = sha256_bytes(payload)

    private_b64, public_b64, recipient_key_id = generate_recipient_keypair()
    envelope, ciphertext = seal(
        payload,
        recipient_public_b64=public_b64,
        run_id=run_id,
        capability=capability,
        data_class="PRIVATE_NON_PHI",
        source_sha256=source_sha256,
    )
    chunks = chunk_ciphertext(ciphertext, chunk_chars=64)
    restored = open_capsule(
        envelope,
        assemble_chunks(chunks),
        recipient_private_b64=private_b64,
        expected_run_id=run_id,
        expected_capability=capability,
        expected_source_sha256=source_sha256,
    )
    if restored != payload:
        raise SystemExit("capsule roundtrip mismatch")

    receipt = {
        "receipt_version": "1.0",
        "result": "PASS",
        "schema": envelope["schema"],
        "authority": envelope["authority"],
        "run_id": run_id,
        "capability": capability,
        "data_class": envelope["data_class"],
        "recipient_key_id": recipient_key_id,
        "source_sha256": source_sha256,
        "ciphertext_sha256": envelope["ciphertext_sha256"],
        "chunk_count": len(chunks),
        "private_key_persisted": False,
        "plaintext_artifact_emitted": False,
    }
    Path("capsule-transport-receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
