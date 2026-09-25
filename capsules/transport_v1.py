from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SCHEMA = "life-lately-capsule-v1"
AUTHORITY = "life_lately_private_authority"
INFO = b"life-lately-capsule-v1"
ALLOWED_DATA_CLASSES = {"SYNTHETIC_NON_PHI", "PRIVATE_NON_PHI"}
FORBIDDEN_DATA_CLASSES = {"PHI", "CLINICAL_RECORD", "PSYCHOTHERAPY_NOTE"}
ENVELOPE_FIELDS = {
    "schema", "run_id", "authority", "capability", "data_class",
    "source_sha256", "recipient_key_id", "sender_public_b64",
    "nonce_b64", "ciphertext_sha256", "plaintext_sha256",
}
DEFAULT_CHUNK_CHARS = 8000

def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")

def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)

def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def generate_recipient_keypair() -> tuple[str, str, str]:
    private = x25519.X25519PrivateKey.generate()
    private_raw = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return _b64e(private_raw), _b64e(public_raw), "sha256:" + sha256_bytes(public_raw)

def aad_bytes(*, run_id: str, capability: str, data_class: str, source_sha256: str, recipient_key_id: str) -> bytes:
    return json.dumps(
        {
            "schema": SCHEMA,
            "run_id": str(run_id),
            "authority": AUTHORITY,
            "capability": capability,
            "data_class": data_class,
            "source_sha256": source_sha256,
            "recipient_key_id": recipient_key_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

def _derive_key(shared: bytes, aad: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(aad).digest(),
        info=INFO,
    ).derive(shared)

def _validate_data_class(data_class: str) -> None:
    if data_class in FORBIDDEN_DATA_CLASSES:
        raise RuntimeError(f"forbidden capsule data_class: {data_class}")
    if data_class not in ALLOWED_DATA_CLASSES:
        raise RuntimeError(f"unsupported capsule data_class: {data_class}")

def seal(
    plaintext: bytes,
    *,
    recipient_public_b64: str,
    run_id: str,
    capability: str,
    data_class: str,
    source_sha256: str,
) -> tuple[dict, bytes]:
    _validate_data_class(data_class)
    if sha256_bytes(plaintext) != source_sha256:
        raise RuntimeError("source_sha256 must bind the exact plaintext payload")

    recipient_raw = _b64d(recipient_public_b64)
    if len(recipient_raw) != 32:
        raise RuntimeError("recipient public key length invalid")
    recipient = x25519.X25519PublicKey.from_public_bytes(recipient_raw)
    recipient_key_id = "sha256:" + sha256_bytes(recipient_raw)

    sender = x25519.X25519PrivateKey.generate()
    sender_public_raw = sender.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    aad = aad_bytes(
        run_id=str(run_id),
        capability=capability,
        data_class=data_class,
        source_sha256=source_sha256,
        recipient_key_id=recipient_key_id,
    )
    key = _derive_key(sender.exchange(recipient), aad)
    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)

    envelope = {
        "schema": SCHEMA,
        "run_id": str(run_id),
        "authority": AUTHORITY,
        "capability": capability,
        "data_class": data_class,
        "source_sha256": source_sha256,
        "recipient_key_id": recipient_key_id,
        "sender_public_b64": _b64e(sender_public_raw),
        "nonce_b64": _b64e(nonce),
        "ciphertext_sha256": sha256_bytes(ciphertext),
        "plaintext_sha256": source_sha256,
    }
    return envelope, ciphertext

def open_capsule(
    envelope: dict,
    ciphertext: bytes,
    *,
    recipient_private_b64: str,
    expected_run_id: str,
    expected_capability: str,
    expected_source_sha256: str,
) -> bytes:
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
        raise RuntimeError("capsule envelope field set mismatch")
    if envelope["schema"] != SCHEMA or envelope["authority"] != AUTHORITY:
        raise RuntimeError("capsule schema/authority mismatch")
    if str(envelope["run_id"]) != str(expected_run_id):
        raise RuntimeError("capsule run_id mismatch")
    if envelope["capability"] != expected_capability:
        raise RuntimeError("capsule capability mismatch")
    if envelope["source_sha256"] != expected_source_sha256:
        raise RuntimeError("capsule source hash mismatch")
    _validate_data_class(envelope["data_class"])
    if sha256_bytes(ciphertext) != envelope["ciphertext_sha256"]:
        raise RuntimeError("capsule ciphertext digest mismatch")

    private_raw = _b64d(recipient_private_b64)
    if len(private_raw) != 32:
        raise RuntimeError("recipient private key length invalid")
    private = x25519.X25519PrivateKey.from_private_bytes(private_raw)
    recipient_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    recipient_key_id = "sha256:" + sha256_bytes(recipient_raw)
    if recipient_key_id != envelope["recipient_key_id"]:
        raise RuntimeError("recipient key fingerprint mismatch")

    sender_raw = _b64d(envelope["sender_public_b64"])
    nonce = _b64d(envelope["nonce_b64"])
    if len(sender_raw) != 32 or len(nonce) != 12:
        raise RuntimeError("capsule sender key/nonce invalid")
    aad = aad_bytes(
        run_id=str(expected_run_id),
        capability=expected_capability,
        data_class=envelope["data_class"],
        source_sha256=expected_source_sha256,
        recipient_key_id=recipient_key_id,
    )
    shared = private.exchange(x25519.X25519PublicKey.from_public_bytes(sender_raw))
    plaintext = ChaCha20Poly1305(_derive_key(shared, aad)).decrypt(nonce, ciphertext, aad)
    if sha256_bytes(plaintext) != envelope["plaintext_sha256"]:
        raise RuntimeError("capsule plaintext digest mismatch")
    return plaintext

def chunk_ciphertext(ciphertext: bytes, *, chunk_chars: int = DEFAULT_CHUNK_CHARS) -> list[str]:
    if int(chunk_chars) <= 0:
        raise ValueError("chunk_chars must be positive")
    payload_b64 = _b64e(ciphertext)
    return [payload_b64[i:i+int(chunk_chars)] for i in range(0, len(payload_b64), int(chunk_chars))]

def assemble_chunks(chunks: list[str]) -> bytes:
    if not chunks:
        raise RuntimeError("capsule chunk list empty")
    return _b64d("".join(chunks))
