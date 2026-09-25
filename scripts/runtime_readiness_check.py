#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

PUBLIC_TARGET_CAPABILITIES = {
    "SITE_HEALTH_CHECK",
    "BOOKING_LINK_CHECK",
    "PROFILE_LINK_CHECK",
    "EMAIL_DNS_AUDIT",
    "TLS_HEALTH_CHECK",
    "DOMAIN_EXPIRY_CHECK",
}

FORBIDDEN_FIELDS = {
    "client_name", "patient_name", "dob", "diagnosis", "clinical_note",
    "clinical_narrative", "ssn", "provider_password", "mailbox_password",
    "cloudflare_api_token", "clinical_system_token",
}

def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def walk_keys(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key.lower()
            yield from walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_keys(child)

def validate(bindings):
    errors = []
    pending = []

    if bindings.get("schema_version") != "1.0":
        errors.append("schema_version must be 1.0")
    if bindings.get("data_policy") != "PUBLIC_OR_SYNTHETIC_ONLY":
        errors.append("data_policy must be PUBLIC_OR_SYNTHETIC_ONLY")

    seen = set()
    for item in bindings.get("bindings", []):
        ident = item.get("id")
        if not ident:
            errors.append("binding id is required")
            continue
        if ident in seen:
            errors.append(f"duplicate binding id: {ident}")
        seen.add(ident)

        capability = item.get("capability")
        if capability not in PUBLIC_TARGET_CAPABILITIES:
            errors.append(f"{ident}: unsupported public binding capability {capability}")

        if item.get("enabled"):
            if not item.get("target"):
                errors.append(f"{ident}: enabled binding requires target")
            if item.get("activation_requires"):
                pending.append(f"{ident}: activation requirements must be externally evidenced before production use")
        else:
            pending.append(f"{ident}: not activated")

    bad = sorted(set(walk_keys(bindings)) & FORBIDDEN_FIELDS)
    if bad:
        errors.append("forbidden secret/PHI-shaped fields present: " + ", ".join(bad))

    state = "FAIL" if errors else ("PREACTIVATION" if pending else "READY")
    return {
        "receipt_version":"1.0",
        "result":state,
        "binding_count":len(bindings.get("bindings", [])),
        "enabled_count":sum(1 for item in bindings.get("bindings", []) if item.get("enabled")),
        "errors":errors,
        "pending":pending,
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bindings", default="runtime/public_bindings.v1.json")
    parser.add_argument("--write")
    args = parser.parse_args()

    receipt = validate(load(args.bindings))
    rendered = json.dumps(receipt, indent=2, sort_keys=True)
    print(rendered)
    if args.write:
        Path(args.write).write_text(rendered + "\n", encoding="utf-8")

    raise SystemExit(1 if receipt["result"] == "FAIL" else 0)

if __name__ == "__main__":
    main()
