#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path

REQUIRED = {
    "SITE_BUILD_TEST",
    "SITE_DEPLOY",
    "DNS_DRIFT_AUDIT",
    "TLS_HEALTH_CHECK",
    "SITE_HEALTH_CHECK",
    "BOOKING_LINK_CHECK",
    "PROFILE_LINK_CHECK",
    "EMAIL_DNS_AUDIT",
    "CONFIG_DRIFT_AUDIT",
    "DOMAIN_EXPIRY_CHECK",
    "BUSINESS_DEPENDENCY_HEALTH",
    "SYNTHETIC_ROUTE_PROBE",
    "DEPLOYMENT_RECEIPT",
}

FORBIDDEN_KEYS = {
    "client_name", "patient_name", "dob", "diagnosis", "clinical_note",
    "clinical_narrative", "email", "phone", "address", "ssn",
}

def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def canonical_hash(obj):
    payload = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()

def walk_keys(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key.lower()
            yield from walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_keys(child)

def validate(capabilities, smoke):
    errors = []

    if capabilities.get("schema_version") != "1.0":
        errors.append("capability schema_version must be 1.0")
    if smoke.get("schema_version") != "1.0":
        errors.append("smoke schema_version must be 1.0")
    if smoke.get("data_class") != "SYNTHETIC_NON_PHI":
        errors.append("smoke data_class must be SYNTHETIC_NON_PHI")

    names = [item.get("name") for item in capabilities.get("capabilities", [])]
    if len(names) != len(set(names)):
        errors.append("capability names must be unique")

    missing = sorted(REQUIRED - set(names))
    if missing:
        errors.append("missing required capabilities: " + ", ".join(missing))

    allowed = set(names)
    for probe in smoke.get("probes", []):
        if probe.get("capability") not in allowed:
            errors.append(f"probe {probe.get('id')} uses undeclared capability")

    present_forbidden = sorted(set(walk_keys(smoke)) & FORBIDDEN_KEYS)
    if present_forbidden:
        errors.append("forbidden public-data keys present: " + ", ".join(present_forbidden))

    receipt = {
        "receipt_version": "1.0",
        "result": "PASS" if not errors else "FAIL",
        "capability_registry_sha256": canonical_hash(capabilities),
        "smoke_manifest_sha256": canonical_hash(smoke),
        "capability_count": len(names),
        "probe_count": len(smoke.get("probes", [])),
        "errors": errors,
    }
    return receipt

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--capabilities", default="runtime/capabilities.v1.json")
    parser.add_argument("--smoke", default="fixtures/runtime_smoke.v1.json")
    parser.add_argument("--write")
    args = parser.parse_args()

    receipt = validate(load(args.capabilities), load(args.smoke))
    rendered = json.dumps(receipt, indent=2, sort_keys=True)
    print(rendered)
    if args.write:
        Path(args.write).write_text(rendered + "\n", encoding="utf-8")
    raise SystemExit(0 if receipt["result"] == "PASS" else 1)

if __name__ == "__main__":
    main()
