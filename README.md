# LifeLately-LPC-Runtime

Public execution/deployment plane for the Life Lately Counseling prototype.

## Authority boundary

The private repository `XoticHaze/LifeLately-LPC` is the product, business-rule, and operating-model authority.

This public repository executes bounded runtime capabilities. It must not redefine client routing, clinician activation, payer participation, acquisition semantics, or clinical policy.

## Current implemented baseline

Implemented and CI-validated:

- governed capability registry: `runtime/capabilities.v1.json`;
- synthetic runtime smoke manifest: `fixtures/runtime_smoke.v1.json`;
- fail-closed contract validator: `scripts/runtime_contract_check.py`;
- public-target activation manifest: `runtime/public_bindings.v1.json`;
- preactivation readiness validator: `scripts/runtime_readiness_check.py`;
- unit tests for contract and readiness state;
- GitHub Actions workflow emitting sanitized receipts.

Current production-binding state is intentionally `PREACTIVATION`.

Real site, booking, public profile, DNS expectation, TLS, and registrar bindings are not enabled until the corresponding business/provider prerequisites are evidenced.

## Security model

Public compute does **not** imply public workload data.

The runtime follows this boundary:

1. acquire only an authorized bounded job;
2. accept public, synthetic, or explicitly approved private/encrypted input classes;
3. verify capability and input class before execution;
4. materialize protected plaintext only transiently where a later approved workflow explicitly permits it;
5. execute an allowlisted capability rather than arbitrary shell authority;
6. emit sanitized receipts/results;
7. destroy transient protected material before completion.

Never commit:

- provider or client credentials;
- client data or PHI;
- private application source;
- Cloudflare/API secrets;
- mailbox credentials;
- clinical-system tokens;
- decrypted private workload material.

Clinical/PHI workloads require a separate HIPAA/BAA boundary decision even when cryptographic transport is secure.

## Capability registry

Current declared capabilities:

- SITE_BUILD_TEST
- SITE_DEPLOY
- DNS_DRIFT_AUDIT
- TLS_HEALTH_CHECK
- SITE_HEALTH_CHECK
- BOOKING_LINK_CHECK
- PROFILE_LINK_CHECK
- EMAIL_DNS_AUDIT
- CONFIG_DRIFT_AUDIT
- DOMAIN_EXPIRY_CHECK
- BUSINESS_DEPENDENCY_HEALTH
- SYNTHETIC_ROUTE_PROBE
- DEPLOYMENT_RECEIPT

## Public binding rule

`runtime/public_bindings.v1.json` is fail closed.

A binding may be enabled only when:

- its target is public/runtime-safe;
- the private operating authority has approved the route;
- its declared activation requirements have durable evidence;
- enabling it does not move PHI or secrets into public repository/artifacts.

Examples:

- SITE_HEALTH_CHECK waits for approved site deployment;
- BOOKING_LINK_CHECK waits for a real approved clinical booking URL and active clinician route;
- PROFILE_LINK_CHECK waits for an approved public provider/profile URL;
- EMAIL_DNS_AUDIT waits for the real Workspace tenant and approved DNS expectations.

## Runtime receipts

CI produces two sanitized receipts:

1. `runtime-contract-receipt.json`
   - capability registry hash;
   - smoke manifest hash;
   - capability count;
   - probe count;
   - PASS/FAIL.

2. `runtime-readiness-receipt.json`
   - binding count;
   - enabled binding count;
   - PREACTIVATION/READY/FAIL;
   - pending activation conditions;
   - validation errors.

The receipt workflow must remain safe to expose publicly.

## Next runtime stages

1. bind a staging website target;
2. execute live public DNS/TLS/site probes;
3. add approved static-site build/deploy input path from private source authority;
4. bind public booking/profile links only after real clinical accounts are ready;
5. add email DNS expectation checks after Workspace creation;
6. add Cloudflare deployment using repository/environment secrets, never committed secrets;
7. add business dependency health and expiry/renewal checks;
8. preserve deterministic sanitized receipts for every activation.

## Migration requirement

Everything must remain portable to a future practice-controlled GitHub/Cloudflare account. Avoid hardcoded personal account IDs and personal-account assumptions.
