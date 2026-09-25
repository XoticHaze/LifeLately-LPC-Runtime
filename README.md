# LifeLately-LPC-Runtime

Public execution/deployment plane for the Life Lately Counseling prototype.

## Purpose

This repository is intended to provide reusable public compute for:
- website build/test/deploy;
- Cloudflare deployment and configuration validation;
- DNS/TLS/site health checks;
- configuration drift checks;
- link/profile/booking availability checks;
- bounded automation jobs;
- deterministic receipts and deployment provenance.

The private product/source authority remains `LifeLately-LPC`.

## Security model

Public compute does **not** imply public workload data.

The runtime should follow a fail-closed private-input pattern:
1. acquire a run-bound authenticated request;
2. receive only encrypted/private source or inputs when required;
3. verify declared identities/hashes;
4. materialize plaintext transiently only inside the authorized job;
5. execute an allowlisted capability rather than arbitrary shell authority;
6. emit sanitized deterministic receipts/results;
7. destroy transient private material before job completion.

Never commit provider credentials, client data, PHI, private application source, Cloudflare secrets, mailbox credentials, or other protected plaintext to this repository.

## Initial capability backlog

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
- DEPLOYMENT_RECEIPT

## Migration requirement

Everything must remain portable to a future practice-controlled GitHub/Cloudflare account. Avoid hardcoded owner IDs and personal-account assumptions.
