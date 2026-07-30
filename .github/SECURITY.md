# Security Policy

OpenSigner manages the key shares that control user wallets. We take reports
seriously and would rather hear about a suspected issue than not.

## Reporting a Vulnerability

**Do not open a public issue or pull request for a security problem.** A public
report tells everyone running OpenSigner about the weakness at the same moment it
tells us, and self-hosted deployments cannot be patched centrally.

Instead, either:

- Use [GitHub private vulnerability reporting](https://github.com/openfort-xyz/opensigner/security/advisories/new)
  (preferred — it keeps the discussion attached to the repository), or
- Email [security@openfort.xyz](mailto:security@openfort.xyz).

Please include, as far as you can:

- the affected component (`auth_service`, `hot_storage`, `cold_storage`, `iframe`)
  and its version, commit, or image digest;
- what an attacker gains, and what access they need to begin;
- reproduction steps or a proof of concept;
- any suggested fix.

## What to expect

| Stage | Target |
|---|---|
| Acknowledgement of your report | 2 business days |
| Initial assessment and severity | 5 business days |
| Fix or documented mitigation for high severity | 30 days |
| Public advisory | after a fix ships, coordinated with you |

We will keep you updated while we investigate, credit you in the advisory unless
you would rather we did not, and tell you plainly if we conclude something is not
a vulnerability.

## Scope

In scope: `auth_service`, `hot_storage`, the `iframe` integration, the
`docker-compose` deployment, and the documented setup guidance. Weaknesses in the
key-splitting and recovery design are in scope even without a working exploit.

Out of scope: findings that require an already-compromised host or administrator
credentials; missing hardening with no demonstrated impact; volumetric
denial-of-service; raw scanner output with no analysis; and the placeholder
credentials in `.env.example`, which exist to be replaced.

## Supported versions

`main` is the supported branch and receives security fixes. There is no
long-term-support branch. Because OpenSigner is self-hosted, applying a fix means
rebuilding and redeploying — pin images by digest and track releases.

## Deploying safely

Self-hosters own their configuration. Before going to production: generate every
secret in `.env.example` with a CSPRNG, serve every component over TLS, restrict
`ALLOWED_ORIGINS` to origins you control, keep the databases off any public
network, and do not use the development compose overlay, which disables database
TLS.
