# NOCTYRA Access Control Policy

Status: repository-owner policy for private development.

## Access principles
- Private repository by default.
- Grant access only to named people with a documented project need.
- Use least privilege; avoid granting admin permissions for routine contribution.
- Require multi-factor authentication on Git hosting accounts.
- Remove access promptly when a contributor's role ends.
- Do not share personal access tokens or account credentials.
- Store automation credentials in the platform's secret store, never in source.

## Change control
- Keep `main` releasable.
- Use short-lived feature branches for implementation work.
- Require review for changes to cryptography, file formats, key management,
  image parsing, transport, and release workflows.
- Require formatting, linting, tests, and dependency review.
- Do not merge code with unresolved critical or high-severity findings.

## Sensitive materials
Do not commit:
- passwords, private keys, recovery secrets, API tokens, or certificates;
- real personal documents or private carrier images;
- plaintext test fixtures derived from private user data;
- logs containing secrets or decrypted content.

## Operational note
This file documents intended controls. The repository owner must separately
enable and verify GitHub branch protection, required reviews, secret scanning,
and account MFA in the hosting service settings. A policy document does not
activate those controls automatically.
