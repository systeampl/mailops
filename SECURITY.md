# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's security
advisory form for this repository. Do not open a public issue containing
secrets, exploit details, private mail data, or affected infrastructure.

Include the affected `mailops` version or commit, operating system,
reproduction steps, impact, and any suggested mitigation. Reports will be
acknowledged and triaged as soon as practical.

## Operational guidance

- Treat domain inventories, endpoint details, credentials, and generated
  reports as sensitive operational data.
- Keep private-target protection enabled unless an internal probe is
  intentional and authorized.
- Keep `mailops` and its Go toolchain updated; CI runs `govulncheck` on every
  change.
