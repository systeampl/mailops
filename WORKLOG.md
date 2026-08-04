# Mailops work log

## 2026-07-12

- Implemented the first standalone checker and terminal/machine output.

## 2026-07-18

- Reached 66 tests and 78.6% package coverage.
- Recorded P0/P1 proposals around correctness, public API, safety, and release
  automation.

## 2026-07-24

- Published the initial repository state as `v0.1.0` code.

## 2026-08-03

- Re-reviewed source, test suite, fresh and installed binaries, and the prior
  work journal.
- Reproduced a stale installed binary and vulnerable Go/module versions.
- Fixed DNSBL classification, deadlines, exit status, SPF/BIMI error handling,
  and observability gaps.
- Implemented RFC 9989 DMARC, the public schema/API, stable finding codes,
  posture/availability split, IDN/resolver/batch/config support, active-target
  controls, DNSSEC, DANE/TLSA, deeper SPF/BIMI checks, CI/release automation,
  and live integration coverage.
- Re-ran unit, race, shuffle, coverage, vet, vulnerability, build, and live
  validation after the changes; exact final results belong in the release/PR
  report rather than this long-lived journal.

## 2026-08-04 — SysTeam Ops Tools cohesion pass

Confirmed `dnsops`, `certops`, and `mailops` as public repositories in the
`systeampl` organization. Aligned branding, build metadata, version output,
CI, Dependabot, GoReleaser, security policy, and contribution guidance across
the ecosystem.

Staticcheck findings were resolved by removing a dead MDA wrapper and
simplifying MTA-STS wildcard normalization. The final validation included race
tests, vet, Staticcheck, govulncheck, actionlint, six-platform release
snapshots, checksums, live DNS/SMTP/IMAP/integration checks, OTLP export,
strict-policy exits, and fresh release-binary execution.

## 2026-08-04 — public integration contract and publish gate

Normalized the supported engine schema to `mailops.report.v1` and documented
the same additive-field and severity contract used by the other SysTeam Ops
Tools. The public engine remains backend-neutral so a SysChecks adapter can be
implemented independently.

The final publish gate passed race/shuffle tests, vet, Staticcheck,
govulncheck, actionlint, GoReleaser validation, six release targets, checksum
and archive-content verification, live policy/config/strict checks, SMTP and
IMAP probes, Prometheus, and OTLP from the generated release binary. Aggregate
statement coverage was 72.8%.
