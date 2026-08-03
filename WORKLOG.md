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
