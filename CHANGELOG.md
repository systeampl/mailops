# Changelog

All notable changes to `mailops` are documented here. The project follows
Semantic Versioning.

## [Unreleased]

### Changed

- aligned CI, releases, dependency updates, security guidance, and build
  metadata with the SysTeam Ops Tools contract
- standardized `version` and `--version` text, JSON, and YAML output
- normalized the public report schema identifier to `mailops.report.v1`

### Fixed

- removed dead probe code and simplified MTA-STS wildcard normalization found
  by Staticcheck

## [0.2.0] - 2026-08-03

### Added

- RFC 9989 DMARC DNS Tree Walk, inherited `sp`/`np` policy, PSD and `t=y`.
- DNSSEC authentication status and DANE/TLSA discovery/certificate matching.
- Public versioned Go engine at `pkg/mailops`, finding codes, and separate
  posture and availability statuses.
- IDN normalization, custom DNS resolver, multi-domain batch mode, line-based
  domain files, and YAML configuration.
- SSRF-oriented target policy for SMTP, MDA, MTA-STS, and BIMI assets.
- BIMI SVG Tiny-PS and authority-certificate inspection.
- Opt-in live integration tests, GitHub CI, scheduled live checks, Dependabot,
  and GoReleaser configuration.

### Fixed

- DNSBL provider/error responses are no longer reported as listings.
- Overall deadlines now interrupt stalled SMTP/MDA reads and OTLP requests.
- Invalid input exits with documented status 2.
- SPF include/redirect failures invalidate SPF; malformed mechanisms and
  duplicate redirects are reported.
- BIMI DNS failures and RBL lookup failures are visible in findings/metrics.
- Go and `x/net` dependencies were updated past reported vulnerabilities.

## [0.1.0] - 2026-07-24

- Initial standalone mail policy, reputation, SMTP/MDA, Prometheus, and OTLP
  implementation.

[Unreleased]: https://github.com/systeampl/mailops/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/systeampl/mailops/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/systeampl/mailops/releases/tag/v0.1.0
