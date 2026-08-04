# mailops

[![CI](https://github.com/systeampl/mailops/actions/workflows/ci.yml/badge.svg)](https://github.com/systeampl/mailops/actions/workflows/ci.yml)

`mailops` is a standalone mail deliverability, email security, and mail
operations checker with human-friendly terminal output, JSON/YAML reports,
Prometheus text output, and optional OTLP/HTTP metric export.

Part of [SysTeam Ops Tools](https://github.com/systeampl):
[dnsops](https://github.com/systeampl/dnsops) ·
[certops](https://github.com/systeampl/certops) ·
[mailops](https://github.com/systeampl/mailops). The open-source tools are
built by [SysTeam](https://systeam.pl), run standalone, and provide structured
results designed for deep checks in [SysChecks](https://syschecks.com).

## Quick Start

```bash
mailops check example.com
mailops check example.com --json
mailops check example.com --yaml
mailops check example.com --prom
mailops check example.com example.net --json
mailops check --config examples/mailops.yaml --yaml
```

Use a provider profile when the domain is backed by a known mail platform:

```bash
mailops check example.com --profile google-workspace
mailops check example.com --profile microsoft-365
```

Run active SMTP and mailbox-access probes:

```bash
mailops check example.com --smtp --smtp-port 25
mailops check example.com --smtp --smtp-host smtp.example.com --smtp-port 465,587
mailops check example.com --mda --mda-host imap.example.com --mda-host pop.example.com
```

Check reputation lists:

```bash
mailops check example.com --reputation
mailops check example.com --reputation --domainbl dbl.spamhaus.org --domainbl multi.surbl.org
```

Export OTEL metrics:

```bash
mailops check example.com --otel-endpoint http://localhost:4318
```

## Installation

`mailops` requires Go 1.25 or newer and selects the patched Go 1.26.5
toolchain declared in `go.mod`. Build it from the project directory:

```bash
go mod download
go build -trimpath -o mailops .
./mailops version
```

Install the resulting binary somewhere on `PATH`, for example:

```bash
sudo install -m 0755 mailops /usr/local/bin/mailops
```

Checks use the system DNS resolver by default; `--resolver` selects another
recursive resolver. Core checks require outbound DNS and may
fetch an MTA-STS policy over HTTPS. SMTP, MDA, reputation, and OTEL options
also require access to their respective network endpoints.

## Command Reference

```text
mailops check <domain...> [--json|--yaml|--prom] [options]
mailops version [--json|--yaml]
```

Options may appear before or after the domain. List options are repeatable and
also accept comma-separated values.

| Option | Default | Purpose |
| --- | --- | --- |
| `--profile <name>` | none | Apply a provider profile; repeatable. |
| `--selector <name>` | common selectors | Select DKIM selectors; repeatable. |
| `--rbl <zone>` | built-in IPv4 DNSBLs | Select IP reputation zones; repeatable. |
| `--no-rbl` | false | Disable the otherwise enabled MX-IP DNSBL checks. |
| `--no-dnssec` | false | Disable DNSSEC authentication checks. |
| `--no-dane` | false | Disable TLSA/DANE discovery and certificate matching. |
| `--reputation` | false | Enable domain DBL/SURBL/URIBL-style checks. |
| `--domainbl <zone>` | built-in domain lists | Select domain reputation zones; repeatable. |
| `--smtp` | false | Probe SMTP endpoints. |
| `--smtp-host <host>` | MX hosts | Select SMTP hosts; repeatable. |
| `--smtp-port <port>` | `25` | Select SMTP ports; repeatable. |
| `--no-open-relay` | false | Skip the SMTP unauthenticated RCPT relay probe. |
| `--mda` | false | Probe IMAP and POP3 endpoints. |
| `--mda-host <host>` | common names | Select MDA hosts; repeatable. |
| `--mda-port <port>` | `143,993,110,995` | Select MDA ports; repeatable. |
| `--resolver <address>` | system | Use a DNS resolver IP or `host:port`. |
| `--domains-file <path>` | none | Add domains from a line-oriented file. |
| `--config <path>` | none | Load domains and check defaults from YAML. |
| `--allow-private-targets` | false | Permit active probes to private/special-use addresses. |
| `--strict` | false | Promote selected policy and transport warnings to critical. |
| `--timeout <duration>` | `10s` | Set the overall check deadline. |
| `--fail-on <level>` | `critical` | Exit with status 1 at `warn`, `critical`, or `error`. |
| `--otel-endpoint <url>` | none | POST OTLP/HTTP JSON metrics to the endpoint. |
| `--json` | false | Emit JSON instead of terminal output. |
| `--yaml` | false | Emit YAML instead of terminal output. |
| `--prom` | false | Emit Prometheus text exposition. |

The three output flags are mutually exclusive. `--otel-endpoint` is
independent of the selected local output format. If its URL does not end in
`/v1/metrics`, that path is appended automatically.

## What It Checks

Core DNS and policy checks:

- MX presence and MX host resolution.
- SPF syntax, multiple SPF detection, mechanism/address validation, `all`
  policy warnings, recursive `include` / `redirect`, loops, and lookup limits.
- DKIM selector discovery and public key parsing.
- DMARC RFC 9989 DNS Tree Walk (up to eight queries), inherited `sp`/`np`
  policy, PSD boundaries, `t=y`, report destinations, and external report
  authorization hints. Historic `pct` is reported but ignored.
- DNSSEC signature/authentication state using the selected recursive resolver.
- SMTP TLSA/DANE records, DNSSEC protection, syntax, and observed certificate
  matching when an SMTP TLS probe is available.
- MTA-STS TXT and HTTPS policy.
- MTA-STS MX coverage: whether real MX hosts are covered by policy `mx:`
  patterns.
- TLS-RPT record.
- BIMI record/tag syntax, safe HTTPS asset retrieval, SVG 1.2 Tiny-PS checks,
  authority X.509 parsing, explicit publication decline, and effective DMARC
  enforcement compatibility.
- PTR and forward-confirmed reverse DNS for MX IPs.
- DNSBL/RBL checks for MX IPv4 addresses.
- Optional domain reputation checks through DNS-based DBL/SURBL/URIBL-style
  zones.

Active SMTP checks:

- TCP connect.
- Banner read.
- EHLO.
- STARTTLS on `25` / `587`.
- Implicit TLS on `465`.
- TLS version and certificate expiry.
- Advertised SMTP AUTH mechanisms.
- Unauthenticated open-relay RCPT probe without sending message `DATA`.

Active MDA checks:

- IMAP `143`.
- IMAPS `993`.
- POP3 `110`.
- POP3S `995`.
- TCP connect.
- Banner/capability checks.
- STARTTLS/STLS where applicable.
- TLS version and certificate expiry.

## Provider Profiles

Profiles pre-fill common DKIM selectors and provider endpoints. Explicit CLI
flags still win: if you pass `--smtp-host`, `--smtp-port`, `--mda-host`, or
`--mda-port`, those values are kept.

Built-in profiles:

- `google-workspace`
- `gmail`
- `microsoft-365`
- `office365`
- `amazonses`
- `sendgrid`
- `mailgun`
- `postmark`
- `mandrill`
- `zoho`

Examples:

```bash
mailops check example.com --profile google-workspace --smtp --mda
mailops check example.com --profile sendgrid --smtp
mailops check example.com --profile microsoft-365 --selector selector1 --selector selector2
```

## SMTP Probes

By default, `--smtp` checks MX hosts on port `25`.

```bash
mailops check example.com --smtp
```

For submission endpoints, use explicit hosts:

```bash
mailops check example.com --smtp --smtp-host smtp.example.com --smtp-port 587
mailops check example.com --smtp --smtp-host smtp.example.com --smtp-port 465,587
```

`465` is treated as implicit TLS. `25` and `587` use plain SMTP first and then
STARTTLS if advertised.

Open relay checking is enabled whenever `--smtp` is enabled. The probe issues:

```text
MAIL FROM:<mailops-open-relay-test@example.net>
RCPT TO:<mailops-open-relay-test@example.org>
RSET
```

It does not send `DATA`. If the server accepts the external unauthenticated
recipient, `mailops` reports a critical open-relay finding.

Disable this probe only when a target policy forbids RCPT probing:

```bash
mailops check example.com --smtp --no-open-relay
```

## MDA Probes

`--mda` checks mailbox access endpoints without logging in.

```bash
mailops check example.com --mda
mailops check example.com --mda --mda-host imap.example.com --mda-port 993
mailops check example.com --mda --mda-host imap.example.com --mda-host pop.example.com --mda-port 993,995
```

When no host is provided, `mailops` tries common names:

- `imap.<domain>`
- `pop.<domain>`
- `mail.<domain>`

The MDA probe checks service availability and TLS posture. It does not validate
user credentials or read mailboxes.

## Reputation

`--reputation` checks domain reputation DNS zones. Defaults:

- `dbl.spamhaus.org`
- `multi.surbl.org`
- `multi.uribl.com`

Example:

```bash
mailops check example.com --reputation
```

Some public reputation zones return `127.0.0.1` for blocked, rate-limited, or
policy-denied queries. `mailops` treats that as a lookup error, not as a real
listing.

## Output Formats

Terminal output is the default. It uses the same colored table style as
`dnsops` and `certops`.

```bash
mailops check example.com
```

Machine-readable output:

```bash
mailops check example.com --json
mailops check example.com --yaml
mailops check example.com --prom
```

Prometheus metric names use the `mailops_` prefix. OTEL metric names use the
`mailops.*` namespace.

JSON output is an array of reports, even for one domain. YAML output uses a
top-level `reports` key. Each report contains the normalized domain, aggregate
status, separate `posture_status` and `availability_status`, individual
protocol results, findings with stable `code` values, summary counts, generation
time, and duration. Prometheus and OTEL output expose the operational subset
as metrics rather than serializing the entire report.

`schema_version` identifies the machine-readable contract. Consumers can use
the supported Go API at `github.com/systeampl/mailops/pkg/mailops`. The current
value is `mailops.report.v1`; new fields may be added within that version and
breaking changes increment its major component. Common finding severity
constants are `info`, `warn`, `critical`, and `error`. Integration adapters
belong in the consuming product, so the standalone tool and its public engine
remain reusable.

## Batch and YAML configuration

All positional domains are checked, with one independent timeout per domain:

```bash
mailops check example.com example.net --json
mailops check --domains-file domains.txt --prom
mailops check --config examples/mailops.yaml --yaml
```

Blank lines and lines beginning with `#` are ignored in domain files. Explicit
CLI flags override their YAML counterparts. IDNs may be supplied as Unicode or
as DNS A-labels; reports use normalized A-labels.

## Active-target safety

SMTP, IMAP/POP3, MTA-STS, and BIMI requests reject loopback, private,
link-local, documentation, carrier-grade NAT, and other special-use addresses
by default. BIMI HTTP connections are resolved through the selected resolver
and pinned to an approved address. Use `--allow-private-targets` only for an
intentional internal monitoring job. The open-relay probe still stops before
`DATA`.

OTEL export currently uses OTLP/HTTP JSON without custom authentication
headers. An export failure is written to standard error but does not replace
the mail check status or its output.

## Prometheus

`--prom` is useful for:

- `node_exporter` textfile collector.
- cron/systemd timers.
- CI jobs.
- one-shot probes from a private agent.

For textfile collector usage, write atomically:

```bash
out=/var/lib/node_exporter/textfile_collector/mailops_example.prom
mailops check example.com --prom --profile google-workspace --reputation --smtp --mda --no-rbl > "${out}.tmp"
mv "${out}.tmp" "${out}"
```

Useful operational metrics:

- `mailops_check_up`
- `mailops_check_duration_seconds`
- `mailops_last_check_timestamp_seconds`
- `mailops_status_code`

Useful DNS/policy metrics:

- `mailops_mx_records`
- `mailops_record_present`
- `mailops_record_valid`
- `mailops_spf_estimated_lookups`
- `mailops_spf_lookup_limit_used`
- `mailops_dmarc_pct`
- `mailops_dnssec_secure`
- `mailops_dane_tlsa_present`
- `mailops_dane_tlsa_valid`
- `mailops_dane_tlsa_matched`
- `mailops_dkim_valid_selectors`
- `mailops_mta_sts_mx_matched_ratio`
- `mailops_ptr_forward_confirmed_ratio`

Useful reputation metrics:

- `mailops_rbl_hits`
- `mailops_rbl_listed`
- `mailops_domainbl_hits`
- `mailops_domainbl_listed`
- `mailops_domainbl_lookup_error`

Useful SMTP/MDA metrics:

- `mailops_smtp_connect_ok`
- `mailops_smtp_tls_ok`
- `mailops_smtp_auth_mechanisms`
- `mailops_smtp_open_relay_checked`
- `mailops_smtp_open_relay`
- `mailops_smtp_relay_mail_code`
- `mailops_smtp_relay_rcpt_code`
- `mailops_smtp_cert_days_remaining`
- `mailops_mda_connect_ok`
- `mailops_mda_tls_ok`
- `mailops_mda_cert_days_remaining`

Example Prometheus alert ideas:

```promql
time() - mailops_last_check_timestamp_seconds > 900
mailops_status_code >= 2
mailops_smtp_open_relay == 1
mailops_smtp_tls_ok == 0
mailops_mda_tls_ok == 0
mailops_smtp_cert_days_remaining < 14
mailops_mta_sts_mx_matched_ratio < 1
mailops_domainbl_hits > 0
```

## Systemd Timer

Examples are in:

- `examples/systemd/mailops-example.service`
- `examples/systemd/mailops-example.timer`

Typical install:

```bash
sudo cp examples/systemd/mailops-example.service /etc/systemd/system/
sudo cp examples/systemd/mailops-example.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mailops-example.timer
```

Make sure `node_exporter` is started with:

```text
--collector.textfile.directory=/var/lib/node_exporter/textfile_collector
```

## Exit Codes

`--fail-on` controls when `mailops` exits non-zero:

```bash
mailops check example.com --fail-on warn
mailops check example.com --fail-on critical
mailops check example.com --fail-on error
```

Default:

```text
critical
```

| Code | Meaning |
| --- | --- |
| `0` | The aggregate status is below the configured `--fail-on` threshold. |
| `1` | The aggregate status reached the configured threshold. |
| `2` | The command, option, domain, or option value is invalid. |

`--strict` does not enable additional probes. It promotes selected findings:
DMARC `p=none`, missing or invalid MTA-STS and TLS-RPT, SMTP without STARTTLS,
and failures on requested MDA endpoints. This is useful for domains where
transport policy is mandatory rather than advisory.

## Development

The test suite uses in-memory DNS resolvers, protocol pipes, and HTTP transport
stubs, so it does not require external DNS, SMTP, IMAP, POP3, or OTLP services.

```bash
go test ./...
go test -race ./...
go vet ./...
go test -tags=integration -v ./integration
```

Generate a coverage report with:

```bash
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out
```

## Current Limitations and Roadmap

- SPF validation estimates DNS-triggering mechanisms and expands
  `include`/`redirect`, but it is not a complete SPF evaluator. It does not
  model macros, void-lookup limits, or every per-mechanism DNS limit.
- DKIM has no standardized selector discovery mechanism. Common selectors and
  provider profiles are best-effort; use `--selector` for authoritative
  results.
- BIMI parses the authority certificate and its validity period, but does not
  yet validate the complete VMC/CMC trust chain or the logo-hash extension.
- DNSSEC status trusts the selected validating recursive resolver's AD bit; it
  does not perform a local root-to-leaf cryptographic validation.
- SMTP TLS probing proves that a TLS 1.2+ session with a trusted certificate
  works. It does not enumerate accepted legacy protocol versions, cipher
  suites, or REQUIRETLS support.
- End-to-end inbox placement is not checked. That requires sending controlled
  messages to seed mailboxes and using credentials or provider APIs.
- SMTP open-relay probing stops before `DATA`; it detects RCPT acceptance, not
  final delivery.
- MDA probes do not log in, verify credentials, or read mailboxes.
- Public reputation DNS zones may rate-limit or block generic resolver usage.
- Provider profiles are operational defaults, not authoritative vendor APIs.
- The live integration suite verifies public DNS/policy discovery; it does not
  send mail or require mailbox credentials.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
