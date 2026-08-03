package main

import (
	"fmt"
	"os"
)

var version = "0.2.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	switch os.Args[1] {
	case "check":
		runCheck(os.Args[2:])
	case "version":
		fmt.Println("mailops", version)
	case "help", "-h", "--help":
		usage()
	default:
		fatal("unknown command: " + os.Args[1])
	}
}

func usage() {
	fmt.Println(`mailops - mail deliverability and email security operations checks

Usage:
  mailops check <domain...> [--json|--yaml|--prom] [options]
  mailops version

Commands:
  check      Run mail DNS, policy, DNSSEC/DANE, reputation and endpoint checks

Common options:
  --profile <name>        Provider profile, e.g. google-workspace, microsoft-365
  --selector <name>       DKIM selector to check; repeatable or comma-separated
  --rbl <zone>            DNSBL zone to query; repeatable or comma-separated
  --no-rbl                Skip RBL checks
  --no-dnssec             Skip DNSSEC authentication checks
  --no-dane               Skip TLSA/DANE discovery and certificate matching
  --reputation            Check domain reputation lists such as DBL/SURBL/URIBL
  --domainbl <zone>       Domain reputation DNSBL zone; repeatable/comma-separated
  --smtp                  Check SMTP connect, EHLO, STARTTLS, and certificate health
  --smtp-host <host>      SMTP host for --smtp; repeatable/comma-separated
  --smtp-port <port>      SMTP port for --smtp checks; repeatable/comma-separated
  --no-open-relay         Skip unauthenticated open relay RCPT probe during --smtp
  --mda                   Check IMAP/POP3 connect, capabilities, TLS, and certificate health
  --mda-host <host>       IMAP/POP3 host for --mda; repeatable/comma-separated
  --mda-port <port>       IMAP/POP3 port for --mda; repeatable/comma-separated
  --resolver <address>    DNS resolver IP or host:port
  --domains-file <path>   Read additional domains, one per line
  --config <path>         Read batch/check defaults from YAML
  --allow-private-targets Permit active probes to private/special-use addresses
  --strict                Treat missing MTA-STS/TLS-RPT and weak DMARC harder
  --timeout <duration>    Overall timeout, e.g. 10s
  --fail-on <level>       Exit non-zero on warn, critical, or error (default critical)
  --otel-endpoint <url>   Export OTLP/HTTP metrics, e.g. http://localhost:4318
  --json                  Emit JSON
  --yaml                  Emit YAML
  --prom                  Emit Prometheus metrics`)
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "mailops:", msg)
	os.Exit(2)
}
