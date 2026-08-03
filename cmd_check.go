package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	mailcheck "github.com/systeampl/mailops/pkg/mailops"
	"gopkg.in/yaml.v3"
)

func runCheck(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{
		"--timeout":       true,
		"--fail-on":       true,
		"--otel-endpoint": true,
		"--resolver":      true,
		"--domains-file":  true,
		"--config":        true,
		"--profile":       true,
		"--selector":      true,
		"--rbl":           true,
		"--domainbl":      true,
		"--smtp-host":     true,
		"--smtp-port":     true,
		"--mda-host":      true,
		"--mda-port":      true,
	})
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	promOut := fs.Bool("prom", false, "emit Prometheus metrics")
	strict := fs.Bool("strict", false, "strict policy mode")
	noRBL := fs.Bool("no-rbl", false, "skip DNSBL checks")
	noDNSSEC := fs.Bool("no-dnssec", false, "skip DNSSEC authentication checks")
	noDANE := fs.Bool("no-dane", false, "skip TLSA/DANE discovery and certificate matching")
	reputation := fs.Bool("reputation", false, "check domain reputation lists such as DBL/SURBL/URIBL")
	smtp := fs.Bool("smtp", false, "check SMTP port 25, EHLO, STARTTLS, and certificate health for MX hosts")
	noOpenRelay := fs.Bool("no-open-relay", false, "skip unauthenticated open relay RCPT probe during --smtp checks")
	mda := fs.Bool("mda", false, "check IMAP/POP3 endpoint connect, capabilities, STARTTLS/STLS, and certificate health")
	timeoutText := fs.String("timeout", "10s", "overall timeout")
	failOn := fs.String("fail-on", "critical", "exit non-zero on warn, critical, or error")
	otelEndpoint := fs.String("otel-endpoint", "", "export OTLP/HTTP metrics endpoint")
	resolverAddress := fs.String("resolver", "", "DNS resolver IP or host:port")
	domainsFile := fs.String("domains-file", "", "read additional domains from a line-oriented file")
	configFile := fs.String("config", "", "read batch/check defaults from a YAML file")
	allowPrivateTargets := fs.Bool("allow-private-targets", false, "allow active probes to private, loopback, link-local, and special-use addresses")
	var profiles stringListFlag
	var selectors stringListFlag
	var rbls stringListFlag
	var domainBLs stringListFlag
	var smtpHosts stringListFlag
	var smtpPorts stringListFlag
	var mdaHosts stringListFlag
	var mdaPorts stringListFlag
	fs.Var(&profiles, "profile", "Provider profile; repeatable or comma-separated")
	fs.Var(&selectors, "selector", "DKIM selector; repeatable or comma-separated")
	fs.Var(&rbls, "rbl", "DNSBL zone; repeatable or comma-separated")
	fs.Var(&domainBLs, "domainbl", "Domain reputation DNSBL zone; repeatable or comma-separated")
	fs.Var(&smtpHosts, "smtp-host", "SMTP host for --smtp checks; repeatable or comma-separated")
	fs.Var(&smtpPorts, "smtp-port", "SMTP port for --smtp checks; repeatable or comma-separated")
	fs.Var(&mdaHosts, "mda-host", "IMAP/POP3 host for --mda checks; repeatable or comma-separated")
	fs.Var(&mdaPorts, "mda-port", "IMAP/POP3 port for --mda checks; repeatable or comma-separated")
	if err := fs.Parse(args); err != nil {
		fatal(err.Error())
	}
	config, err := loadCheckConfig(*configFile)
	if err != nil {
		fatal(err.Error())
	}
	visited := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })
	applyCheckConfig(config, visited, timeoutText, failOn, resolverAddress, domainsFile, strict, noRBL, noDNSSEC, noDANE, reputation, smtp, noOpenRelay, mda, allowPrivateTargets, &profiles, &selectors, &rbls, &domainBLs, &smtpHosts, &smtpPorts, &mdaHosts, &mdaPorts)
	domainArgs := append([]string(nil), fs.Args()...)
	domainArgs = append(domainArgs, config.Domains...)
	domains, err := collectDomains(domainArgs, *domainsFile)
	if err != nil {
		fatal(err.Error())
	}
	if len(domains) == 0 {
		fatal("usage: mailops check <domain...> [--domains-file path] [--json|--yaml|--prom]")
	}
	format, err := resolveOutput(*jsonOut, *yamlOut, *promOut)
	if err != nil {
		fatal(err.Error())
	}
	timeout, err := time.ParseDuration(*timeoutText)
	if err != nil {
		fatal("invalid --timeout: " + err.Error())
	}
	if timeout <= 0 {
		fatal("invalid --timeout: duration must be positive")
	}
	if !validFailOn(*failOn) {
		fatal("invalid --fail-on: expected warn, critical, or error")
	}
	ports, err := parsePorts(smtpPorts, nil)
	if err != nil {
		fatal("invalid --smtp-port: " + err.Error())
	}
	mdaPortValues, err := parsePorts(mdaPorts, nil)
	if err != nil {
		fatal("invalid --mda-port: " + err.Error())
	}
	selectorsExplicit := len(selectors) > 0
	mdaHostsExplicit := len(mdaHosts) > 0
	appliedProfiles, selectors, ports, smtpHosts, mdaPortValues, mdaHosts, err := applyProfiles(
		profiles,
		selectors,
		smtpHosts,
		ports,
		len(smtpPorts) > 0,
		mdaHosts,
		mdaPortValues,
		len(mdaPorts) > 0,
	)
	if err != nil {
		fatal(err.Error())
	}
	if len(ports) == 0 {
		ports = []int{25}
	}
	if len(mdaPortValues) == 0 {
		mdaPortValues = []int{143, 993, 110, 995}
	}
	reports := make([]mailcheck.Report, 0, len(domains))
	exitCode := 0
	for _, domain := range domains {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		report := mailcheck.Run(ctx, mailcheck.Options{
			Domain:              domain,
			Profiles:            appliedProfiles,
			DKIMSelectors:       selectors,
			DKIMExplicit:        selectorsExplicit,
			RBLServers:          rbls,
			DomainBLServers:     domainBLs,
			Timeout:             timeout,
			Strict:              *strict,
			CheckRBL:            !*noRBL,
			CheckReputation:     *reputation,
			CheckSMTP:           *smtp,
			SMTPHosts:           smtpHosts,
			SMTPPorts:           ports,
			CheckOpenRelay:      *smtp && !*noOpenRelay,
			CheckMDA:            *mda,
			MDAHosts:            mdaHosts,
			MDAExplicit:         mdaHostsExplicit,
			MDAPorts:            mdaPortValues,
			ResolverAddress:     *resolverAddress,
			AllowPrivateTargets: *allowPrivateTargets,
			DisableDNSSEC:       *noDNSSEC,
			DisableDANE:         *noDANE,
		})
		cancel()
		reports = append(reports, report)
		if code := reportExitCode(report, *failOn); code > exitCode {
			exitCode = code
		}
	}
	exportCtx, exportCancel := context.WithTimeout(context.Background(), timeout)
	defer exportCancel()
	if err := exportReportsOTEL(exportCtx, *otelEndpoint, reports); err != nil {
		fmt.Fprintln(os.Stderr, "mailops: otel export:", err)
	}
	printReports(reports, format)
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

type checkFileConfig struct {
	Domains             []string `yaml:"domains"`
	DomainsFile         string   `yaml:"domains_file"`
	Timeout             string   `yaml:"timeout"`
	FailOn              string   `yaml:"fail_on"`
	Resolver            string   `yaml:"resolver"`
	Strict              bool     `yaml:"strict"`
	NoRBL               bool     `yaml:"no_rbl"`
	NoDNSSEC            bool     `yaml:"no_dnssec"`
	NoDANE              bool     `yaml:"no_dane"`
	Reputation          bool     `yaml:"reputation"`
	SMTP                bool     `yaml:"smtp"`
	NoOpenRelay         bool     `yaml:"no_open_relay"`
	MDA                 bool     `yaml:"mda"`
	AllowPrivateTargets bool     `yaml:"allow_private_targets"`
	Profiles            []string `yaml:"profiles"`
	Selectors           []string `yaml:"selectors"`
	RBLs                []string `yaml:"rbls"`
	DomainBLs           []string `yaml:"domain_bls"`
	SMTPHosts           []string `yaml:"smtp_hosts"`
	SMTPPorts           []int    `yaml:"smtp_ports"`
	MDAHosts            []string `yaml:"mda_hosts"`
	MDAPorts            []int    `yaml:"mda_ports"`
}

func loadCheckConfig(filename string) (checkFileConfig, error) {
	var config checkFileConfig
	if strings.TrimSpace(filename) == "" {
		return config, nil
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return config, fmt.Errorf("read --config: %w", err)
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("parse --config: %w", err)
	}
	return config, nil
}

func applyCheckConfig(config checkFileConfig, visited map[string]bool, timeoutText, failOn, resolverAddress, domainsFile *string, strict, noRBL, noDNSSEC, noDANE, reputation, smtp, noOpenRelay, mda, allowPrivateTargets *bool, profiles, selectors, rbls, domainBLs, smtpHosts, smtpPorts, mdaHosts, mdaPorts *stringListFlag) {
	if !visited["timeout"] && config.Timeout != "" {
		*timeoutText = config.Timeout
	}
	if !visited["fail-on"] && config.FailOn != "" {
		*failOn = config.FailOn
	}
	if !visited["resolver"] && config.Resolver != "" {
		*resolverAddress = config.Resolver
	}
	if !visited["domains-file"] && config.DomainsFile != "" {
		*domainsFile = config.DomainsFile
	}
	if !visited["strict"] && config.Strict {
		*strict = true
	}
	if !visited["no-rbl"] && config.NoRBL {
		*noRBL = true
	}
	if !visited["no-dnssec"] && config.NoDNSSEC {
		*noDNSSEC = true
	}
	if !visited["no-dane"] && config.NoDANE {
		*noDANE = true
	}
	if !visited["reputation"] && config.Reputation {
		*reputation = true
	}
	if !visited["smtp"] && config.SMTP {
		*smtp = true
	}
	if !visited["no-open-relay"] && config.NoOpenRelay {
		*noOpenRelay = true
	}
	if !visited["mda"] && config.MDA {
		*mda = true
	}
	if !visited["allow-private-targets"] && config.AllowPrivateTargets {
		*allowPrivateTargets = true
	}
	applyStringConfig := func(name string, destination *stringListFlag, values []string) {
		if !visited[name] && len(values) > 0 {
			*destination = append((*destination)[:0], values...)
		}
	}
	applyPortConfig := func(name string, destination *stringListFlag, values []int) {
		if visited[name] || len(values) == 0 {
			return
		}
		*destination = (*destination)[:0]
		for _, port := range values {
			*destination = append(*destination, strconv.Itoa(port))
		}
	}
	applyStringConfig("profile", profiles, config.Profiles)
	applyStringConfig("selector", selectors, config.Selectors)
	applyStringConfig("rbl", rbls, config.RBLs)
	applyStringConfig("domainbl", domainBLs, config.DomainBLs)
	applyStringConfig("smtp-host", smtpHosts, config.SMTPHosts)
	applyPortConfig("smtp-port", smtpPorts, config.SMTPPorts)
	applyStringConfig("mda-host", mdaHosts, config.MDAHosts)
	applyPortConfig("mda-port", mdaPorts, config.MDAPorts)
}

func collectDomains(args []string, filename string) ([]string, error) {
	values := append([]string(nil), args...)
	if strings.TrimSpace(filename) != "" {
		data, err := os.ReadFile(filename)
		if err != nil {
			return nil, fmt.Errorf("read --domains-file: %w", err)
		}
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				values = append(values, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("read --domains-file: %w", err)
		}
	}
	seen := map[string]bool{}
	domains := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		domains = append(domains, value)
	}
	return domains, nil
}

func reportExitCode(report mailcheck.Report, failOn string) int {
	for _, finding := range report.Findings {
		if finding.Scope == "input" && finding.Severity == mailcheck.SeverityError {
			return 2
		}
	}
	if failOnStatus(report.Status, failOn) {
		return 1
	}
	return 0
}

func printReports(reports []mailcheck.Report, format outputFormat) {
	switch format {
	case outputJSON:
		printJSON(reports)
	case outputYAML:
		printYAMLReports(reports)
	case outputProm:
		printPromReports(reports)
	default:
		for _, report := range reports {
			printRawReport(report)
		}
	}
}

func printRawReport(report mailcheck.Report) {
	fmt.Printf("%s  mail report\n", report.Domain)
	fmt.Printf("resolver: %s\n", report.Resolver)
	if len(report.Profiles) > 0 {
		fmt.Printf("profiles: %s\n", strings.Join(report.Profiles, ", "))
	}
	fmt.Printf("status: %s\n", statusColor(report.Status))
	fmt.Printf("posture: %s\n", statusColor(report.PostureStatus))
	fmt.Printf("availability: %s\n", statusColor(report.AvailabilityStatus))
	if report.Error != "" {
		fmt.Printf("error: %s\n", report.Error)
	}
	fmt.Println()

	rows := [][]string{
		{"mx", "records", fmt.Sprintf("%d", report.RecordCounts.MX), statusColor(okCritical(report.RecordCounts.MX > 0))},
		{"mx", "hosts", compactMX(report.MX, 3), "info"},
		{"spf", "record", statusColor(yesNo(report.SPF.Present)), statusColor(okCritical(report.SPF.Present && report.SPF.Valid))},
		{"spf", "lookups", fmt.Sprintf("%d", report.SPF.EstimatedLookups), statusColor(spfLookupStatus(report.SPF.EstimatedLookups))},
		{"spf", "all", emptyDash(report.SPF.AllMechanism), statusColor(spfAllStatus(report.SPF.AllMechanism))},
		{"dmarc", "policy", statusColor(emptyDash(report.DMARC.EffectivePolicy)), statusColor(dmarcPolicyStatus(report.DMARC.EffectivePolicy))},
		{"dmarc", "source", emptyDash(report.DMARC.PolicyDomain), "info"},
		{"dmarc", "rua", fmt.Sprintf("%d", len(report.DMARC.RUA)), statusColor(okWarn(len(report.DMARC.RUA) > 0))},
		{"dnssec", "authenticated", yesNo(report.DNSSEC.Secure), statusColor(okWarn(report.DNSSEC.Secure))},
		{"dane", "tlsa", daneCell(report), statusColor(daneStatus(report))},
		{"dkim", "valid_selectors", fmt.Sprintf("%d/%d", report.RecordCounts.DKIM, len(report.DKIM)), statusColor(dkimStatus(report))},
		{"mta-sts", "policy", mtaSTSCell(report), statusColor(mtaSTSStatus(report))},
		{"mta-sts", "mx_covered", mtaSTSMXCell(report), statusColor(mtaSTSMXStatus(report))},
		{"tls-rpt", "record", statusColor(yesNo(report.TLSRPT.Present)), statusColor(okWarn(report.TLSRPT.Present && report.TLSRPT.Valid))},
		{"bimi", "record", statusColor(yesNo(report.BIMI.Present)), bimiStatus(report)},
		{"ptr", "forward_confirmed", ptrCell(report), statusColor(ptrStatus(report))},
		{"rbl", "listings", fmt.Sprintf("%d", report.RecordCounts.RBLHits), statusColor(rblStatus(report))},
		{"reputation", "domainbl", reputationCell(report), statusColor(reputationStatus(report))},
		{"smtp", "transport", smtpCell(report), statusColor(smtpStatus(report))},
		{"smtp", "tls", smtpTLSCell(report), statusColor(smtpTLSStatus(report))},
		{"smtp", "auth", smtpAuthCell(report), statusColor(smtpAuthStatus(report))},
		{"smtp", "open_relay", smtpOpenRelayCell(report), statusColor(smtpOpenRelayStatus(report))},
		{"smtp", "cert_days", smtpCertDaysCell(report), statusColor(smtpCertDaysStatus(report))},
		{"mda", "transport", mdaCell(report), statusColor(mdaStatus(report))},
		{"mda", "tls", mdaTLSCell(report), statusColor(mdaTLSStatus(report))},
		{"mda", "cert_days", mdaCertDaysCell(report), statusColor(mdaCertDaysStatus(report))},
		{"runtime", "duration_ms", fmt.Sprintf("%d", report.DurationMS), "info"},
	}
	renderTable([]string{"scope", "check", "value", "status"}, rows)

	fmt.Println()
	renderFindings(report.Findings)
	fmt.Printf("\nsummary: status=%s, findings=%d warn=%d critical=%d error=%d\n",
		statusColor(report.Status),
		len(report.Findings),
		report.Summary.Warn,
		report.Summary.Critical,
		report.Summary.Error,
	)
}

func daneCell(report mailcheck.Report) string {
	present := 0
	for _, row := range report.DANE {
		if row.Present {
			present++
		}
	}
	return fmt.Sprintf("%d/%d", present, len(report.DANE))
}

func daneStatus(report mailcheck.Report) string {
	for _, row := range report.DANE {
		if row.Present && !row.Valid {
			return "critical"
		}
		if row.Error != "" {
			return "warn"
		}
	}
	return "ok"
}

func renderFindings(findings []mailcheck.Finding) {
	fmt.Println("findings:")
	if len(findings) == 0 {
		fmt.Println("  none")
		return
	}
	rows := make([][]string, 0, len(findings))
	for _, finding := range findings {
		rows = append(rows, []string{statusColor(finding.Severity), finding.Scope, finding.Message})
	}
	renderTable([]string{"severity", "scope", "message"}, rows)
}

func okCritical(ok bool) string {
	if ok {
		return "ok"
	}
	return "critical"
}

func okWarn(ok bool) string {
	if ok {
		return "ok"
	}
	return "warn"
}

func spfLookupStatus(count int) string {
	if count > 10 {
		return "critical"
	}
	if count >= 8 {
		return "warn"
	}
	return "ok"
}

func spfAllStatus(value string) string {
	switch value {
	case "+all":
		return "critical"
	case "?all", "~all", "":
		return "warn"
	default:
		return "ok"
	}
}

func dmarcPolicyStatus(policy string) string {
	switch policy {
	case "reject", "quarantine":
		return "ok"
	case "none":
		return "warn"
	default:
		return "critical"
	}
}

func dkimStatus(report mailcheck.Report) string {
	if report.RecordCounts.DKIM > 0 {
		return "ok"
	}
	if findingSeverity(report.Findings, "dkim") == "warn" {
		return "warn"
	}
	return "info"
}

func mtaSTSCell(report mailcheck.Report) string {
	if report.MTASTS.Error != "" {
		return "error"
	}
	if !report.MTASTS.TXTPresent {
		return "missing"
	}
	if report.MTASTS.Mode != "" {
		return report.MTASTS.Mode
	}
	return "present"
}

func mtaSTSStatus(report mailcheck.Report) string {
	if report.MTASTS.Error != "" {
		return "warn"
	}
	if report.MTASTS.Mode == "enforce" {
		return "ok"
	}
	if report.MTASTS.TXTPresent {
		return "warn"
	}
	return "warn"
}

func mtaSTSMXCell(report mailcheck.Report) string {
	if !report.MTASTS.Valid || report.MTASTS.MXTotal == 0 {
		return "-"
	}
	return fmt.Sprintf("%d/%d", report.MTASTS.MXMatched, report.MTASTS.MXTotal)
}

func mtaSTSMXStatus(report mailcheck.Report) string {
	if !report.MTASTS.Valid || report.MTASTS.MXTotal == 0 {
		return "info"
	}
	if report.MTASTS.MXMatched == report.MTASTS.MXTotal {
		return "ok"
	}
	return "warn"
}

func bimiStatus(report mailcheck.Report) string {
	if !report.BIMI.Present {
		return statusColor("info")
	}
	if report.BIMI.Valid && report.BIMI.Warning == "" {
		return statusColor("ok")
	}
	return statusColor("warn")
}

func ptrCell(report mailcheck.Report) string {
	if len(report.PTR) == 0 {
		return "0/0"
	}
	ok := 0
	for _, row := range report.PTR {
		if row.ForwardConfirmed {
			ok++
		}
	}
	return fmt.Sprintf("%d/%d", ok, len(report.PTR))
}

func ptrStatus(report mailcheck.Report) string {
	if len(report.PTR) == 0 {
		return "info"
	}
	for _, row := range report.PTR {
		if !row.ForwardConfirmed {
			return "warn"
		}
	}
	return "ok"
}

func rblStatus(report mailcheck.Report) string {
	if len(report.RBL) == 0 {
		return "info"
	}
	if report.RecordCounts.RBLHits > 0 {
		return "critical"
	}
	for _, row := range report.RBL {
		if len(row.Errors) > 0 {
			return "warn"
		}
	}
	return "ok"
}

func reputationCell(report mailcheck.Report) string {
	if len(report.DomainBL) == 0 {
		return "disabled"
	}
	checked := 0
	for _, row := range report.DomainBL {
		checked += len(row.CleanOn) + len(row.ListedOn) + len(row.ErrorOn)
	}
	return fmt.Sprintf("%d/%d listed", report.RecordCounts.DomainBLHits, checked)
}

func reputationStatus(report mailcheck.Report) string {
	if len(report.DomainBL) == 0 {
		return "info"
	}
	if report.RecordCounts.DomainBLHits > 0 {
		return "critical"
	}
	for _, row := range report.DomainBL {
		if len(row.Errors) > 0 {
			return "warn"
		}
	}
	return "ok"
}

func smtpCell(report mailcheck.Report) string {
	if len(report.SMTP) == 0 {
		return "disabled"
	}
	ok := 0
	for _, row := range report.SMTP {
		if row.ConnectOK {
			ok++
		}
	}
	return fmt.Sprintf("%d/%d", ok, len(report.SMTP))
}

func smtpStatus(report mailcheck.Report) string {
	if len(report.SMTP) == 0 {
		return "info"
	}
	for _, row := range report.SMTP {
		if !row.ConnectOK {
			return "critical"
		}
	}
	return "ok"
}

func smtpTLSCell(report mailcheck.Report) string {
	if len(report.SMTP) == 0 {
		return "disabled"
	}
	ok := 0
	for _, row := range report.SMTP {
		if row.TLSOK {
			ok++
		}
	}
	return fmt.Sprintf("%d/%d", ok, len(report.SMTP))
}

func smtpTLSStatus(report mailcheck.Report) string {
	if len(report.SMTP) == 0 {
		return "info"
	}
	for _, row := range report.SMTP {
		if row.Error != "" {
			return "critical"
		}
		if !row.TLSOK {
			return "warn"
		}
	}
	return "ok"
}

func smtpCertDaysCell(report mailcheck.Report) string {
	if len(report.SMTP) == 0 {
		return "disabled"
	}
	minDays := 0
	seen := false
	for _, row := range report.SMTP {
		if row.CertDaysRemaining == 0 && row.CertNotAfter.IsZero() {
			continue
		}
		if !seen || row.CertDaysRemaining < minDays {
			minDays = row.CertDaysRemaining
			seen = true
		}
	}
	if !seen {
		return "-"
	}
	return fmt.Sprintf("%d", minDays)
}

func smtpAuthCell(report mailcheck.Report) string {
	if len(report.SMTP) == 0 {
		return "disabled"
	}
	total := 0
	for _, row := range report.SMTP {
		total += len(row.AuthMechanisms)
	}
	return fmt.Sprintf("%d", total)
}

func smtpAuthStatus(report mailcheck.Report) string {
	if len(report.SMTP) == 0 {
		return "info"
	}
	for _, row := range report.SMTP {
		if (row.Port == 465 || row.Port == 587) && len(row.AuthMechanisms) == 0 {
			return "warn"
		}
	}
	return "ok"
}

func smtpOpenRelayCell(report mailcheck.Report) string {
	if len(report.SMTP) == 0 {
		return "disabled"
	}
	checked := 0
	open := 0
	for _, row := range report.SMTP {
		if row.RelayCheck {
			checked++
		}
		if row.OpenRelay {
			open++
		}
	}
	if checked == 0 {
		return "disabled"
	}
	if open > 0 {
		return fmt.Sprintf("%d/%d open", open, checked)
	}
	return fmt.Sprintf("0/%d open", checked)
}

func smtpOpenRelayStatus(report mailcheck.Report) string {
	if len(report.SMTP) == 0 {
		return "info"
	}
	checked := false
	for _, row := range report.SMTP {
		if row.OpenRelay {
			return "critical"
		}
		if row.RelayCheck {
			checked = true
		}
	}
	if !checked {
		return "info"
	}
	return "ok"
}

func smtpCertDaysStatus(report mailcheck.Report) string {
	if len(report.SMTP) == 0 {
		return "info"
	}
	cell := smtpCertDaysCell(report)
	if cell == "-" {
		return "info"
	}
	days := 0
	if _, err := fmt.Sscanf(cell, "%d", &days); err != nil {
		return "info"
	}
	if days < 0 {
		return "critical"
	}
	if days < 14 {
		return "warn"
	}
	return "ok"
}

func mdaCell(report mailcheck.Report) string {
	if len(report.MDA) == 0 {
		return "disabled"
	}
	ok := 0
	for _, row := range report.MDA {
		if row.ConnectOK {
			ok++
		}
	}
	return fmt.Sprintf("%d/%d", ok, len(report.MDA))
}

func mdaStatus(report mailcheck.Report) string {
	if len(report.MDA) == 0 {
		return "info"
	}
	for _, row := range report.MDA {
		if !row.ConnectOK {
			return "warn"
		}
	}
	return "ok"
}

func mdaTLSCell(report mailcheck.Report) string {
	if len(report.MDA) == 0 {
		return "disabled"
	}
	ok := 0
	for _, row := range report.MDA {
		if row.TLSOK {
			ok++
		}
	}
	return fmt.Sprintf("%d/%d", ok, len(report.MDA))
}

func mdaTLSStatus(report mailcheck.Report) string {
	if len(report.MDA) == 0 {
		return "info"
	}
	for _, row := range report.MDA {
		if row.Error != "" {
			return "warn"
		}
		if !row.TLSOK && row.Port != 110 && row.Port != 143 {
			return "warn"
		}
	}
	return "ok"
}

func mdaCertDaysCell(report mailcheck.Report) string {
	if len(report.MDA) == 0 {
		return "disabled"
	}
	minDays := 0
	seen := false
	for _, row := range report.MDA {
		if row.CertDaysRemaining == 0 && row.CertNotAfter.IsZero() {
			continue
		}
		if !seen || row.CertDaysRemaining < minDays {
			minDays = row.CertDaysRemaining
			seen = true
		}
	}
	if !seen {
		return "-"
	}
	return fmt.Sprintf("%d", minDays)
}

func mdaCertDaysStatus(report mailcheck.Report) string {
	if len(report.MDA) == 0 {
		return "info"
	}
	cell := mdaCertDaysCell(report)
	if cell == "-" {
		return "info"
	}
	days := 0
	if _, err := fmt.Sscanf(cell, "%d", &days); err != nil {
		return "info"
	}
	if days < 0 {
		return "critical"
	}
	if days < 14 {
		return "warn"
	}
	return "ok"
}

func findingSeverity(findings []mailcheck.Finding, scope string) string {
	best := "info"
	rank := map[string]int{"info": 0, "warn": 1, "critical": 2, "error": 3}
	for _, finding := range findings {
		if finding.Scope != scope {
			continue
		}
		if rank[finding.Severity] > rank[best] {
			best = finding.Severity
		}
	}
	return best
}

func compactMX(mx []mailcheck.MXRecord, limit int) string {
	if len(mx) == 0 {
		return "-"
	}
	values := make([]string, 0, len(mx))
	for _, row := range mx {
		values = append(values, row.Host)
	}
	if len(values) <= limit {
		return strings.Join(values, ", ")
	}
	return strings.Join(values[:limit], ", ") + fmt.Sprintf(" +%d more", len(values)-limit)
}

func parsePorts(values []string, defaults []int) ([]int, error) {
	if len(values) == 0 {
		return defaults, nil
	}
	seen := map[int]bool{}
	ports := make([]int, 0, len(values))
	for _, value := range values {
		port, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return nil, err
		}
		if port <= 0 || port > 65535 {
			return nil, fmt.Errorf("%d is outside 1-65535", port)
		}
		if !seen[port] {
			seen[port] = true
			ports = append(ports, port)
		}
	}
	return ports, nil
}
