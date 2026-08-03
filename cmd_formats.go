package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	mailcheck "github.com/systeampl/mailops/pkg/mailops"
)

func printYAMLReports(reports []mailcheck.Report) {
	payload := struct {
		Reports []mailcheck.Report `yaml:"reports"`
	}{Reports: reports}
	data, err := yaml.Marshal(payload)
	if err != nil {
		fatal(err.Error())
	}
	fmt.Print(string(data))
}

func printPromReports(reports []mailcheck.Report) {
	fmt.Println("# HELP mailops_check_up Mailops check execution health (1=check completed, 0=tool/input error).")
	fmt.Println("# TYPE mailops_check_up gauge")
	fmt.Println("# HELP mailops_check_duration_seconds Mailops check duration in seconds.")
	fmt.Println("# TYPE mailops_check_duration_seconds gauge")
	fmt.Println("# HELP mailops_last_check_timestamp_seconds Unix timestamp of the last completed check.")
	fmt.Println("# TYPE mailops_last_check_timestamp_seconds gauge")
	fmt.Println("# HELP mailops_status_code Aggregate status as a numeric code (0=ok, 1=warn, 2=critical, 3=error).")
	fmt.Println("# TYPE mailops_status_code gauge")
	fmt.Println("# HELP mailops_status Mail deliverability aggregate status (1=current status, 0=otherwise).")
	fmt.Println("# TYPE mailops_status gauge")
	fmt.Println("# HELP mailops_posture_status_code Configuration posture status (0=ok, 1=warn, 2=critical, 3=error).")
	fmt.Println("# TYPE mailops_posture_status_code gauge")
	fmt.Println("# HELP mailops_availability_status_code Active service availability status (0=ok/not checked, 1=warn, 2=critical, 3=error).")
	fmt.Println("# TYPE mailops_availability_status_code gauge")
	fmt.Println("# HELP mailops_findings Number of findings by severity.")
	fmt.Println("# TYPE mailops_findings gauge")
	fmt.Println("# HELP mailops_record_present Presence of key mail records (1=present, 0=missing).")
	fmt.Println("# TYPE mailops_record_present gauge")
	fmt.Println("# HELP mailops_record_valid Validity of key mail records (1=valid, 0=missing/invalid).")
	fmt.Println("# TYPE mailops_record_valid gauge")
	fmt.Println("# HELP mailops_mx_records Number of MX records.")
	fmt.Println("# TYPE mailops_mx_records gauge")
	fmt.Println("# HELP mailops_spf_estimated_lookups Estimated SPF lookup count after include/redirect expansion.")
	fmt.Println("# TYPE mailops_spf_estimated_lookups gauge")
	fmt.Println("# HELP mailops_spf_lookup_limit_used SPF DNS lookup limit utilization, where 1.0 means 10 lookups.")
	fmt.Println("# TYPE mailops_spf_lookup_limit_used gauge")
	fmt.Println("# HELP mailops_dmarc_pct DMARC pct tag value.")
	fmt.Println("# TYPE mailops_dmarc_pct gauge")
	fmt.Println("# HELP mailops_dnssec_secure DNS response authentication through DNSSEC (1=authenticated, 0=not authenticated/error).")
	fmt.Println("# TYPE mailops_dnssec_secure gauge")
	fmt.Println("# HELP mailops_dane_tlsa_present TLSA record presence per mail endpoint (1=present, 0=absent).")
	fmt.Println("# TYPE mailops_dane_tlsa_present gauge")
	fmt.Println("# HELP mailops_dane_tlsa_valid TLSA record syntax and DNSSEC validity per mail endpoint (1=valid, 0=invalid/absent).")
	fmt.Println("# TYPE mailops_dane_tlsa_valid gauge")
	fmt.Println("# HELP mailops_dane_tlsa_matched Observed SMTP certificate match against TLSA (1=matched, 0=not matched/not observed).")
	fmt.Println("# TYPE mailops_dane_tlsa_matched gauge")
	fmt.Println("# HELP mailops_dkim_valid_selectors Number of valid DKIM selectors found.")
	fmt.Println("# TYPE mailops_dkim_valid_selectors gauge")
	fmt.Println("# HELP mailops_dkim_selector_ok DKIM selector health (1=ok, 0=missing/error).")
	fmt.Println("# TYPE mailops_dkim_selector_ok gauge")
	fmt.Println("# HELP mailops_mta_sts_mx_matched_ratio Ratio of MX hosts covered by the MTA-STS policy mx patterns.")
	fmt.Println("# TYPE mailops_mta_sts_mx_matched_ratio gauge")
	fmt.Println("# HELP mailops_ptr_records Number of MX IPs checked for PTR.")
	fmt.Println("# TYPE mailops_ptr_records gauge")
	fmt.Println("# HELP mailops_ptr_forward_confirmed_ratio Ratio of MX IPs with forward-confirmed PTR.")
	fmt.Println("# TYPE mailops_ptr_forward_confirmed_ratio gauge")
	fmt.Println("# HELP mailops_rbl_hits Number of DNSBL listings across checked MX IPs.")
	fmt.Println("# TYPE mailops_rbl_hits gauge")
	fmt.Println("# HELP mailops_rbl_listed DNSBL listing status per IP (1=listed, 0=not listed).")
	fmt.Println("# TYPE mailops_rbl_listed gauge")
	fmt.Println("# HELP mailops_rbl_lookup_error DNSBL lookup or provider response error per IP and zone (1=error, 0=no error).")
	fmt.Println("# TYPE mailops_rbl_lookup_error gauge")
	fmt.Println("# HELP mailops_domainbl_hits Number of domain reputation DNSBL listings.")
	fmt.Println("# TYPE mailops_domainbl_hits gauge")
	fmt.Println("# HELP mailops_domainbl_listed Domain reputation DNSBL listing status per zone (1=listed, 0=not listed).")
	fmt.Println("# TYPE mailops_domainbl_listed gauge")
	fmt.Println("# HELP mailops_domainbl_lookup_error Domain reputation DNSBL lookup error per zone (1=error, 0=no error).")
	fmt.Println("# TYPE mailops_domainbl_lookup_error gauge")
	fmt.Println("# HELP mailops_smtp_probe_checked Number of SMTP host:port probes checked.")
	fmt.Println("# TYPE mailops_smtp_probe_checked gauge")
	fmt.Println("# HELP mailops_smtp_connect_ok SMTP TCP connect health per MX host (1=ok, 0=failed).")
	fmt.Println("# TYPE mailops_smtp_connect_ok gauge")
	fmt.Println("# HELP mailops_smtp_starttls_offered SMTP STARTTLS advertisement per MX host (1=offered, 0=missing).")
	fmt.Println("# TYPE mailops_smtp_starttls_offered gauge")
	fmt.Println("# HELP mailops_smtp_starttls_ok SMTP STARTTLS handshake health per MX host (1=ok, 0=failed/missing).")
	fmt.Println("# TYPE mailops_smtp_starttls_ok gauge")
	fmt.Println("# HELP mailops_smtp_tls_ok SMTP TLS health per MX host and port, including implicit TLS on 465 (1=ok, 0=failed/missing).")
	fmt.Println("# TYPE mailops_smtp_tls_ok gauge")
	fmt.Println("# HELP mailops_smtp_auth_mechanisms Number of SMTP AUTH mechanisms advertised per host and port.")
	fmt.Println("# TYPE mailops_smtp_auth_mechanisms gauge")
	fmt.Println("# HELP mailops_smtp_open_relay_checked SMTP unauthenticated external relay RCPT probe execution per host and port (1=checked, 0=not checked).")
	fmt.Println("# TYPE mailops_smtp_open_relay_checked gauge")
	fmt.Println("# HELP mailops_smtp_open_relay SMTP unauthenticated external relay acceptance per host and port (1=open relay risk, 0=not accepted/not checked).")
	fmt.Println("# TYPE mailops_smtp_open_relay gauge")
	fmt.Println("# HELP mailops_smtp_relay_mail_code SMTP response code from unauthenticated external relay MAIL FROM probe.")
	fmt.Println("# TYPE mailops_smtp_relay_mail_code gauge")
	fmt.Println("# HELP mailops_smtp_relay_rcpt_code SMTP response code from unauthenticated external relay RCPT probe.")
	fmt.Println("# TYPE mailops_smtp_relay_rcpt_code gauge")
	fmt.Println("# HELP mailops_smtp_cert_days_remaining SMTP TLS leaf certificate days remaining per MX host.")
	fmt.Println("# TYPE mailops_smtp_cert_days_remaining gauge")
	fmt.Println("# HELP mailops_mda_endpoint_checked Number of IMAP/POP3 endpoints checked.")
	fmt.Println("# TYPE mailops_mda_endpoint_checked gauge")
	fmt.Println("# HELP mailops_mda_connect_ok IMAP/POP3 TCP connect health per endpoint (1=ok, 0=failed).")
	fmt.Println("# TYPE mailops_mda_connect_ok gauge")
	fmt.Println("# HELP mailops_mda_tls_ok IMAP/POP3 TLS or STARTTLS/STLS handshake health per endpoint (1=ok, 0=failed/missing).")
	fmt.Println("# TYPE mailops_mda_tls_ok gauge")
	fmt.Println("# HELP mailops_mda_starttls_offered IMAP STARTTLS or POP3 STLS advertisement per plaintext endpoint (1=offered, 0=missing).")
	fmt.Println("# TYPE mailops_mda_starttls_offered gauge")
	fmt.Println("# HELP mailops_mda_cert_days_remaining IMAP/POP3 leaf certificate days remaining per endpoint.")
	fmt.Println("# TYPE mailops_mda_cert_days_remaining gauge")
	for _, report := range reports {
		base := map[string]string{"domain": report.Domain}
		fmt.Printf("mailops_check_up{%s} %d\n", promLabels(base), boolInt(report.Error == "" && report.Status != mailcheck.SeverityError))
		fmt.Printf("mailops_check_duration_seconds{%s} %.3f\n", promLabels(base), float64(report.DurationMS)/1000)
		fmt.Printf("mailops_last_check_timestamp_seconds{%s} %d\n", promLabels(base), report.GeneratedAt.Unix())
		fmt.Printf("mailops_status_code{%s} %d\n", promLabels(base), statusCode(report.Status))
		fmt.Printf("mailops_posture_status_code{%s} %d\n", promLabels(base), statusCode(report.PostureStatus))
		fmt.Printf("mailops_availability_status_code{%s} %d\n", promLabels(base), statusCode(report.AvailabilityStatus))
		for _, status := range []string{"ok", "warn", "critical", "error"} {
			fmt.Printf("mailops_status{%s} %d\n", promLabels(map[string]string{
				"domain": report.Domain,
				"status": status,
			}), boolInt(report.Status == status))
		}
		for _, sev := range []string{"info", "warn", "critical", "error"} {
			fmt.Printf("mailops_findings{%s} %d\n", promLabels(map[string]string{
				"domain":   report.Domain,
				"severity": sev,
			}), findingCount(report, sev))
		}
		fmt.Printf("mailops_mx_records{%s} %d\n", promLabels(base), report.RecordCounts.MX)
		fmt.Printf("mailops_dnssec_secure{%s} %d\n", promLabels(base), boolInt(report.DNSSEC.Secure))
		for _, row := range report.DANE {
			labels := map[string]string{"domain": report.Domain, "host": row.Host, "port": strconv.Itoa(row.Port)}
			fmt.Printf("mailops_dane_tlsa_present{%s} %d\n", promLabels(labels), boolInt(row.Present))
			fmt.Printf("mailops_dane_tlsa_valid{%s} %d\n", promLabels(labels), boolInt(row.Valid))
			fmt.Printf("mailops_dane_tlsa_matched{%s} %d\n", promLabels(labels), boolInt(row.Matched))
		}
		for _, record := range []struct {
			name string
			ok   bool
		}{
			{"spf", report.SPF.Present},
			{"dmarc", report.DMARC.Present},
			{"mta_sts", report.MTASTS.TXTPresent},
			{"tls_rpt", report.TLSRPT.Present},
			{"bimi", report.BIMI.Present},
		} {
			fmt.Printf("mailops_record_present{%s} %d\n", promLabels(map[string]string{
				"domain": report.Domain,
				"record": record.name,
			}), boolInt(record.ok))
		}
		for _, record := range []struct {
			name  string
			valid bool
		}{
			{"spf", report.SPF.Valid},
			{"dmarc", report.DMARC.Valid},
			{"mta_sts", report.MTASTS.Valid},
			{"tls_rpt", report.TLSRPT.Valid},
			{"bimi", report.BIMI.Valid},
		} {
			fmt.Printf("mailops_record_valid{%s} %d\n", promLabels(map[string]string{
				"domain": report.Domain,
				"record": record.name,
			}), boolInt(record.valid))
		}
		fmt.Printf("mailops_spf_estimated_lookups{%s} %d\n", promLabels(base), report.SPF.EstimatedLookups)
		fmt.Printf("mailops_spf_lookup_limit_used{%s} %.2f\n", promLabels(base), float64(report.SPF.EstimatedLookups)/10)
		fmt.Printf("mailops_dmarc_pct{%s} %d\n", promLabels(base), report.DMARC.Pct)
		fmt.Printf("mailops_dkim_valid_selectors{%s} %d\n", promLabels(base), report.RecordCounts.DKIM)
		for _, row := range report.DKIM {
			fmt.Printf("mailops_dkim_selector_ok{%s} %d\n", promLabels(map[string]string{
				"domain":   report.Domain,
				"selector": row.Selector,
			}), boolInt(row.Valid))
		}
		fmt.Printf("mailops_mta_sts_mx_matched_ratio{%s} %.2f\n", promLabels(base), ratio(report.MTASTS.MXMatched, report.MTASTS.MXTotal))
		ptrConfirmed, ptrTotal := ptrConfirmedCount(report)
		fmt.Printf("mailops_ptr_records{%s} %d\n", promLabels(base), ptrTotal)
		fmt.Printf("mailops_ptr_forward_confirmed_ratio{%s} %.2f\n", promLabels(base), ratio(ptrConfirmed, ptrTotal))
		fmt.Printf("mailops_rbl_hits{%s} %d\n", promLabels(base), report.RecordCounts.RBLHits)
		for _, row := range report.RBL {
			fmt.Printf("mailops_rbl_listed{%s} %d\n", promLabels(map[string]string{
				"domain": report.Domain,
				"ip":     row.IP,
			}), boolInt(len(row.ListedOn) > 0))
			for _, zone := range row.CleanOn {
				fmt.Printf("mailops_rbl_lookup_error{%s} 0\n", promLabels(map[string]string{"domain": report.Domain, "ip": row.IP, "zone": zone}))
			}
			for _, zone := range row.ListedOn {
				fmt.Printf("mailops_rbl_lookup_error{%s} 0\n", promLabels(map[string]string{"domain": report.Domain, "ip": row.IP, "zone": zone}))
			}
			for _, zone := range row.ErrorOn {
				fmt.Printf("mailops_rbl_lookup_error{%s} 1\n", promLabels(map[string]string{"domain": report.Domain, "ip": row.IP, "zone": zone}))
			}
		}
		fmt.Printf("mailops_domainbl_hits{%s} %d\n", promLabels(base), report.RecordCounts.DomainBLHits)
		for _, row := range report.DomainBL {
			for _, zone := range row.CleanOn {
				fmt.Printf("mailops_domainbl_listed{%s} 0\n", promLabels(map[string]string{"domain": report.Domain, "zone": zone}))
				fmt.Printf("mailops_domainbl_lookup_error{%s} 0\n", promLabels(map[string]string{"domain": report.Domain, "zone": zone}))
			}
			for _, zone := range row.ListedOn {
				fmt.Printf("mailops_domainbl_listed{%s} 1\n", promLabels(map[string]string{"domain": report.Domain, "zone": zone}))
				fmt.Printf("mailops_domainbl_lookup_error{%s} 0\n", promLabels(map[string]string{"domain": report.Domain, "zone": zone}))
			}
			for _, zone := range row.ErrorOn {
				fmt.Printf("mailops_domainbl_lookup_error{%s} 1\n", promLabels(map[string]string{"domain": report.Domain, "zone": zone}))
			}
		}
		fmt.Printf("mailops_smtp_probe_checked{%s} %d\n", promLabels(base), len(report.SMTP))
		for _, row := range report.SMTP {
			labels := map[string]string{"domain": report.Domain, "host": row.Host, "port": strconv.Itoa(row.Port)}
			fmt.Printf("mailops_smtp_connect_ok{%s} %d\n", promLabels(labels), boolInt(row.ConnectOK))
			fmt.Printf("mailops_smtp_starttls_offered{%s} %d\n", promLabels(labels), boolInt(row.STARTTLSOffered))
			fmt.Printf("mailops_smtp_starttls_ok{%s} %d\n", promLabels(labels), boolInt(row.STARTTLSOK))
			fmt.Printf("mailops_smtp_tls_ok{%s} %d\n", promLabels(labels), boolInt(row.TLSOK))
			fmt.Printf("mailops_smtp_auth_mechanisms{%s} %d\n", promLabels(labels), len(row.AuthMechanisms))
			fmt.Printf("mailops_smtp_open_relay_checked{%s} %d\n", promLabels(labels), boolInt(row.RelayCheck))
			fmt.Printf("mailops_smtp_open_relay{%s} %d\n", promLabels(labels), boolInt(row.OpenRelay))
			if row.RelayMailCode > 0 {
				fmt.Printf("mailops_smtp_relay_mail_code{%s} %d\n", promLabels(labels), row.RelayMailCode)
			}
			if row.RelayRcptCode > 0 {
				fmt.Printf("mailops_smtp_relay_rcpt_code{%s} %d\n", promLabels(labels), row.RelayRcptCode)
			}
			if !row.CertNotAfter.IsZero() {
				fmt.Printf("mailops_smtp_cert_days_remaining{%s} %d\n", promLabels(labels), row.CertDaysRemaining)
			}
		}
		fmt.Printf("mailops_mda_endpoint_checked{%s} %d\n", promLabels(base), len(report.MDA))
		for _, row := range report.MDA {
			labels := map[string]string{
				"domain":   report.Domain,
				"host":     row.Host,
				"port":     strconv.Itoa(row.Port),
				"protocol": row.Protocol,
			}
			fmt.Printf("mailops_mda_connect_ok{%s} %d\n", promLabels(labels), boolInt(row.ConnectOK))
			fmt.Printf("mailops_mda_tls_ok{%s} %d\n", promLabels(labels), boolInt(row.TLSOK))
			fmt.Printf("mailops_mda_starttls_offered{%s} %d\n", promLabels(labels), boolInt(row.STARTTLSOffered))
			if !row.CertNotAfter.IsZero() {
				fmt.Printf("mailops_mda_cert_days_remaining{%s} %d\n", promLabels(labels), row.CertDaysRemaining)
			}
		}
	}
}

func statusCode(status string) int {
	switch strings.ToLower(status) {
	case "warn":
		return 1
	case "critical":
		return 2
	case "error":
		return 3
	default:
		return 0
	}
}

func findingCount(report mailcheck.Report, severity string) int {
	count := 0
	for _, finding := range report.Findings {
		if finding.Severity == severity {
			count++
		}
	}
	return count
}

func ptrConfirmedCount(report mailcheck.Report) (int, int) {
	confirmed := 0
	for _, ptr := range report.PTR {
		if ptr.ForwardConfirmed {
			confirmed++
		}
	}
	return confirmed, len(report.PTR)
}

func ratio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func promLabels(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key, value := range labels {
		if strings.TrimSpace(value) == "" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+strconv.Quote(labels[key]))
	}
	return strings.Join(parts, ",")
}
