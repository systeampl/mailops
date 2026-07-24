package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/systeampl/mailops/internal/mailcheck"
)

func TestPolicyAndRecordDisplayStatuses(t *testing.T) {
	if okCritical(true) != "ok" || okCritical(false) != "critical" || okWarn(false) != "warn" {
		t.Fatal("unexpected boolean status")
	}
	if spfLookupStatus(11) != "critical" || spfLookupStatus(8) != "warn" || spfLookupStatus(7) != "ok" {
		t.Fatal("unexpected SPF lookup status")
	}
	if spfAllStatus("+all") != "critical" || spfAllStatus("~all") != "warn" || spfAllStatus("-all") != "ok" {
		t.Fatal("unexpected SPF all status")
	}
	if dmarcPolicyStatus("reject") != "ok" || dmarcPolicyStatus("none") != "warn" || dmarcPolicyStatus("") != "critical" {
		t.Fatal("unexpected DMARC status")
	}
	report := mailcheck.Report{MTASTS: mailcheck.MTASTSReport{Error: "DNS failed"}}
	if mtaSTSCell(report) != "error" || mtaSTSStatus(report) != "warn" {
		t.Fatalf("unexpected MTA-STS display: %q/%q", mtaSTSCell(report), mtaSTSStatus(report))
	}
	report.MTASTS = mailcheck.MTASTSReport{TXTPresent: true, PolicyPresent: true, Valid: true, Mode: "enforce", MXMatched: 2, MXTotal: 2}
	if mtaSTSCell(report) != "enforce" || mtaSTSStatus(report) != "ok" || mtaSTSMXCell(report) != "2/2" || mtaSTSMXStatus(report) != "ok" {
		t.Fatalf("unexpected MTA-STS healthy display")
	}
}

func TestPrintReportsAcrossAllFormats(t *testing.T) {
	report := mailcheck.Report{
		Domain:       "example.com",
		Status:       "warn",
		Resolver:     "test",
		GeneratedAt:  time.Unix(100, 0),
		MX:           []mailcheck.MXRecord{{Host: "mx.example.com"}},
		SPF:          mailcheck.SPFReport{Present: true, Valid: true, AllMechanism: "-all"},
		DMARC:        mailcheck.DMARCReport{Present: true, Valid: true, Policy: "reject", Pct: 100},
		BIMI:         mailcheck.BIMIReport{Present: true, Valid: true},
		PTR:          []mailcheck.PTRReport{{IP: "192.0.2.1", ForwardConfirmed: true}},
		RecordCounts: mailcheck.RecordCounts{MX: 1},
		Findings:     []mailcheck.Finding{{Severity: "warn", Scope: "test", Message: "example finding"}},
		Summary:      mailcheck.ReportSummary{Warn: 1},
	}
	textOutput := captureStdout(t, func() { printReports([]mailcheck.Report{report}, outputText) })
	for _, fragment := range []string{"example.com  mail report", "mx.example.com", "example finding", "summary: status=warn"} {
		if !strings.Contains(textOutput, fragment) {
			t.Fatalf("text output missing %q:\n%s", fragment, textOutput)
		}
	}
	jsonOutput := captureStdout(t, func() { printReports([]mailcheck.Report{report}, outputJSON) })
	var decoded []mailcheck.Report
	if err := json.Unmarshal([]byte(jsonOutput), &decoded); err != nil || len(decoded) != 1 || decoded[0].Domain != "example.com" {
		t.Fatalf("JSON output did not round-trip: err=%v output=%s", err, jsonOutput)
	}
	yamlOutput := captureStdout(t, func() { printReports([]mailcheck.Report{report}, outputYAML) })
	if !strings.Contains(yamlOutput, "reports:") || !strings.Contains(yamlOutput, "mx.example.com") {
		t.Fatalf("YAML output incomplete:\n%s", yamlOutput)
	}
	promOutput := captureStdout(t, func() { printReports([]mailcheck.Report{report}, outputProm) })
	if !strings.Contains(promOutput, `mailops_mx_records{domain="example.com"} 1`) {
		t.Fatalf("Prometheus output incomplete:\n%s", promOutput)
	}
}

func TestReputationDisplayReflectsLookupFailures(t *testing.T) {
	report := mailcheck.Report{
		RBL: []mailcheck.RBLReport{{IP: "192.0.2.1", Errors: []string{"timeout"}}},
		DomainBL: []mailcheck.DomainBLReport{{
			Domain: "example.com", ErrorOn: []string{"dbl.example"}, Errors: []string{"timeout"},
		}},
	}
	if rblStatus(report) != "warn" || reputationStatus(report) != "warn" || reputationCell(report) != "0/1 listed" {
		t.Fatalf("RBL=%q reputation=%q cell=%q", rblStatus(report), reputationStatus(report), reputationCell(report))
	}
	report.RecordCounts.RBLHits = 1
	report.RecordCounts.DomainBLHits = 1
	if rblStatus(report) != "critical" || reputationStatus(report) != "critical" {
		t.Fatal("listings did not override lookup warning")
	}
}

func TestTransportDisplayHelpers(t *testing.T) {
	now := time.Now()
	report := mailcheck.Report{
		SMTP: []mailcheck.SMTPReport{
			{Host: "mx1", Port: 25, ConnectOK: true, TLSOK: true, RelayCheck: true, CertNotAfter: now.Add(30 * 24 * time.Hour), CertDaysRemaining: 30},
			{Host: "mx2", Port: 587, ConnectOK: true, TLSOK: false, AuthMechanisms: []string{"PLAIN"}, RelayCheck: true, OpenRelay: true, CertNotAfter: now.Add(5 * 24 * time.Hour), CertDaysRemaining: 5},
		},
		MDA: []mailcheck.MDAReport{
			{Host: "imap", Port: 993, ConnectOK: true, TLSOK: true, CertNotAfter: now.Add(20 * 24 * time.Hour), CertDaysRemaining: 20},
			{Host: "pop", Port: 995, ConnectOK: false, TLSOK: false, CertNotAfter: now.Add(-24 * time.Hour), CertDaysRemaining: -1},
		},
	}
	if smtpCell(report) != "2/2" || smtpStatus(report) != "ok" || smtpTLSCell(report) != "1/2" || smtpTLSStatus(report) != "warn" {
		t.Fatal("unexpected SMTP transport display")
	}
	if smtpAuthCell(report) != "1" || smtpAuthStatus(report) != "ok" || smtpOpenRelayCell(report) != "1/2 open" || smtpOpenRelayStatus(report) != "critical" {
		t.Fatal("unexpected SMTP feature display")
	}
	if smtpCertDaysCell(report) != "5" || smtpCertDaysStatus(report) != "warn" {
		t.Fatal("unexpected SMTP certificate display")
	}
	if mdaCell(report) != "1/2" || mdaStatus(report) != "warn" || mdaTLSCell(report) != "1/2" || mdaTLSStatus(report) != "warn" {
		t.Fatal("unexpected MDA transport display")
	}
	if mdaCertDaysCell(report) != "-1" || mdaCertDaysStatus(report) != "critical" {
		t.Fatal("unexpected MDA certificate display")
	}
}

func TestFindingAndCompactMXHelpers(t *testing.T) {
	findings := []mailcheck.Finding{
		{Severity: "warn", Scope: "dkim"},
		{Severity: "critical", Scope: "dkim"},
		{Severity: "error", Scope: "other"},
	}
	if findingSeverity(findings, "dkim") != "critical" {
		t.Fatal("wrong finding severity")
	}
	report := mailcheck.Report{Findings: findings}
	if dkimStatus(report) != "info" {
		t.Fatal("unexpected DKIM status without valid selector")
	}
	report.RecordCounts.DKIM = 1
	if dkimStatus(report) != "ok" {
		t.Fatal("valid DKIM selector not shown as healthy")
	}
	mx := []mailcheck.MXRecord{{Host: "a"}, {Host: "b"}, {Host: "c"}}
	if compactMX(nil, 2) != "-" || compactMX(mx, 2) != "a, b +1 more" {
		t.Fatal("unexpected compact MX output")
	}
}
