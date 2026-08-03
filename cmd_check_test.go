package main

import (
	"os"
	"path/filepath"
	"testing"

	mailcheck "github.com/systeampl/mailops/pkg/mailops"
)

func TestParsePorts(t *testing.T) {
	got, err := parsePorts([]string{"25", "587", "25"}, []int{25})
	if err != nil {
		t.Fatal(err)
	}
	want := []int{25, 587}
	if len(got) != len(want) {
		t.Fatalf("ports = %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ports = %#v", got)
		}
	}
}

func TestCollectDomainsAndYAMLConfig(t *testing.T) {
	directory := t.TempDir()
	domainsFile := filepath.Join(directory, "domains.txt")
	if err := os.WriteFile(domainsFile, []byte("# fleet\nexample.com\nexample.net\nexample.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	domains, err := collectDomains([]string{"example.org", "example.com"}, domainsFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 3 || domains[0] != "example.org" || domains[1] != "example.com" || domains[2] != "example.net" {
		t.Fatalf("domains = %#v", domains)
	}

	configFile := filepath.Join(directory, "mailops.yaml")
	configText := "domains: [example.com, example.net]\ntimeout: 4s\nresolver: 1.1.1.1\nsmtp: true\nsmtp_ports: [25, 587]\n"
	if err := os.WriteFile(configFile, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := loadCheckConfig(configFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Domains) != 2 || config.Timeout != "4s" || config.Resolver != "1.1.1.1" || !config.SMTP || len(config.SMTPPorts) != 2 {
		t.Fatalf("config = %#v", config)
	}
}

func TestReportExitCodeDistinguishesInvalidInput(t *testing.T) {
	invalid := mailcheck.Report{Status: mailcheck.SeverityError, Findings: []mailcheck.Finding{{Severity: mailcheck.SeverityError, Scope: "input"}}}
	if got := reportExitCode(invalid, "critical"); got != 2 {
		t.Fatalf("invalid input exit code = %d, want 2", got)
	}
	critical := mailcheck.Report{Status: mailcheck.SeverityCritical}
	if got := reportExitCode(critical, "critical"); got != 1 {
		t.Fatalf("critical exit code = %d, want 1", got)
	}
	if got := reportExitCode(critical, "error"); got != 0 {
		t.Fatalf("below-threshold exit code = %d, want 0", got)
	}
}

func TestParsePortsDefault(t *testing.T) {
	got, err := parsePorts(nil, []int{143, 993})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != 143 || got[1] != 993 {
		t.Fatalf("ports = %#v", got)
	}
}

func TestParsePortsRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{"invalid", "0", "65536"} {
		if _, err := parsePorts([]string{value}, nil); err == nil {
			t.Fatalf("parsePorts(%q) succeeded", value)
		}
	}
}
