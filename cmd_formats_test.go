package main

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	yamlv3 "gopkg.in/yaml.v3"

	"github.com/systeampl/mailops/internal/mailcheck"
)

func TestMetricFormattingHelpers(t *testing.T) {
	labels := promLabels(map[string]string{"zone": "a\"b", "domain": "example.com", "empty": ""})
	if labels != `domain="example.com",zone="a\"b"` {
		t.Fatalf("labels = %q", labels)
	}
	if statusCode("warn") != 1 || statusCode("critical") != 2 || statusCode("error") != 3 || statusCode("other") != 0 {
		t.Fatal("unexpected status code")
	}
	if ratio(1, 4) != 0.25 || ratio(1, 0) != 0 {
		t.Fatal("unexpected ratio")
	}
	report := mailcheck.Report{
		PTR:      []mailcheck.PTRReport{{ForwardConfirmed: true}, {}},
		Findings: []mailcheck.Finding{{Severity: "warn"}, {Severity: "critical"}, {Severity: "warn"}},
	}
	confirmed, total := ptrConfirmedCount(report)
	if confirmed != 1 || total != 2 || findingCount(report, "warn") != 2 {
		t.Fatalf("confirmed=%d total=%d warnings=%d", confirmed, total, findingCount(report, "warn"))
	}
	if !strings.Contains(promLabels(map[string]string{"line": "a\nb"}), `line="a\nb"`) {
		t.Fatal("newline was not escaped")
	}
}

func TestPrometheusAndYAMLOutputContainOperationalData(t *testing.T) {
	report := mailcheck.Report{
		Domain:      "example.com",
		Status:      "warn",
		Resolver:    "test",
		GeneratedAt: time.Unix(100, 0),
		SPF:         mailcheck.SPFReport{Present: true, Valid: true, EstimatedLookups: 2},
		DMARC:       mailcheck.DMARCReport{Present: true, Valid: true, Policy: "reject", Pct: 100},
		MTASTS:      mailcheck.MTASTSReport{TXTPresent: true, PolicyPresent: true, Valid: false},
		MX:          []mailcheck.MXRecord{{Host: "mx.example.com", Preference: 10, IPs: []string{"192.0.2.1"}}},
		DKIM:        []mailcheck.DKIMReport{{Selector: "s1", Present: true, Valid: true, KeyType: "rsa", KeyBits: 2048}},
		SMTP:        []mailcheck.SMTPReport{{Host: "mx.example.com", Port: 25, ConnectOK: true, TLSOK: true}},
		Findings:    []mailcheck.Finding{{Severity: "warn", Scope: "rbl", Message: "lookup failed"}},
	}
	prom := captureStdout(t, func() { printPromReports([]mailcheck.Report{report}) })
	if !strings.Contains(prom, `mailops_status_code{domain="example.com"} 1`) ||
		!strings.Contains(prom, `mailops_record_valid{domain="example.com",record="mta_sts"} 0`) {
		t.Fatalf("Prometheus output missing metrics:\n%s", prom)
	}
	yaml := captureStdout(t, func() { printYAMLReports([]mailcheck.Report{report}) })
	if !strings.Contains(yaml, `domain: example.com`) || !strings.Contains(yaml, `message: lookup failed`) {
		t.Fatalf("YAML output missing report data:\n%s", yaml)
	}
	var decoded struct {
		Reports []mailcheck.Report `yaml:"reports"`
	}
	if err := yamlv3.Unmarshal([]byte(yaml), &decoded); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, yaml)
	}
	if len(decoded.Reports) != 1 || len(decoded.Reports[0].MX) != 1 || len(decoded.Reports[0].DKIM) != 1 || len(decoded.Reports[0].SMTP) != 1 {
		t.Fatalf("YAML round-trip lost report fields: %#v", decoded.Reports)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	fn()
	_ = writer.Close()
	os.Stdout = original
	data, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
