package mailops

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPublicEngineSchemaAndFindingCodes(t *testing.T) {
	report := Run(context.Background(), Options{Domain: "not a domain", Timeout: time.Second})
	if report.SchemaVersion != SchemaVersion || report.PostureStatus != SeverityError || report.AvailabilityStatus != "not_checked" {
		t.Fatalf("unexpected public report status: %#v", report)
	}
	if len(report.Findings) != 1 || report.Findings[0].Code != "MAILOPS_INPUT_INVALID_DOMAIN" {
		t.Fatalf("unstable finding code: %#v", report.Findings)
	}
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"\"schema_version\"", "\"posture_status\"", "\"availability_status\"", "\"code\""} {
		if !strings.Contains(string(payload), field) {
			t.Fatalf("public JSON omitted %s: %s", field, payload)
		}
	}
}
