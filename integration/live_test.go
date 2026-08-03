//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/systeampl/mailops/pkg/mailops"
)

func TestLivePublicMailPolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("live integration test disabled in short mode")
	}
	domain := os.Getenv("MAILOPS_TEST_DOMAIN")
	if domain == "" {
		domain = "gmail.com"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report := mailops.Run(ctx, mailops.Options{
		Domain:      domain,
		Timeout:     30 * time.Second,
		CheckRBL:    false,
		CheckMTASTS: true,
		CheckTLSRPT: true,
		CheckBIMI:   true,
	})
	if report.Error != "" {
		t.Fatalf("live check failed: %s", report.Error)
	}
	if len(report.MX) == 0 || !report.SPF.Present || !report.DMARC.Present {
		t.Fatalf("incomplete live policy report for %s: MX=%d SPF=%t DMARC=%t", domain, len(report.MX), report.SPF.Present, report.DMARC.Present)
	}
	if report.SchemaVersion != mailops.SchemaVersion {
		t.Fatalf("schema version = %q", report.SchemaVersion)
	}
}
