package main

import "testing"

func TestBuildVersionReport(t *testing.T) {
	oldVersion, oldCommit, oldDate := version, commit, date
	t.Cleanup(func() { version, commit, date = oldVersion, oldCommit, oldDate })
	version, commit, date = "1.2.3", "abc123", "2026-08-04T00:00:00Z"
	report := buildVersionReport()
	if report.Version != version || report.Commit != commit || report.BuildDate != date {
		t.Fatalf("version report = %+v", report)
	}
	if report.GoVersion == "" || report.OS == "" || report.Arch == "" {
		t.Fatalf("runtime fields missing: %+v", report)
	}
}
