package main

import (
	"reflect"
	"testing"
)

func TestStringListFlagSplitsAndSkipsEmptyValues(t *testing.T) {
	var values stringListFlag
	if err := values.Set(" one, two ,,three "); err != nil {
		t.Fatal(err)
	}
	want := stringListFlag{"one", "two", "three"}
	if !reflect.DeepEqual(values, want) || values.String() != "one,two,three" {
		t.Fatalf("values = %#v, string = %q", values, values.String())
	}
}

func TestResolveOutput(t *testing.T) {
	tests := []struct {
		json, yaml, prom bool
		want             outputFormat
		wantErr          bool
	}{
		{want: outputText},
		{json: true, want: outputJSON},
		{yaml: true, want: outputYAML},
		{prom: true, want: outputProm},
		{json: true, yaml: true, wantErr: true},
	}
	for _, test := range tests {
		got, err := resolveOutput(test.json, test.yaml, test.prom)
		if (err != nil) != test.wantErr || got != test.want {
			t.Fatalf("resolveOutput(%t,%t,%t) = %q, %v", test.json, test.yaml, test.prom, got, err)
		}
	}
}

func TestFailOnStatus(t *testing.T) {
	if !failOnStatus("critical", "warn") || !failOnStatus("error", "critical") {
		t.Fatal("expected threshold to fail")
	}
	if failOnStatus("warn", "critical") || failOnStatus("ok", "warn") {
		t.Fatal("status failed below threshold")
	}
	if !failOnStatus("critical", "not-a-level") {
		t.Fatal("invalid threshold should use critical default")
	}
	if !validFailOn(" WARN ") || !validFailOn("critical") || !validFailOn("error") || validFailOn("info") {
		t.Fatal("unexpected --fail-on validation")
	}
}

func TestNormalizeFlagArgsAllowsFlagsAfterDomain(t *testing.T) {
	got := normalizeFlagArgs(
		[]string{"example.com", "--smtp", "--timeout", "2s", "--selector=s1"},
		map[string]bool{"--timeout": true, "--selector": true},
	)
	want := []string{"--smtp", "--timeout", "2s", "--selector=s1", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

func TestSmallFormattingHelpers(t *testing.T) {
	if boolInt(true) != 1 || boolInt(false) != 0 {
		t.Fatal("boolInt returned unexpected value")
	}
	if visibleLen("\x1b[31mcritical\x1b[0m") != len("critical") {
		t.Fatal("visibleLen counted ANSI escapes")
	}
	if emptyDash("  ") != "-" || emptyDash("value") != "value" {
		t.Fatal("emptyDash returned unexpected value")
	}
}
