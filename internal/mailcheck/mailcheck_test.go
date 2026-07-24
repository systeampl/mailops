package mailcheck

import (
	"bufio"
	"strings"
	"testing"
)

func TestParseSPFRecord(t *testing.T) {
	got := parseSPFRecord("v=spf1 include:_spf.example.net ~all")
	if got.All != "~all" {
		t.Fatalf("All = %q", got.All)
	}
	if len(got.Warnings) == 0 {
		t.Fatal("expected warning for softfail")
	}
}

func TestParseDMARCTags(t *testing.T) {
	tags := parseTags("v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=50")
	if tags["p"] != "reject" {
		t.Fatalf("p = %q", tags["p"])
	}
	if tags["rua"] != "mailto:dmarc@example.com" {
		t.Fatalf("rua = %q", tags["rua"])
	}
}

func TestParseMTASTSPolicy(t *testing.T) {
	policy := parseMTASTSPolicy("version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.net\nmax_age: 86400\n")
	if policy["mode"] != "enforce" {
		t.Fatalf("mode = %q", policy["mode"])
	}
	values := splitPolicyValues(policy["mx"])
	if len(values) != 2 {
		t.Fatalf("mx values = %#v", values)
	}
}

func TestMatchMTASTSMX(t *testing.T) {
	patterns := []string{"mail.example.com", "*.mx.example.net"}
	if !matchMTASTSMX("mail.example.com.", patterns) {
		t.Fatal("exact match failed")
	}
	if !matchMTASTSMX("a.mx.example.net", patterns) {
		t.Fatal("wildcard match failed")
	}
	if matchMTASTSMX("mx.example.net", patterns) {
		t.Fatal("wildcard matched bare suffix")
	}
}

func TestReadSMTPResponse(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("250-mail.example.com\r\n250-STARTTLS\r\n250 OK\r\n"))
	code, lines, err := readSMTPResponse(reader)
	if err != nil {
		t.Fatal(err)
	}
	if code != 250 {
		t.Fatalf("code = %d", code)
	}
	if !smtpLinesContain(lines, "STARTTLS") {
		t.Fatalf("STARTTLS not detected in %#v", lines)
	}
}

func TestParseSMTPAuthMechanisms(t *testing.T) {
	got := parseSMTPAuthMechanisms([]string{
		"250-mail.example.com",
		"250-AUTH PLAIN LOGIN XOAUTH2",
		"250 AUTH=CRAM-MD5",
	})
	want := []string{"CRAM-MD5", "LOGIN", "PLAIN", "XOAUTH2"}
	if len(got) != len(want) {
		t.Fatalf("auth mechanisms = %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("auth mechanisms = %#v", got)
		}
	}
}

func TestMDAProtocol(t *testing.T) {
	tests := map[int]string{
		143: "imap",
		993: "imaps",
		110: "pop3",
		995: "pop3s",
		999: "tcp",
	}
	for port, want := range tests {
		if got := mdaProtocol(port); got != want {
			t.Fatalf("mdaProtocol(%d) = %q, want %q", port, got, want)
		}
	}
}

func TestNormalizeHosts(t *testing.T) {
	got := normalizeHosts([]string{" Mail.Example.COM. ", "mail.example.com", "", "imap.example.com"})
	want := []string{"mail.example.com", "imap.example.com"}
	if len(got) != len(want) {
		t.Fatalf("hosts = %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("hosts = %#v", got)
		}
	}
}
