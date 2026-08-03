package mailcheck

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestDNSSECSignedResponseDetectionAndFindings(t *testing.T) {
	message := new(dns.Msg)
	message.AuthenticatedData = true
	message.Answer = []dns.RR{&dns.RRSIG{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET}}}
	if !dnsMessageSigned(message) || !messageHasType(message, dns.TypeRRSIG) {
		t.Fatal("signed response was not recognized")
	}
	if findings := dnsSECFindings(DNSSECReport{Checked: true, Signed: true, Secure: true}); len(findings) != 0 {
		t.Fatalf("secure response findings = %#v", findings)
	}
	findings := dnsSECFindings(DNSSECReport{Checked: true, Signed: true})
	if len(findings) != 1 || findings[0].Severity != SeverityWarn {
		t.Fatalf("unauthenticated signed response findings = %#v", findings)
	}
}

func TestDANETLSAValidationAndCertificateMatching(t *testing.T) {
	certificate := &x509.Certificate{Raw: []byte("leaf-certificate"), RawSubjectPublicKeyInfo: []byte("leaf-spki")}
	digest := sha256.Sum256(certificate.Raw)
	message := new(dns.Msg)
	message.AuthenticatedData = true
	message.Answer = []dns.RR{&dns.TLSA{
		Hdr:          dns.RR_Header{Name: "_25._tcp.mx.example.com.", Rrtype: dns.TypeTLSA, Class: dns.ClassINET},
		Usage:        3,
		Selector:     0,
		MatchingType: 1,
		Certificate:  hex.EncodeToString(digest[:]),
	}}
	report := analyzeDANEResponse(DANEReport{Host: "mx.example.com", Port: 25}, message, certificate)
	if !report.Present || !report.Valid || !report.DNSSECSecure || !report.Matched || len(report.Records) != 1 || !report.Records[0].Matched {
		t.Fatalf("matching TLSA report = %#v", report)
	}

	message.AuthenticatedData = false
	insecure := analyzeDANEResponse(DANEReport{Host: "mx.example.com", Port: 25}, message, certificate)
	if insecure.Valid || !strings.Contains(insecure.Warning, "DNSSEC") {
		t.Fatalf("insecure TLSA report = %#v", insecure)
	}
	findings := daneFindings([]DANEReport{insecure})
	if len(findings) != 1 || findings[0].Severity != SeverityCritical {
		t.Fatalf("insecure TLSA findings = %#v", findings)
	}
}

func TestTLSARejectsInvalidFieldsAndDigestLength(t *testing.T) {
	for _, record := range []TLSARecord{
		{Usage: 4, Selector: 0, MatchingType: 1, AssociationData: strings.Repeat("00", 32)},
		{Usage: 3, Selector: 2, MatchingType: 1, AssociationData: strings.Repeat("00", 32)},
		{Usage: 3, Selector: 0, MatchingType: 3, AssociationData: strings.Repeat("00", 32)},
		{Usage: 3, Selector: 0, MatchingType: 1, AssociationData: "00"},
		{Usage: 3, Selector: 0, MatchingType: 1, AssociationData: "not-hex"},
	} {
		if validTLSARecord(record) {
			t.Fatalf("invalid TLSA accepted: %#v", record)
		}
	}
}
