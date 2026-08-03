package mailcheck

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type fakeResolver struct {
	mx     map[string][]*net.MX
	txt    map[string][]string
	ips    map[string][]net.IPAddr
	ptr    map[string][]string
	errors map[string]error
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func testTLSConfigs(t *testing.T, host string) (*tls.Config, func(string) *tls.Config) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certificateDER}, PrivateKey: privateKey}},
		MinVersion:   tls.VersionTLS12,
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	clientConfig := func(serverName string) *tls.Config {
		return &tls.Config{ServerName: serverName, RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return serverConfig, clientConfig
}

func (r fakeResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if err := r.errors["mx:"+name]; err != nil {
		return nil, err
	}
	if records, ok := r.mx[name]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (r fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if err := r.errors["txt:"+name]; err != nil {
		return nil, err
	}
	if records, ok := r.txt[name]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (r fakeResolver) LookupIPAddr(_ context.Context, name string) ([]net.IPAddr, error) {
	if err := r.errors["ip:"+name]; err != nil {
		return nil, err
	}
	if records, ok := r.ips[name]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (r fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if err := r.errors["ptr:"+addr]; err != nil {
		return nil, err
	}
	if records, ok := r.ptr[addr]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
}

func TestRunWithResolverProducesHealthyReport(t *testing.T) {
	dkimKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	r := fakeResolver{
		mx: map[string][]*net.MX{
			"example.com": {{Host: "mail.example.com.", Pref: 10}},
		},
		txt: map[string][]string{
			"example.com":               {"v=spf1 -all"},
			"_dmarc.example.com":        {"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"},
			"s1._domainkey.example.com": {"v=DKIM1; k=ed25519; p=" + dkimKey},
			"_smtp._tls.example.com":    {"v=TLSRPTv1; rua=mailto:tlsrpt@example.com"},
		},
		ips: map[string][]net.IPAddr{
			"mail.example.com": {{IP: net.ParseIP("192.0.2.1")}},
		},
		ptr: map[string][]string{
			"192.0.2.1": {"mail.example.com."},
		},
		errors: map[string]error{},
	}
	report := run(context.Background(), Options{
		Domain:        "https://Example.COM:443/path",
		DKIMSelectors: []string{"s1"},
		CheckTLSRPT:   true,
		Timeout:       time.Second,
	}, r)
	if report.Domain != "example.com" {
		t.Fatalf("domain = %q", report.Domain)
	}
	if report.Status != "ok" {
		t.Fatalf("status = %q, findings = %#v", report.Status, report.Findings)
	}
	if report.RecordCounts.MX != 1 || report.RecordCounts.DKIM != 1 || !report.PTR[0].ForwardConfirmed {
		t.Fatalf("unexpected report: %#v", report)
	}
}

func TestRunReportsResolverFailureAsMeasurementError(t *testing.T) {
	lookupErr := &net.DNSError{Err: "temporary failure", IsTemporary: true}
	r := fakeResolver{errors: map[string]error{
		"mx:example.com":                lookupErr,
		"txt:example.com":               lookupErr,
		"txt:_dmarc.example.com":        lookupErr,
		"txt:s1._domainkey.example.com": lookupErr,
		"txt:_smtp._tls.example.com":    lookupErr,
	}}
	report := run(context.Background(), Options{
		Domain:        "example.com",
		DKIMSelectors: []string{"s1"},
		CheckTLSRPT:   true,
		Timeout:       time.Second,
	}, r)
	if report.Status != SeverityError {
		t.Fatalf("status = %q, findings = %#v", report.Status, report.Findings)
	}
	for _, finding := range report.Findings {
		if strings.HasPrefix(finding.Message, "no MX") || strings.HasPrefix(finding.Message, "no SPF") || strings.HasPrefix(finding.Message, "no DMARC") {
			t.Fatalf("resolver failure misreported as absence: %#v", finding)
		}
	}
}

func TestRunRejectsEmptyDomainWithoutNetwork(t *testing.T) {
	report := Run(context.Background(), Options{})
	if report.Status != SeverityError || report.Error != "domain is required" || report.Summary.Error != 1 {
		t.Fatalf("report = %#v", report)
	}
}

func TestRunRejectsMalformedDomainsWithoutNetwork(t *testing.T) {
	for _, domain := range []string{"bad_domain", "bad..example", "-bad.example", "192.0.2.1", "[2001:db8::1]"} {
		report := Run(context.Background(), Options{Domain: domain})
		if report.Status != SeverityError || !strings.HasPrefix(report.Error, "invalid domain:") || len(report.Findings) != 1 || report.Findings[0].Scope != "input" {
			t.Fatalf("domain=%q report=%#v", domain, report)
		}
	}
}

func TestNullMXIsReportedAsCritical(t *testing.T) {
	r := fakeResolver{
		mx: map[string][]*net.MX{"example.com": {{Host: ".", Pref: 0}}},
		txt: map[string][]string{
			"example.com":            {"v=spf1 -all"},
			"_dmarc.example.com":     {"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"},
			"_smtp._tls.example.com": {"v=TLSRPTv1; rua=mailto:tlsrpt@example.com"},
		},
		errors: map[string]error{},
	}
	report := run(context.Background(), Options{Domain: "example.com", DKIMSelectors: []string{"s1"}, CheckTLSRPT: true}, r)
	if report.Status != SeverityCritical || len(report.MX) != 1 || report.MX[0].Host != "." {
		t.Fatalf("report = %#v", report)
	}
	found := false
	for _, finding := range report.Findings {
		if strings.Contains(finding.Message, "does not accept email") {
			found = true
		}
	}
	if !found {
		t.Fatalf("null MX finding missing: %#v", report.Findings)
	}
}

func TestSPFLookupsAllowSharedIncludesAndCountCIDRMechanisms(t *testing.T) {
	r := fakeResolver{txt: map[string][]string{
		"example.com":    {"v=spf1 a/24 mx/24 include:a.example include:b.example -all"},
		"a.example":      {"v=spf1 include:shared.example -all"},
		"b.example":      {"v=spf1 include:shared.example -all"},
		"shared.example": {"v=spf1 exists:sender.example -all"},
	}, errors: map[string]error{}}
	count, errs := countSPFLookups(context.Background(), r, "example.com", map[string]bool{}, 0)
	if len(errs) != 0 {
		t.Fatalf("errors = %#v", errs)
	}
	if count != 8 {
		t.Fatalf("count = %d, want 8", count)
	}
}

func TestSPFAllMechanismAndVersionRequireExactTokens(t *testing.T) {
	parsed := parseSPFRecord("v=spf1 include:small.example -all")
	if parsed.All != "-all" {
		t.Fatalf("all mechanism = %q", parsed.All)
	}
	includeOnly := parseSPFRecord("v=spf1 include:small.example")
	if includeOnly.All != "" || len(includeOnly.Warnings) != 1 || includeOnly.Warnings[0] != "SPF has no all mechanism" {
		t.Fatalf("include was treated as all: %#v", includeOnly)
	}
	if hasSPFVersion("v=spf10 -all") || !hasSPFVersion("V=SPF1 -all") {
		t.Fatal("SPF version matching is not exact")
	}
	if hasTagVersion("v=DMARC10; p=reject", "DMARC1") || !hasTagVersion("v=DMARC1; p=reject", "DMARC1") {
		t.Fatal("tag version matching is not exact")
	}
}

func TestSPFFindingsDistinguishFailureFromMissingRecord(t *testing.T) {
	failure := spfFindings(SPFReport{Errors: []string{"SPF TXT lookup failed: timeout"}})
	if len(failure) != 1 || failure[0].Severity != SeverityError {
		t.Fatalf("failure findings = %#v", failure)
	}
	missing := spfFindings(SPFReport{})
	if len(missing) != 1 || missing[0].Severity != SeverityCritical || missing[0].Message != "no SPF record found" {
		t.Fatalf("missing findings = %#v", missing)
	}
}

func TestSPFReferencedLookupFailureInvalidatesRecord(t *testing.T) {
	r := fakeResolver{
		txt:    map[string][]string{"example.com": {"v=spf1 include:missing.example -all"}},
		errors: map[string]error{},
	}
	report := checkSPF(context.Background(), r, "example.com")
	if report.Valid || len(report.Errors) == 0 || !strings.Contains(strings.Join(report.Errors, " "), "missing.example") {
		t.Fatalf("broken SPF include accepted: %#v", report)
	}
}

func TestSPFRejectsMalformedMechanismsAndDuplicateRedirect(t *testing.T) {
	tests := []string{
		"v=spf1 ip4:999.1.1.1 -all",
		"v=spf1 ip6:192.0.2.1 -all",
		"v=spf1 unknown:value -all",
		"v=spf1 include: -all",
		"v=spf1 redirect=a.example redirect=b.example",
	}
	for _, record := range tests {
		parsed := parseSPFRecord(record)
		if len(parsed.Errors) == 0 {
			t.Fatalf("malformed SPF accepted: %q", record)
		}
	}

	r := fakeResolver{txt: map[string][]string{
		"example.com":   {"v=spf1 include:child.example -all"},
		"child.example": {"v=spf1 -all", "v=spf1 ~all"},
	}, errors: map[string]error{}}
	report := checkSPF(context.Background(), r, "example.com")
	if report.Valid || !strings.Contains(strings.Join(report.Errors, " "), "multiple SPF") {
		t.Fatalf("multiple referenced SPF records accepted: %#v", report)
	}
}

func TestCheckDMARCIgnoresHistoricPct(t *testing.T) {
	for _, pct := range []string{"abc", "-1", "101"} {
		r := fakeResolver{txt: map[string][]string{
			"_dmarc.example.com": {"v=DMARC1; p=reject; pct=" + pct + "; rua=mailto:dmarc@example.com"},
		}, errors: map[string]error{}}
		report := checkDMARC(context.Background(), r, "example.com")
		if !report.Valid || len(report.Warnings) == 0 || report.EffectivePolicy != "reject" {
			t.Fatalf("historic pct=%q affected policy: %#v", pct, report)
		}
	}
}

func TestCheckDMARCRFC9989TreeWalkAndInheritedPolicies(t *testing.T) {
	r := fakeResolver{
		txt: map[string][]string{
			"_dmarc.example.com": {"v=DMARC1; p=reject; sp=quarantine; np=reject; rua=mailto:dmarc@example.com"},
		},
		ips:    map[string][]net.IPAddr{"mail.example.com": {{IP: net.ParseIP("192.0.2.10")}}},
		errors: map[string]error{},
	}
	existing := checkDMARC(context.Background(), r, "mail.example.com")
	if !existing.Valid || !existing.Inherited || existing.PolicyDomain != "example.com" || existing.EffectivePolicy != "quarantine" || existing.AppliedPolicyTag != "sp" {
		t.Fatalf("inherited existing-domain policy = %#v", existing)
	}

	nonexistent := checkDMARC(context.Background(), r, "missing.example.com")
	if nonexistent.EffectivePolicy != "reject" || nonexistent.AppliedPolicyTag != "np" || nonexistent.AuthorDomainExists == nil || *nonexistent.AuthorDomainExists {
		t.Fatalf("inherited nonexistent-domain policy = %#v", nonexistent)
	}
}

func TestCheckDMARCRFC9989PSDAndTestingMode(t *testing.T) {
	r := fakeResolver{txt: map[string][]string{
		"_dmarc.example.test": {"v=DMARC1; p=reject; psd=y; t=y; rua=mailto:dmarc@example.test"},
	}, errors: map[string]error{}}
	report := checkDMARC(context.Background(), r, "tenant.example.test")
	if !report.Inherited || report.PSD != "y" || !report.Testing || report.EffectivePolicy != "quarantine" {
		t.Fatalf("PSD/testing policy = %#v", report)
	}
}

func TestCheckDMARCRFC9989DiscardsMultipleRecordsAndUsesParent(t *testing.T) {
	r := fakeResolver{txt: map[string][]string{
		"_dmarc.mail.example.com": {"v=DMARC1; p=none", "v=DMARC1; p=reject"},
		"_dmarc.example.com":      {"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"},
	}, errors: map[string]error{}}
	report := checkDMARC(context.Background(), r, "mail.example.com")
	if !report.Valid || report.PolicyDomain != "example.com" || !strings.Contains(strings.Join(report.Errors, " "), "multiple") {
		t.Fatalf("multiple-record fallback = %#v", report)
	}
}

func TestDMARCTreeWalkIsBoundedToEightQueries(t *testing.T) {
	targets := dmarcTreeTargets("one.two.three.four.five.six.seven.eight.nine.ten.example")
	if len(targets) != 8 {
		t.Fatalf("tree walk has %d targets: %#v", len(targets), targets)
	}
	if targets[0] != "one.two.three.four.five.six.seven.eight.nine.ten.example" || targets[1] != "five.six.seven.eight.nine.ten.example" || targets[7] != "example" {
		t.Fatalf("unexpected targets: %#v", targets)
	}
}

func TestDMARCVersionIsCaseSensitive(t *testing.T) {
	r := fakeResolver{txt: map[string][]string{
		"_dmarc.example.com": {"v=dmarc1; p=reject"},
	}, errors: map[string]error{}}
	if report := checkDMARC(context.Background(), r, "example.com"); report.Present {
		t.Fatalf("lowercase version accepted: %#v", report)
	}
}

func TestCheckDKIMValidatesEncodingAndActualRSAKeySize(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	r := fakeResolver{txt: map[string][]string{
		"bad._domainkey.example.com":  {"v=DKIM1; p=%%%"},
		"good._domainkey.example.com": {"v=DKIM1; p=" + base64.StdEncoding.EncodeToString(der)},
	}, errors: map[string]error{}}
	rows := checkDKIM(context.Background(), r, "example.com", []string{"bad", "good"})
	if rows[0].Valid || !strings.Contains(rows[0].Error, "base64") {
		t.Fatalf("invalid key accepted: %#v", rows[0])
	}
	if !rows[1].Valid || rows[1].KeyBits != 1024 || !strings.Contains(rows[1].Warning, "1024 bits") {
		t.Fatalf("RSA key parsed incorrectly: %#v", rows[1])
	}
}

func TestMTASTSTXTAndPolicyValidation(t *testing.T) {
	valid := validMTASTSTXTRecords([]string{"v=STSv1; id=20260719", "unrelated"})
	if len(valid) != 1 {
		t.Fatalf("valid records = %#v", valid)
	}
	if got := validMTASTSTXTRecords([]string{"v=STSv1; id=bad-id", "v=STSv1"}); len(got) != 0 {
		t.Fatalf("invalid TXT records accepted: %#v", got)
	}
	if err := validateMTASTSPolicy(map[string]string{
		"version": "STSv1", "mode": "none", "max_age": "0",
	}); err != nil {
		t.Fatalf("valid mode=none policy rejected: %v", err)
	}
	for _, policy := range []map[string]string{
		{"version": "STSv2", "mode": "enforce", "max_age": "1", "mx": "mail.example.com"},
		{"version": "STSv1", "mode": "invalid", "max_age": "1", "mx": "mail.example.com"},
		{"version": "STSv1", "mode": "enforce", "max_age": "31557601", "mx": "mail.example.com"},
		{"version": "STSv1", "mode": "enforce", "max_age": "+1", "mx": "mail.example.com"},
		{"version": "STSv1", "mode": "enforce", "max_age": "1"},
		{"version": "STSv1", "mode": "enforce", "max_age": "1", "mx": "bad*mx.example.com"},
	} {
		if err := validateMTASTSPolicy(policy); err == nil {
			t.Fatalf("invalid policy accepted: %#v", policy)
		}
	}
	parsed := parseMTASTSPolicy("version: STSv1\nmode: testing\nmode: enforce\nmx: a.example\nmx: b.example\nmax_age: 1\n")
	if parsed["mode"] != "testing" || parsed["mx"] != "a.example,b.example" {
		t.Fatalf("policy parsing = %#v", parsed)
	}
}

func TestTLSRPTAcceptsHTTPSAndRejectsMultiplePolicies(t *testing.T) {
	httpsResolver := fakeResolver{txt: map[string][]string{
		"_smtp._tls.example.com": {"v=TLSRPTv1; rua=https://reports.example.com/v1/tlsrpt"},
	}, errors: map[string]error{}}
	httpsReport := checkTLSRPT(context.Background(), httpsResolver, "example.com")
	if !httpsReport.Present || !httpsReport.Valid || len(httpsReport.RUA) != 1 {
		t.Fatalf("HTTPS TLS-RPT rejected: %#v", httpsReport)
	}
	multipleResolver := fakeResolver{txt: map[string][]string{
		"_smtp._tls.example.com": {
			"v=TLSRPTv1; rua=mailto:one@example.com",
			"v=TLSRPTv1; rua=mailto:two@example.com",
		},
	}, errors: map[string]error{}}
	multiple := checkTLSRPT(context.Background(), multipleResolver, "example.com")
	if !multiple.Present || multiple.Valid || !strings.Contains(multiple.Error, "multiple") {
		t.Fatalf("multiple TLS-RPT records accepted: %#v", multiple)
	}
	findings := tlsRPTFindings(multiple, true)
	if len(findings) != 1 || findings[0].Severity != SeverityCritical {
		t.Fatalf("strict TLS-RPT findings = %#v", findings)
	}
}

func TestMTASTSMXCoverageAndStrictFindings(t *testing.T) {
	report := MTASTSReport{Valid: true, PolicyPresent: true, MXPatterns: []string{"mail.example.com"}}
	applyMTASTSMXCoverage(&report, []MXRecord{{Host: "mail.example.com"}, {Host: "backup.example.com"}})
	if report.MXMatched != 1 || report.MXTotal != 2 || len(report.MXUnmatched) != 1 {
		t.Fatalf("coverage = %#v", report)
	}
	findings := mtaSTSFindings(report, true)
	if len(findings) != 1 || findings[0].Severity != SeverityCritical {
		t.Fatalf("findings = %#v", findings)
	}
	invalid := MTASTSReport{PolicyPresent: true, MXPatterns: []string{"mail.example.com"}}
	applyMTASTSMXCoverage(&invalid, []MXRecord{{Host: "mail.example.com"}})
	if invalid.MXTotal != 0 {
		t.Fatalf("invalid policy received coverage: %#v", invalid)
	}
	invalidFindings := mtaSTSFindings(MTASTSReport{Error: "invalid policy"}, true)
	if len(invalidFindings) != 1 || invalidFindings[0].Severity != SeverityCritical {
		t.Fatalf("strict invalid policy findings = %#v", invalidFindings)
	}
}

func TestMTASTSHTTPClientDoesNotFollowRedirects(t *testing.T) {
	targetRequests := 0
	client := newMTASTSHTTPClient(time.Second)
	client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/target" {
			targetRequests++
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok")), Request: request}, nil
		}
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"/target"}},
			Body:       io.NopCloser(strings.NewReader("redirect")),
			Request:    request,
		}, nil
	})
	response, err := client.Get("https://example.test/start")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound || targetRequests != 0 {
		t.Fatalf("status=%d target_requests=%d", response.StatusCode, targetRequests)
	}
}

func TestCheckMTASTSFullFetchAndValidation(t *testing.T) {
	r := fakeResolver{txt: map[string][]string{
		"_mta-sts.example.com": {"v=STSv1; id=20260719"},
	}, errors: map[string]error{}}
	newClient := func(status int, body string) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.String() != "https://mta-sts.example.com/.well-known/mta-sts.txt" {
				t.Fatalf("unexpected policy URL %q", request.URL.String())
			}
			return &http.Response{
				StatusCode: status,
				Header:     http.Header{"Content-Type": []string{"text/plain"}},
				Body:       io.NopCloser(strings.NewReader(body)),
				Request:    request,
			}, nil
		})}
	}
	validBody := "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"
	valid := checkMTASTSWithClient(context.Background(), r, "example.com", time.Second, newClient(http.StatusOK, validBody))
	if !valid.TXTPresent || !valid.PolicyPresent || !valid.Valid || valid.Mode != "enforce" || valid.MaxAge != 86400 {
		t.Fatalf("valid policy report = %#v", valid)
	}
	httpFailure := checkMTASTSWithClient(context.Background(), r, "example.com", time.Second, newClient(http.StatusServiceUnavailable, ""))
	if !strings.Contains(httpFailure.Error, "HTTP 503") || httpFailure.PolicyPresent {
		t.Fatalf("HTTP failure report = %#v", httpFailure)
	}
	invalid := checkMTASTSWithClient(context.Background(), r, "example.com", time.Second, newClient(http.StatusOK, "version: STSv2\nmode: enforce\nmx: mail.example.com\nmax_age: 1\n"))
	if !invalid.PolicyPresent || invalid.Valid || invalid.Error == "" {
		t.Fatalf("invalid policy report = %#v", invalid)
	}
	oversized := checkMTASTSWithClient(context.Background(), r, "example.com", time.Second, newClient(http.StatusOK, strings.Repeat("x", 64*1024+1)))
	if !strings.Contains(oversized.Error, "size limit") {
		t.Fatalf("oversized policy report = %#v", oversized)
	}
}

func TestReputationLookupsSeparateMissingBlockedAndFailed(t *testing.T) {
	notFound := &net.DNSError{Err: "no such host", IsNotFound: true}
	timeout := errors.New("resolver timeout")
	r := fakeResolver{
		ips: map[string][]net.IPAddr{
			"4.3.2.1.listed.test":      {{IP: net.ParseIP("127.0.0.2")}},
			"4.3.2.1.blocked.test":     {{IP: net.ParseIP("127.0.0.1")}},
			"example.com.listed.test":  {{IP: net.ParseIP("127.0.0.2")}},
			"example.com.blocked.test": {{IP: net.ParseIP("127.0.0.1")}},
		},
		errors: map[string]error{
			"ip:4.3.2.1.clean.test":      notFound,
			"ip:4.3.2.1.failed.test":     timeout,
			"ip:example.com.clean.test":  notFound,
			"ip:example.com.failed.test": timeout,
		},
	}
	rbl := checkRBL(context.Background(), r, []string{"1.2.3.4"}, []string{"listed.test", "clean.test", "blocked.test", "failed.test"})[0]
	if len(rbl.ListedOn) != 1 || len(rbl.CleanOn) != 1 || len(rbl.ErrorOn) != 2 || len(rbl.Errors) != 2 {
		t.Fatalf("RBL classification = %#v", rbl)
	}
	domainBL := checkDomainBL(context.Background(), r, "example.com", []string{"listed.test", "clean.test", "blocked.test", "failed.test"})[0]
	if len(domainBL.ListedOn) != 1 || len(domainBL.CleanOn) != 1 || len(domainBL.ErrorOn) != 2 || len(domainBL.Errors) != 2 {
		t.Fatalf("domain BL classification = %#v", domainBL)
	}
}

func TestDNSBLProviderErrorCodesAreNotListingsOrClean(t *testing.T) {
	r := fakeResolver{
		ips: map[string][]net.IPAddr{
			"4.3.2.1.error.test":      {{IP: net.ParseIP("127.255.255.254")}},
			"4.3.2.1.unexpected.test": {{IP: net.ParseIP("192.0.2.1")}},
			"example.com.error.test":  {{IP: net.ParseIP("127.255.255.252")}},
			"example.com.listed.test": {{IP: net.ParseIP("127.0.1.2")}},
		},
		errors: map[string]error{},
	}
	rbl := checkRBL(context.Background(), r, []string{"1.2.3.4"}, []string{"error.test", "unexpected.test"})[0]
	if len(rbl.CleanOn) != 0 || len(rbl.ListedOn) != 0 || len(rbl.ErrorOn) != 2 {
		t.Fatalf("RBL error responses misclassified: %#v", rbl)
	}
	domainBL := checkDomainBL(context.Background(), r, "example.com", []string{"error.test", "listed.test"})[0]
	if len(domainBL.ErrorOn) != 1 || len(domainBL.ListedOn) != 1 || len(domainBL.CleanOn) != 0 {
		t.Fatalf("domain BL responses misclassified: %#v", domainBL)
	}
}

func TestProtocolCapabilityTokensRequireExactExtension(t *testing.T) {
	if smtpLinesContain([]string{"250-XSTARTTLS"}, "STARTTLS") {
		t.Fatal("XSTARTTLS was treated as STARTTLS")
	}
	if !smtpLinesContain([]string{"250-STARTTLS", "250 AUTH=PLAIN"}, "STARTTLS") {
		t.Fatal("STARTTLS was not detected")
	}
	if smtpLinesContain([]string{"NO-STLS"}, "STLS") {
		t.Fatal("NO-STLS was treated as STLS")
	}
}

func TestRejectedMDACapabilitiesAreErrors(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		response string
		check    func(*MDAReport, net.Conn, *bufio.Reader) MDAReport
	}{
		{name: "imap", protocol: "imap", response: "a001 NO unavailable\r\n", check: checkIMAPCapability},
		{name: "pop3", protocol: "pop3", response: "-ERR unsupported\r\n", check: checkPOP3Capability},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			go func() {
				defer server.Close()
				_, _ = bufio.NewReader(server).ReadString('\n')
				_, _ = io.WriteString(server, test.response)
			}()
			report := test.check(&MDAReport{Host: "mail.example.com", Protocol: test.protocol}, client, bufio.NewReader(client))
			if report.Error == "" || report.CapabilityOK {
				t.Fatalf("report = %#v", report)
			}
		})
	}
}

func TestMDAPlaintextSessionsParseCapabilities(t *testing.T) {
	tests := []struct {
		name       string
		protocol   string
		banner     string
		response   string
		wantNotice string
	}{
		{
			name:       "imap",
			protocol:   "imap",
			banner:     "* OK IMAP ready\r\n",
			response:   "* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\na001 OK CAPABILITY completed\r\n",
			wantNotice: "STARTTLS is not advertised",
		},
		{
			name:       "pop3",
			protocol:   "pop3",
			banner:     "+OK POP3 ready\r\n",
			response:   "+OK capability list\r\nUSER\r\nUIDL\r\n.\r\n",
			wantNotice: "STLS is not advertised",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(time.Second))
			serverErr := make(chan error, 1)
			go func() {
				defer server.Close()
				if _, err := io.WriteString(server, test.banner); err != nil {
					serverErr <- err
					return
				}
				if _, err := bufio.NewReader(server).ReadString('\n'); err != nil {
					serverErr <- err
					return
				}
				_, err := io.WriteString(server, test.response)
				serverErr <- err
			}()
			report := checkMDAProtocol(&MDAReport{Host: "mail.example.com", Protocol: test.protocol}, client)
			if err := <-serverErr; err != nil {
				t.Fatal(err)
			}
			if report.Error != "" || !report.CapabilityOK || !strings.Contains(report.Warning, test.wantNotice) {
				t.Fatalf("report = %#v", report)
			}
		})
	}
}

func TestMDAHostPlainSessionEndToEnd(t *testing.T) {
	client, server := net.Pipe()
	serverErr := make(chan error, 1)
	go func() {
		defer server.Close()
		if _, err := io.WriteString(server, "* OK IMAP ready\r\n"); err != nil {
			serverErr <- err
			return
		}
		reader := bufio.NewReader(server)
		line, err := reader.ReadString('\n')
		if err != nil {
			serverErr <- err
			return
		}
		if line != "a001 CAPABILITY\r\n" {
			serverErr <- fmt.Errorf("unexpected command %q", line)
			return
		}
		_, err = io.WriteString(server, "* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\na001 OK done\r\n")
		serverErr <- err
	}()
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "imap.example.com:143" {
			return nil, fmt.Errorf("unexpected dial %s %s", network, address)
		}
		return client, nil
	}
	report := checkMDAHostWithDial(context.Background(), "imap.example.com", 143, time.Second, dial)
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	if !report.ConnectOK || !report.CapabilityOK || report.TLSOK || report.Warning != "IMAP STARTTLS is not advertised" {
		t.Fatalf("report = %#v", report)
	}
}

func TestMDAImplicitTLSSessionsEndToEnd(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		port     int
		banner   string
		command  string
		response string
	}{
		{
			name:     "imaps",
			host:     "imap.example.com",
			port:     993,
			banner:   "* OK IMAPS ready\r\n",
			command:  "a001 CAPABILITY\r\n",
			response: "* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\na001 OK done\r\n",
		},
		{
			name:     "pop3s",
			host:     "pop.example.com",
			port:     995,
			banner:   "+OK POP3S ready\r\n",
			command:  "CAPA\r\n",
			response: "+OK capability list\r\nUSER\r\nUIDL\r\n.\r\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			serverTLSConfig, clientTLSConfig := testTLSConfigs(t, test.host)
			client, server := net.Pipe()
			serverErr := make(chan error, 1)
			go func() {
				defer server.Close()
				tlsServer := tls.Server(server, serverTLSConfig)
				if err := tlsServer.Handshake(); err != nil {
					serverErr <- err
					return
				}
				if _, err := io.WriteString(tlsServer, test.banner); err != nil {
					serverErr <- err
					return
				}
				line, err := bufio.NewReader(tlsServer).ReadString('\n')
				if err != nil || line != test.command {
					serverErr <- fmt.Errorf("command: line=%q err=%v", line, err)
					return
				}
				_, err = io.WriteString(tlsServer, test.response)
				serverErr <- err
			}()
			dial := func(context.Context, string, string) (net.Conn, error) { return client, nil }
			report := checkMDAHostWithDialAndTLS(context.Background(), test.host, test.port, time.Second, dial, clientTLSConfig)
			if err := <-serverErr; err != nil {
				t.Fatal(err)
			}
			if !report.ConnectOK || !report.TLSOK || !report.CapabilityOK || report.Error != "" || report.TLSVersion == "" || report.CertDaysRemaining < 28 {
				t.Fatalf("report = %#v", report)
			}
		})
	}
}

func TestMDASTARTTLSSessionsEndToEnd(t *testing.T) {
	tests := []struct {
		name               string
		host               string
		port               int
		banner             string
		capabilityCommand  string
		capabilityResponse string
		startTLSCommand    string
		startTLSResponse   string
	}{
		{
			name:               "imap STARTTLS",
			host:               "imap.example.com",
			port:               143,
			banner:             "* OK IMAP ready\r\n",
			capabilityCommand:  "a001 CAPABILITY\r\n",
			capabilityResponse: "* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK done\r\n",
			startTLSCommand:    "a002 STARTTLS\r\n",
			startTLSResponse:   "a002 OK begin TLS\r\n",
		},
		{
			name:               "POP3 STLS",
			host:               "pop.example.com",
			port:               110,
			banner:             "+OK POP3 ready\r\n",
			capabilityCommand:  "CAPA\r\n",
			capabilityResponse: "+OK capability list\r\nSTLS\r\nUSER\r\n.\r\n",
			startTLSCommand:    "STLS\r\n",
			startTLSResponse:   "+OK begin TLS\r\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			serverTLSConfig, clientTLSConfig := testTLSConfigs(t, test.host)
			client, server := net.Pipe()
			serverErr := make(chan error, 1)
			go func() {
				defer server.Close()
				if _, err := io.WriteString(server, test.banner); err != nil {
					serverErr <- err
					return
				}
				reader := bufio.NewReader(server)
				line, err := reader.ReadString('\n')
				if err != nil || line != test.capabilityCommand {
					serverErr <- fmt.Errorf("capability command: line=%q err=%v", line, err)
					return
				}
				if _, err := io.WriteString(server, test.capabilityResponse); err != nil {
					serverErr <- err
					return
				}
				line, err = reader.ReadString('\n')
				if err != nil || line != test.startTLSCommand {
					serverErr <- fmt.Errorf("TLS command: line=%q err=%v", line, err)
					return
				}
				if _, err := io.WriteString(server, test.startTLSResponse); err != nil {
					serverErr <- err
					return
				}
				tlsServer := tls.Server(server, serverTLSConfig)
				serverErr <- tlsServer.Handshake()
			}()
			dial := func(context.Context, string, string) (net.Conn, error) { return client, nil }
			report := checkMDAHostWithDialAndTLS(context.Background(), test.host, test.port, time.Second, dial, clientTLSConfig)
			if err := <-serverErr; err != nil {
				t.Fatal(err)
			}
			if !report.ConnectOK || !report.CapabilityOK || !report.STARTTLSOffered || !report.TLSOK || report.Error != "" || report.TLSVersion == "" || report.CertDaysRemaining < 28 {
				t.Fatalf("report = %#v", report)
			}
		})
	}
}

func TestSMTPResponseRejectsExcessiveContinuation(t *testing.T) {
	var input strings.Builder
	for range 51 {
		input.WriteString("250-more\r\n")
	}
	code, lines, err := readSMTPResponse(bufio.NewReader(strings.NewReader(input.String())))
	if err == nil || code != 250 || len(lines) != 50 || !strings.Contains(err.Error(), "continuation limit") {
		t.Fatalf("code=%d lines=%d err=%v", code, len(lines), err)
	}
}

func TestSMTPRelayProbeDetectsAcceptedAndRejectedRecipient(t *testing.T) {
	for _, test := range []struct {
		name     string
		rcptCode int
		open     bool
	}{
		{name: "accepted", rcptCode: 250, open: true},
		{name: "rejected", rcptCode: 550, open: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(time.Second))
			serverErr := make(chan error, 1)
			go func() {
				defer server.Close()
				reader := bufio.NewReader(server)
				for i, response := range []string{"250 sender ok\r\n", fmt.Sprintf("%d recipient\r\n", test.rcptCode), "250 reset\r\n"} {
					line, err := reader.ReadString('\n')
					if err != nil {
						serverErr <- err
						return
					}
					if i == 0 && !strings.HasPrefix(line, "MAIL FROM:") {
						serverErr <- fmt.Errorf("unexpected command %q", line)
						return
					}
					if _, err := io.WriteString(server, response); err != nil {
						serverErr <- err
						return
					}
				}
				serverErr <- nil
			}()
			report := SMTPReport{}
			runSMTPRelayProbe(&report, client, bufio.NewReader(client), "plain")
			if err := <-serverErr; err != nil {
				t.Fatal(err)
			}
			if !report.RelayCheck || report.RelayMailCode != 250 || report.RelayRcptCode != test.rcptCode || report.OpenRelay != test.open {
				t.Fatalf("report = %#v", report)
			}
		})
	}
}

func TestSMTPHostPlainSessionEndToEnd(t *testing.T) {
	client, server := net.Pipe()
	serverErr := make(chan error, 1)
	go func() {
		defer server.Close()
		if _, err := io.WriteString(server, "220 mx.example.com ESMTP ready\r\n"); err != nil {
			serverErr <- err
			return
		}
		reader := bufio.NewReader(server)
		line, err := reader.ReadString('\n')
		if err != nil {
			serverErr <- err
			return
		}
		if line != "EHLO mailops.local\r\n" {
			serverErr <- fmt.Errorf("unexpected EHLO %q", line)
			return
		}
		_, err = io.WriteString(server, "250-mx.example.com\r\n250 AUTH PLAIN LOGIN\r\n")
		serverErr <- err
	}()
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "mx.example.com:25" {
			return nil, fmt.Errorf("unexpected dial %s %s", network, address)
		}
		return client, nil
	}
	report := checkSMTPHostWithDial(context.Background(), "mx.example.com", 25, time.Second, false, dial)
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	if !report.ConnectOK || !report.EHLOOK || report.STARTTLSOffered || report.TLSOK || report.Warning != "STARTTLS is not advertised" {
		t.Fatalf("report = %#v", report)
	}
	if strings.Join(report.AuthMechanisms, ",") != "LOGIN,PLAIN" {
		t.Fatalf("auth mechanisms = %#v", report.AuthMechanisms)
	}
}

func TestSMTPHostSTARTTLSEndToEnd(t *testing.T) {
	serverTLSConfig, clientTLSConfig := testTLSConfigs(t, "smtp.example.com")
	client, server := net.Pipe()
	serverErr := make(chan error, 1)
	go func() {
		defer server.Close()
		if _, err := io.WriteString(server, "220 smtp.example.com ESMTP ready\r\n"); err != nil {
			serverErr <- err
			return
		}
		reader := bufio.NewReader(server)
		line, err := reader.ReadString('\n')
		if err != nil || line != "EHLO mailops.local\r\n" {
			serverErr <- fmt.Errorf("plain EHLO: line=%q err=%v", line, err)
			return
		}
		if _, err := io.WriteString(server, "250-smtp.example.com\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n"); err != nil {
			serverErr <- err
			return
		}
		line, err = reader.ReadString('\n')
		if err != nil || line != "STARTTLS\r\n" {
			serverErr <- fmt.Errorf("STARTTLS: line=%q err=%v", line, err)
			return
		}
		if _, err := io.WriteString(server, "220 ready for TLS\r\n"); err != nil {
			serverErr <- err
			return
		}
		tlsServer := tls.Server(server, serverTLSConfig)
		if err := tlsServer.Handshake(); err != nil {
			serverErr <- err
			return
		}
		line, err = bufio.NewReader(tlsServer).ReadString('\n')
		if err != nil || line != "EHLO mailops.local\r\n" {
			serverErr <- fmt.Errorf("TLS EHLO: line=%q err=%v", line, err)
			return
		}
		_, err = io.WriteString(tlsServer, "250-smtp.example.com\r\n250 AUTH LOGIN XOAUTH2\r\n")
		serverErr <- err
	}()
	dial := func(context.Context, string, string) (net.Conn, error) { return client, nil }
	report := checkSMTPHostWithDialAndTLS(context.Background(), "smtp.example.com", 587, time.Second, false, dial, clientTLSConfig)
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	if !report.ConnectOK || !report.EHLOOK || !report.STARTTLSOffered || !report.STARTTLSOK || !report.TLSOK || report.ImplicitTLS {
		t.Fatalf("report = %#v", report)
	}
	if strings.Join(report.AuthMechanisms, ",") != "LOGIN,PLAIN,XOAUTH2" {
		t.Fatalf("auth mechanisms = %#v", report.AuthMechanisms)
	}
}

func TestSMTPHostImplicitTLSEndToEnd(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mx.example.com"},
		DNSNames:     []string{"mx.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	serverCertificate := tls.Certificate{Certificate: [][]byte{certificateDER}, PrivateKey: privateKey}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	client, server := net.Pipe()
	serverErr := make(chan error, 1)
	go func() {
		defer server.Close()
		tlsServer := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{serverCertificate}, MinVersion: tls.VersionTLS12})
		if err := tlsServer.Handshake(); err != nil {
			serverErr <- err
			return
		}
		if _, err := io.WriteString(tlsServer, "220 mx.example.com ESMTP ready\r\n"); err != nil {
			serverErr <- err
			return
		}
		reader := bufio.NewReader(tlsServer)
		line, err := reader.ReadString('\n')
		if err != nil {
			serverErr <- err
			return
		}
		if line != "EHLO mailops.local\r\n" {
			serverErr <- fmt.Errorf("unexpected EHLO %q", line)
			return
		}
		_, err = io.WriteString(tlsServer, "250-mx.example.com\r\n250 AUTH PLAIN LOGIN\r\n")
		serverErr <- err
	}()
	dial := func(context.Context, string, string) (net.Conn, error) { return client, nil }
	tlsConfig := func(serverName string) *tls.Config {
		return &tls.Config{ServerName: serverName, RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	report := checkSMTPHostWithDialAndTLS(context.Background(), "mx.example.com", 465, time.Second, false, dial, tlsConfig)
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	if !report.ConnectOK || !report.ImplicitTLS || !report.TLSOK || !report.EHLOOK || report.TLSVersion == "" || report.CertDaysRemaining < 28 {
		t.Fatalf("report = %#v", report)
	}
	if strings.Join(report.AuthMechanisms, ",") != "LOGIN,PLAIN" {
		t.Fatalf("auth mechanisms = %#v", report.AuthMechanisms)
	}
}

func TestSMTPAndMDAFindingSeverity(t *testing.T) {
	smtp := smtpFindings([]SMTPReport{
		{Host: "mx1", Port: 25, Error: "dial failed"},
		{Host: "mx2", Port: 25, ConnectOK: true, OpenRelay: true, RelayStage: "plain"},
		{Host: "mx3", Port: 587, ConnectOK: true, RelayError: "timeout", Warning: "STARTTLS is not advertised"},
	}, true)
	if len(smtp) != 5 || smtp[0].Severity != SeverityCritical || smtp[1].Severity != SeverityCritical || smtp[len(smtp)-1].Severity != SeverityCritical {
		t.Fatalf("SMTP findings = %#v", smtp)
	}
	mda := mdaFindings([]MDAReport{
		{Host: "imap", Port: 993, Error: "dial failed"},
		{Host: "pop", Port: 110, Warning: "POP3 STLS is not advertised"},
	}, true, true)
	if len(mda) != 2 || mda[0].Severity != SeverityCritical || mda[1].Severity != SeverityCritical {
		t.Fatalf("MDA findings = %#v", mda)
	}
}

func TestTLSStateAndProtocolHelpers(t *testing.T) {
	soon := &x509.Certificate{NotAfter: time.Now().Add(5 * 24 * time.Hour)}
	smtp := SMTPReport{}
	applySMTPState(&smtp, tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{soon}})
	if smtp.TLSVersion != "TLS1.3" || !strings.Contains(smtp.Warning, "expires") {
		t.Fatalf("SMTP TLS state = %#v", smtp)
	}
	expired := &x509.Certificate{NotAfter: time.Now().Add(-24 * time.Hour)}
	mda := MDAReport{Protocol: "imaps"}
	applyMDAState(&mda, tls.ConnectionState{Version: tls.VersionTLS12, PeerCertificates: []*x509.Certificate{expired}})
	if mda.TLSVersion != "TLS1.2" || !strings.Contains(mda.Error, "expired") {
		t.Fatalf("MDA TLS state = %#v", mda)
	}
	if tlsVersionName(tls.VersionTLS11) != "TLS1.1" || tlsVersionName(0xffff) != "0xffff" {
		t.Fatal("unexpected TLS version name")
	}
	merged := mergeStrings([]string{"B", "A"}, []string{"A", "C", ""})
	if strings.Join(merged, ",") != "A,B,C" {
		t.Fatalf("merged = %#v", merged)
	}
}

func TestBIMIValidationAndFindings(t *testing.T) {
	r := fakeResolver{txt: map[string][]string{
		"default._bimi.example.com": {"v=BIMI1; l=https://example.com/logo.svg"},
	}, errors: map[string]error{}}
	report := checkBIMI(context.Background(), r, "example.com", DMARCReport{Policy: "none"})
	if !report.Valid || report.Warning == "" || len(bimiFindings(report)) != 1 {
		t.Fatalf("BIMI report = %#v", report)
	}
	declinedResolver := fakeResolver{txt: map[string][]string{
		"default._bimi.example.com": {"v=BIMI1; l=; a="},
	}, errors: map[string]error{}}
	declined := checkBIMI(context.Background(), declinedResolver, "example.com", DMARCReport{Policy: "reject", Pct: 100})
	if !declined.Valid || !declined.Declined || declined.Warning == "" {
		t.Fatalf("declination parsed incorrectly: %#v", declined)
	}
}

func TestBIMIResolverFailureProducesFinding(t *testing.T) {
	r := fakeResolver{errors: map[string]error{"txt:default._bimi.example.com": errors.New("resolver timeout")}}
	report := checkBIMI(context.Background(), r, "example.com", DMARCReport{})
	findings := bimiFindings(report)
	if report.Error == "" || len(findings) != 1 || findings[0].Severity != SeverityWarn {
		t.Fatalf("BIMI resolver failure was hidden: report=%#v findings=%#v", report, findings)
	}
}

func TestSMTPReadStopsAtContextDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	dial := func(context.Context, string, string) (net.Conn, error) { return client, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	start := time.Now()
	report := checkSMTPHostWithDial(ctx, "mx.example.com", 25, time.Second, false, dial)
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("SMTP read ignored context deadline: %s", elapsed)
	}
	if report.Error == "" {
		t.Fatalf("deadline did not fail stalled SMTP probe: %#v", report)
	}
}

func TestBIMIRejectsUnsafeURIsWeakDMARCAndMultipleRecords(t *testing.T) {
	tests := []struct {
		name   string
		record string
	}{
		{name: "HTTP logo", record: "v=BIMI1; l=http://example.com/logo.svg"},
		{name: "non SVG logo", record: "v=BIMI1; l=https://example.com/logo.png"},
		{name: "relative logo", record: "v=BIMI1; l=/logo.svg"},
		{name: "IP address logo", record: "v=BIMI1; l=https://192.0.2.1/logo.svg"},
		{name: "HTTP authority", record: "v=BIMI1; l=https://example.com/logo.svg; a=http://example.com/vmc.pem"},
		{name: "wrong case version", record: "v=bimi1; l=https://example.com/logo.svg"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := fakeResolver{txt: map[string][]string{"default._bimi.example.com": {test.record}}, errors: map[string]error{}}
			report := checkBIMI(context.Background(), r, "example.com", DMARCReport{Policy: "reject", Pct: 100})
			if test.name == "wrong case version" {
				if report.Present {
					t.Fatalf("wrong version accepted: %#v", report)
				}
				return
			}
			if !report.Present || report.Valid || report.Error == "" {
				t.Fatalf("invalid BIMI accepted: %#v", report)
			}
		})
	}
	weakDMARCResolver := fakeResolver{txt: map[string][]string{
		"default._bimi.example.com": {"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"},
	}, errors: map[string]error{}}
	weakDMARC := checkBIMI(context.Background(), weakDMARCResolver, "example.com", DMARCReport{Policy: "reject", EffectivePolicy: "none", Testing: true, Pct: 100})
	if !weakDMARC.Valid || !strings.Contains(weakDMARC.Warning, "effective DMARC") {
		t.Fatalf("weak DMARC compatibility missed: %#v", weakDMARC)
	}
	multipleResolver := fakeResolver{txt: map[string][]string{
		"default._bimi.example.com": {
			"v=BIMI1; l=https://example.com/one.svg",
			"v=BIMI1; l=https://example.com/two.svg",
		},
	}, errors: map[string]error{}}
	multiple := checkBIMI(context.Background(), multipleResolver, "example.com", DMARCReport{Policy: "reject", Pct: 100})
	if multiple.Valid || !strings.Contains(multiple.Error, "multiple") {
		t.Fatalf("multiple BIMI records accepted: %#v", multiple)
	}
}

func TestBIMIAssetInspectionValidatesTinyPSAndAuthorityCertificate(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t, "example.com")
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverTLS.Certificates[0].Certificate[0]})
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := []byte(`<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps"><title>Example</title></svg>`)
		contentType := "image/svg+xml"
		if strings.HasSuffix(request.URL.Path, ".pem") {
			body = certificatePEM
			contentType = "application/x-pem-file"
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{contentType}},
			Body:       io.NopCloser(strings.NewReader(string(body))),
			Request:    request,
		}, nil
	})}
	r := fakeResolver{ips: map[string][]net.IPAddr{"example.com": {{IP: net.ParseIP("1.1.1.1")}}}, errors: map[string]error{}}
	report := BIMIReport{
		Present:      true,
		Valid:        true,
		LogoURL:      "https://example.com/logo.svg",
		AuthorityURL: "https://example.com/vmc.pem",
	}
	inspectBIMIAssetsWithClient(context.Background(), r, &report, false, client)
	if report.AssetError != "" || !report.LogoFetched || !report.LogoValid || !report.AuthorityFetched || !report.AuthorityValid {
		t.Fatalf("valid BIMI assets rejected: %#v", report)
	}

	if err := validateBIMISVG([]byte(`<svg version="1.2" baseProfile="tiny-ps"><script/></svg>`), "image/svg+xml"); err == nil {
		t.Fatal("active SVG content accepted")
	}
}

func TestBIMIRejectsDuplicateTags(t *testing.T) {
	r := fakeResolver{txt: map[string][]string{
		"default._bimi.example.com": {"v=BIMI1; l=https://example.com/one.svg; l=https://example.com/two.svg"},
	}, errors: map[string]error{}}
	report := checkBIMI(context.Background(), r, "example.com", DMARCReport{EffectivePolicy: "reject"})
	if report.Valid || !strings.Contains(report.Error, "duplicate") {
		t.Fatalf("duplicate BIMI tags accepted: %#v", report)
	}
}

func TestEmptyActiveProbeSetsDoNotDial(t *testing.T) {
	if got := checkSMTP(context.Background(), nil, nil, nil, time.Second, true); len(got) != 0 {
		t.Fatalf("SMTP rows = %#v", got)
	}
	if got := checkMDA(context.Background(), "example.com", []string{"imap.example.com"}, nil, time.Second, false); len(got) != 0 {
		t.Fatalf("MDA rows = %#v", got)
	}
	if got := checkSMTPHost(context.Background(), "", 25, time.Second, false); got.Error != "empty MX host" {
		t.Fatalf("SMTP empty host = %#v", got)
	}
}

func TestDomainAndMDAEndpointNormalization(t *testing.T) {
	if got := normalizeDomain(" HTTPS://Mail.Example.COM:8443/path?q=1 "); got != "mail.example.com" {
		t.Fatalf("domain = %q", got)
	}
	if got := normalizeDomain("Żółw.example"); got != "xn--w-uga1v8h.example" {
		t.Fatalf("IDN domain = %q", got)
	}
	if got := domainFromMailto("mailto:reports@Reports.Example.NET!10m"); got != "reports.example.net" {
		t.Fatalf("mailto domain = %q", got)
	}
	if got := probableMDAPorts("imap.example.com", []int{110, 143, 993, 995}); len(got) != 2 || got[0] != 143 || got[1] != 993 {
		t.Fatalf("IMAP ports = %#v", got)
	}
	if got := probableMDAPorts("pop.example.com", []int{110, 143, 993, 995}); len(got) != 2 || got[0] != 110 || got[1] != 995 {
		t.Fatalf("POP3 ports = %#v", got)
	}
	if !mdaImplicitTLS(993) || !mdaImplicitTLS(995) || mdaImplicitTLS(143) {
		t.Fatal("unexpected implicit TLS port classification")
	}
}

func TestCustomResolverValidationAndLabel(t *testing.T) {
	_, endpoint, err := newCustomResolver("1.1.1.1")
	if err != nil || endpoint != "1.1.1.1:53" {
		t.Fatalf("resolver endpoint = %q, %v", endpoint, err)
	}
	_, endpoint, err = newCustomResolver("[2606:4700:4700::1111]:5353")
	if err != nil || endpoint != "[2606:4700:4700::1111]:5353" {
		t.Fatalf("IPv6 resolver endpoint = %q, %v", endpoint, err)
	}
	report := Run(context.Background(), Options{Domain: "example.com", ResolverAddress: "bad:address:syntax", Timeout: time.Second})
	if report.Status != SeverityError || report.Resolver != "bad:address:syntax" || !strings.Contains(report.Error, "invalid resolver") {
		t.Fatalf("invalid resolver report = %#v", report)
	}
}

func TestActiveTargetPolicyBlocksPrivateAndSpecialAddresses(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "192.0.2.1", "2001:db8::1"} {
		address, err := netip.ParseAddr(raw)
		if err != nil || !unsafeTargetAddress(address) {
			t.Fatalf("unsafe address %q accepted", raw)
		}
	}
	if unsafeTargetAddress(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("public address rejected")
	}

	r := fakeResolver{
		txt: map[string][]string{"_mta-sts.example.com": {"v=STSv1; id=one"}},
		ips: map[string][]net.IPAddr{
			"smtp.example.com":    {{IP: net.ParseIP("10.0.0.5")}},
			"imap.example.com":    {{IP: net.ParseIP("127.0.0.1")}},
			"mta-sts.example.com": {{IP: net.ParseIP("192.0.2.5")}},
		},
		errors: map[string]error{},
	}
	smtp := checkSMTPWithTargetPolicy(context.Background(), r, nil, []string{"smtp.example.com"}, []int{25}, time.Second, false, false)
	if len(smtp) != 1 || !strings.Contains(smtp[0].Error, "target blocked") {
		t.Fatalf("private SMTP target was probed: %#v", smtp)
	}
	mda := checkMDAWithTargetPolicy(context.Background(), r, "example.com", []string{"imap.example.com"}, []int{143}, time.Second, true, false)
	if len(mda) != 1 || !strings.Contains(mda[0].Error, "target blocked") {
		t.Fatalf("private MDA target was probed: %#v", mda)
	}
	mtaSTS := checkMTASTSWithTargetPolicy(context.Background(), r, "example.com", time.Second, false)
	if !mtaSTS.TXTPresent || !strings.Contains(mtaSTS.Error, "target blocked") {
		t.Fatalf("private MTA-STS target was fetched: %#v", mtaSTS)
	}
}

func TestExternalDMARCReportsUseOrganizationalDomains(t *testing.T) {
	tests := []struct {
		name   string
		source string
		rua    string
		want   bool
	}{
		{name: "same domain", source: "example.com", rua: "mailto:dmarc@example.com", want: false},
		{name: "parent organizational domain", source: "mail.example.co.uk", rua: "mailto:dmarc@example.co.uk", want: false},
		{name: "sibling organizational domain", source: "mail.example.co.uk", rua: "mailto:dmarc@reports.example.co.uk", want: false},
		{name: "external domain", source: "example.co.uk", rua: "mailto:dmarc@example.net", want: true},
		{name: "private suffix tenants", source: "one.appspot.com", rua: "mailto:dmarc@two.appspot.com", want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := externalReportDomain(test.source, test.rua); got != test.want {
				t.Fatalf("externalReportDomain(%q, %q) = %t, want %t", test.source, test.rua, got, test.want)
			}
		})
	}
}

func TestSmallDNSPolicyHelpers(t *testing.T) {
	if !hasMTASTSTXTRecord([]string{"unrelated", "v=STSv1; id=one"}) || hasMTASTSTXTRecord([]string{"unrelated"}) {
		t.Fatal("unexpected MTA-STS TXT detection")
	}
	if !containsDMARCReportAuth([]string{"v=DMARC1; p=none"}) || containsDMARCReportAuth([]string{"v=DMARC10; p=none"}) {
		t.Fatal("unexpected DMARC report authorization detection")
	}
	missing := checkMTASTS(context.Background(), fakeResolver{txt: map[string][]string{}, errors: map[string]error{}}, "example.com", time.Second)
	if missing.TXTPresent || missing.Warning != "MTA-STS TXT record is missing" {
		t.Fatalf("missing MTA-STS report = %#v", missing)
	}
}
