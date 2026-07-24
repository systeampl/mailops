package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/systeampl/mailops/internal/mailcheck"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestOTELDataPointsPreserveZeroValuesAndOneOfType(t *testing.T) {
	floatJSON, err := json.Marshal(otelMetricFloat("ratio", "", "1", nil, 0, time.Unix(1, 0)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(floatJSON), `"asDouble":0`) || strings.Contains(string(floatJSON), `"asInt"`) {
		t.Fatalf("float metric JSON = %s", floatJSON)
	}
	intJSON, err := json.Marshal(otelMetricInt("count", "", "", nil, 0, time.Unix(1, 0)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(intJSON), `"asInt":"0"`) || strings.Contains(string(intJSON), `"asDouble"`) {
		t.Fatalf("int metric JSON = %s", intJSON)
	}
}

func TestPostOTLPUsesMetricsPathAndServiceResource(t *testing.T) {
	var path, body string
	originalTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = originalTransport })
	http.DefaultTransport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		path = request.URL.Path
		data, _ := io.ReadAll(request.Body)
		body = string(data)
		return &http.Response{StatusCode: http.StatusAccepted, Status: "202 Accepted", Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	})
	if err := postOTLP("https://collector.example", "mailops-test", []otelMetric{otelMetricInt("count", "", "", nil, 1, time.Now())}); err != nil {
		t.Fatal(err)
	}
	if path != "/v1/metrics" || !strings.Contains(body, `"service.name"`) || !strings.Contains(body, `"mailops-test"`) {
		t.Fatalf("path=%q body=%s", path, body)
	}
}

func TestPostOTLPReturnsHTTPError(t *testing.T) {
	originalTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = originalTransport })
	http.DefaultTransport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadRequest, Status: "400 Bad Request", Header: http.Header{}, Body: io.NopCloser(strings.NewReader("no")), Request: request}, nil
	})
	if err := postOTLP("https://collector.example/v1/metrics", "mailops", nil); err == nil {
		t.Fatal("expected OTLP HTTP error")
	}
}

func TestExportReportsOTELBuildsCompletePayload(t *testing.T) {
	originalTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = originalTransport })
	var body string
	http.DefaultTransport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		data, _ := io.ReadAll(request.Body)
		body = string(data)
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	})
	report := mailcheck.Report{
		Domain:      "example.com",
		Status:      "warn",
		GeneratedAt: time.Unix(100, 0),
		DKIM:        []mailcheck.DKIMReport{{Selector: "s1", Valid: true}},
		PTR:         []mailcheck.PTRReport{{IP: "192.0.2.1", ForwardConfirmed: true}},
		RBL:         []mailcheck.RBLReport{{IP: "192.0.2.1", ListedOn: []string{"rbl.test"}}},
		DomainBL: []mailcheck.DomainBLReport{{
			CleanOn: []string{"clean.test"}, ListedOn: []string{"listed.test"}, ErrorOn: []string{"error.test"},
		}},
		SMTP: []mailcheck.SMTPReport{{Host: "mx", Port: 25, ConnectOK: true, RelayCheck: true, RelayMailCode: 250, RelayRcptCode: 550}},
		MDA:  []mailcheck.MDAReport{{Host: "imap", Port: 993, Protocol: "imaps", ConnectOK: true, TLSOK: true}},
	}
	if err := exportReportsOTEL("https://collector.example", []mailcheck.Report{report}); err != nil {
		t.Fatal(err)
	}
	for _, metric := range []string{"mailops.check.up", "mailops.dkim.selector_ok", "mailops.rbl.listed", "mailops.domainbl.lookup_error", "mailops.smtp.relay_rcpt_code", "mailops.mda.tls_ok"} {
		if !strings.Contains(body, `"`+metric+`"`) {
			t.Fatalf("payload missing %s", metric)
		}
	}
	if err := exportReportsOTEL("", []mailcheck.Report{report}); err != nil {
		t.Fatalf("empty endpoint should be disabled: %v", err)
	}
}
