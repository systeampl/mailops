package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	mailcheck "github.com/systeampl/mailops/pkg/mailops"
)

type otelPayload struct {
	ResourceMetrics []otelResourceMetric `json:"resourceMetrics"`
}

type otelResourceMetric struct {
	Resource     otelResource      `json:"resource"`
	ScopeMetrics []otelScopeMetric `json:"scopeMetrics"`
}

type otelResource struct {
	Attributes []otelAttribute `json:"attributes"`
}

type otelScopeMetric struct {
	Scope   otelScope    `json:"scope"`
	Metrics []otelMetric `json:"metrics"`
}

type otelScope struct {
	Name string `json:"name"`
}

type otelMetric struct {
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Unit        string    `json:"unit,omitempty"`
	Gauge       otelGauge `json:"gauge"`
}

type otelGauge struct {
	DataPoints []otelDataPoint `json:"dataPoints"`
}

type otelDataPoint struct {
	Attributes   []otelAttribute `json:"attributes,omitempty"`
	TimeUnixNano string          `json:"timeUnixNano"`
	AsInt        *string         `json:"asInt,omitempty"`
	AsDouble     *float64        `json:"asDouble,omitempty"`
}

type otelAttribute struct {
	Key   string    `json:"key"`
	Value otelValue `json:"value"`
}

type otelValue struct {
	StringValue string `json:"stringValue,omitempty"`
}

func exportReportsOTEL(ctx context.Context, endpoint string, reports []mailcheck.Report) error {
	if strings.TrimSpace(endpoint) == "" {
		return nil
	}
	now := time.Now()
	metrics := make([]otelMetric, 0, len(reports)*18)
	for _, report := range reports {
		base := map[string]string{"domain": report.Domain}
		metrics = append(metrics,
			otelMetricInt("mailops.check.up", "Mailops check execution health", "", base, boolInt(report.Error == "" && report.Status != mailcheck.SeverityError), now),
			otelMetricFloat("mailops.check.duration", "Mailops check duration", "s", base, float64(report.DurationMS)/1000, now),
			otelMetricInt("mailops.last_check.timestamp", "Unix timestamp of the last completed check", "s", base, int(report.GeneratedAt.Unix()), now),
			otelMetricInt("mailops.status_code", "Aggregate status as a numeric code", "", base, statusCode(report.Status), now),
			otelMetricInt("mailops.posture.status_code", "Configuration posture status as a numeric code", "", base, statusCode(report.PostureStatus), now),
			otelMetricInt("mailops.availability.status_code", "Active service availability status as a numeric code", "", base, statusCode(report.AvailabilityStatus), now),
		)
		for _, status := range []string{"ok", "warn", "critical", "error"} {
			metrics = append(metrics, otelMetricInt("mailops.status", "Mail deliverability aggregate status", "", map[string]string{
				"domain": report.Domain,
				"status": status,
			}, boolInt(report.Status == status), now))
		}
		metrics = append(metrics,
			otelMetricInt("mailops.mx.records", "Number of MX records", "", base, report.RecordCounts.MX, now),
			otelMetricInt("mailops.spf.estimated_lookups", "Estimated SPF lookup count", "", base, report.SPF.EstimatedLookups, now),
			otelMetricFloat("mailops.spf.lookup_limit_used", "SPF DNS lookup limit utilization", "1", base, float64(report.SPF.EstimatedLookups)/10, now),
			otelMetricInt("mailops.dmarc.pct", "DMARC pct tag value", "", base, report.DMARC.Pct, now),
			otelMetricInt("mailops.dnssec.secure", "DNS response authentication through DNSSEC", "", base, boolInt(report.DNSSEC.Secure), now),
			otelMetricInt("mailops.dkim.valid_selectors", "Number of valid DKIM selectors found", "", base, report.RecordCounts.DKIM, now),
			otelMetricFloat("mailops.mta_sts.mx_matched_ratio", "Ratio of MX hosts covered by the MTA-STS policy mx patterns", "1", base, ratio(report.MTASTS.MXMatched, report.MTASTS.MXTotal), now),
			otelMetricInt("mailops.record.present", "SPF record presence", "", map[string]string{"domain": report.Domain, "record": "spf"}, boolInt(report.SPF.Present), now),
			otelMetricInt("mailops.record.present", "DMARC record presence", "", map[string]string{"domain": report.Domain, "record": "dmarc"}, boolInt(report.DMARC.Present), now),
			otelMetricInt("mailops.record.present", "MTA-STS record presence", "", map[string]string{"domain": report.Domain, "record": "mta_sts"}, boolInt(report.MTASTS.TXTPresent), now),
			otelMetricInt("mailops.record.present", "TLS-RPT record presence", "", map[string]string{"domain": report.Domain, "record": "tls_rpt"}, boolInt(report.TLSRPT.Present), now),
			otelMetricInt("mailops.record.present", "BIMI record presence", "", map[string]string{"domain": report.Domain, "record": "bimi"}, boolInt(report.BIMI.Present), now),
			otelMetricInt("mailops.record.valid", "SPF record validity", "", map[string]string{"domain": report.Domain, "record": "spf"}, boolInt(report.SPF.Valid), now),
			otelMetricInt("mailops.record.valid", "DMARC record validity", "", map[string]string{"domain": report.Domain, "record": "dmarc"}, boolInt(report.DMARC.Valid), now),
			otelMetricInt("mailops.record.valid", "MTA-STS policy validity", "", map[string]string{"domain": report.Domain, "record": "mta_sts"}, boolInt(report.MTASTS.Valid), now),
			otelMetricInt("mailops.record.valid", "TLS-RPT record validity", "", map[string]string{"domain": report.Domain, "record": "tls_rpt"}, boolInt(report.TLSRPT.Valid), now),
			otelMetricInt("mailops.record.valid", "BIMI record validity", "", map[string]string{"domain": report.Domain, "record": "bimi"}, boolInt(report.BIMI.Valid), now),
		)
		for _, row := range report.DANE {
			labels := map[string]string{"domain": report.Domain, "host": row.Host, "port": strconv.Itoa(row.Port)}
			metrics = append(metrics,
				otelMetricInt("mailops.dane.tlsa_present", "TLSA record presence", "", labels, boolInt(row.Present), now),
				otelMetricInt("mailops.dane.tlsa_valid", "TLSA record syntax and DNSSEC validity", "", labels, boolInt(row.Valid), now),
				otelMetricInt("mailops.dane.tlsa_matched", "Observed SMTP certificate TLSA match", "", labels, boolInt(row.Matched), now),
			)
		}
		for _, sev := range []string{"info", "warn", "critical", "error"} {
			metrics = append(metrics, otelMetricInt("mailops.findings", "Number of findings by severity", "", map[string]string{
				"domain":   report.Domain,
				"severity": sev,
			}, findingCount(report, sev), now))
		}
		for _, row := range report.DKIM {
			metrics = append(metrics, otelMetricInt("mailops.dkim.selector_ok", "DKIM selector health", "", map[string]string{
				"domain":   report.Domain,
				"selector": row.Selector,
			}, boolInt(row.Valid), now))
		}
		ptrConfirmed, ptrTotal := ptrConfirmedCount(report)
		metrics = append(metrics,
			otelMetricInt("mailops.ptr.records", "Number of MX IPs checked for PTR", "", base, ptrTotal, now),
			otelMetricFloat("mailops.ptr.forward_confirmed_ratio", "Ratio of MX IPs with forward-confirmed PTR", "1", base, ratio(ptrConfirmed, ptrTotal), now),
			otelMetricInt("mailops.rbl.hits", "Number of DNSBL listings across checked MX IPs", "", base, report.RecordCounts.RBLHits, now),
			otelMetricInt("mailops.domainbl.hits", "Number of domain reputation DNSBL listings", "", base, report.RecordCounts.DomainBLHits, now),
		)
		for _, row := range report.RBL {
			metrics = append(metrics, otelMetricInt("mailops.rbl.listed", "DNSBL listing status per IP", "", map[string]string{
				"domain": report.Domain,
				"ip":     row.IP,
			}, boolInt(len(row.ListedOn) > 0), now))
			for _, zone := range row.CleanOn {
				metrics = append(metrics, otelMetricInt("mailops.rbl.lookup_error", "DNSBL lookup or provider response error per IP and zone", "", map[string]string{"domain": report.Domain, "ip": row.IP, "zone": zone}, 0, now))
			}
			for _, zone := range row.ListedOn {
				metrics = append(metrics, otelMetricInt("mailops.rbl.lookup_error", "DNSBL lookup or provider response error per IP and zone", "", map[string]string{"domain": report.Domain, "ip": row.IP, "zone": zone}, 0, now))
			}
			for _, zone := range row.ErrorOn {
				metrics = append(metrics, otelMetricInt("mailops.rbl.lookup_error", "DNSBL lookup or provider response error per IP and zone", "", map[string]string{"domain": report.Domain, "ip": row.IP, "zone": zone}, 1, now))
			}
		}
		for _, row := range report.DomainBL {
			for _, zone := range row.CleanOn {
				metrics = append(metrics, otelMetricInt("mailops.domainbl.listed", "Domain reputation DNSBL listing status per zone", "", map[string]string{
					"domain": report.Domain,
					"zone":   zone,
				}, 0, now))
				metrics = append(metrics, otelMetricInt("mailops.domainbl.lookup_error", "Domain reputation DNSBL lookup error per zone", "", map[string]string{
					"domain": report.Domain,
					"zone":   zone,
				}, 0, now))
			}
			for _, zone := range row.ListedOn {
				metrics = append(metrics, otelMetricInt("mailops.domainbl.listed", "Domain reputation DNSBL listing status per zone", "", map[string]string{
					"domain": report.Domain,
					"zone":   zone,
				}, 1, now))
				metrics = append(metrics, otelMetricInt("mailops.domainbl.lookup_error", "Domain reputation DNSBL lookup error per zone", "", map[string]string{
					"domain": report.Domain,
					"zone":   zone,
				}, 0, now))
			}
			for _, zone := range row.ErrorOn {
				metrics = append(metrics, otelMetricInt("mailops.domainbl.lookup_error", "Domain reputation DNSBL lookup error per zone", "", map[string]string{
					"domain": report.Domain,
					"zone":   zone,
				}, 1, now))
			}
		}
		metrics = append(metrics, otelMetricInt("mailops.smtp.probe_checked", "Number of SMTP host:port probes checked", "", base, len(report.SMTP), now))
		for _, row := range report.SMTP {
			labels := map[string]string{"domain": report.Domain, "host": row.Host, "port": fmt.Sprintf("%d", row.Port)}
			metrics = append(metrics,
				otelMetricInt("mailops.smtp.connect_ok", "SMTP TCP connect health per MX host", "", labels, boolInt(row.ConnectOK), now),
				otelMetricInt("mailops.smtp.starttls_offered", "SMTP STARTTLS advertisement per MX host", "", labels, boolInt(row.STARTTLSOffered), now),
				otelMetricInt("mailops.smtp.starttls_ok", "SMTP STARTTLS handshake health per MX host", "", labels, boolInt(row.STARTTLSOK), now),
				otelMetricInt("mailops.smtp.tls_ok", "SMTP TLS health per MX host and port, including implicit TLS on 465", "", labels, boolInt(row.TLSOK), now),
				otelMetricInt("mailops.smtp.auth_mechanisms", "Number of SMTP AUTH mechanisms advertised per host and port", "", labels, len(row.AuthMechanisms), now),
				otelMetricInt("mailops.smtp.open_relay_checked", "SMTP unauthenticated external relay RCPT probe execution per host and port", "", labels, boolInt(row.RelayCheck), now),
				otelMetricInt("mailops.smtp.open_relay", "SMTP unauthenticated external relay acceptance per host and port", "", labels, boolInt(row.OpenRelay), now),
			)
			if row.RelayMailCode > 0 {
				metrics = append(metrics, otelMetricInt("mailops.smtp.relay_mail_code", "SMTP response code from unauthenticated external relay MAIL FROM probe", "", labels, row.RelayMailCode, now))
			}
			if row.RelayRcptCode > 0 {
				metrics = append(metrics, otelMetricInt("mailops.smtp.relay_rcpt_code", "SMTP response code from unauthenticated external relay RCPT probe", "", labels, row.RelayRcptCode, now))
			}
			if !row.CertNotAfter.IsZero() {
				metrics = append(metrics, otelMetricInt("mailops.smtp.cert_days_remaining", "SMTP TLS leaf certificate days remaining per MX host", "d", labels, row.CertDaysRemaining, now))
			}
		}
		metrics = append(metrics, otelMetricInt("mailops.mda.endpoint_checked", "Number of IMAP/POP3 endpoints checked", "", base, len(report.MDA), now))
		for _, row := range report.MDA {
			labels := map[string]string{
				"domain":   report.Domain,
				"host":     row.Host,
				"port":     fmt.Sprintf("%d", row.Port),
				"protocol": row.Protocol,
			}
			metrics = append(metrics,
				otelMetricInt("mailops.mda.connect_ok", "IMAP/POP3 TCP connect health per endpoint", "", labels, boolInt(row.ConnectOK), now),
				otelMetricInt("mailops.mda.tls_ok", "IMAP/POP3 TLS or STARTTLS/STLS handshake health per endpoint", "", labels, boolInt(row.TLSOK), now),
				otelMetricInt("mailops.mda.starttls_offered", "IMAP STARTTLS or POP3 STLS advertisement per plaintext endpoint", "", labels, boolInt(row.STARTTLSOffered), now),
			)
			if !row.CertNotAfter.IsZero() {
				metrics = append(metrics, otelMetricInt("mailops.mda.cert_days_remaining", "IMAP/POP3 leaf certificate days remaining per endpoint", "d", labels, row.CertDaysRemaining, now))
			}
		}
	}
	return postOTLP(ctx, endpoint, "mailops", metrics)
}

func otelMetricInt(name, description, unit string, labels map[string]string, value int, ts time.Time) otelMetric {
	encodedValue := fmt.Sprintf("%d", value)
	return otelMetric{
		Name:        name,
		Description: description,
		Unit:        unit,
		Gauge: otelGauge{DataPoints: []otelDataPoint{{
			Attributes:   otelAttributes(labels),
			TimeUnixNano: fmt.Sprintf("%d", ts.UnixNano()),
			AsInt:        &encodedValue,
		}}},
	}
}

func otelMetricFloat(name, description, unit string, labels map[string]string, value float64, ts time.Time) otelMetric {
	encodedValue := value
	return otelMetric{
		Name:        name,
		Description: description,
		Unit:        unit,
		Gauge: otelGauge{DataPoints: []otelDataPoint{{
			Attributes:   otelAttributes(labels),
			TimeUnixNano: fmt.Sprintf("%d", ts.UnixNano()),
			AsDouble:     &encodedValue,
		}}},
	}
}

func otelAttributes(labels map[string]string) []otelAttribute {
	out := make([]otelAttribute, 0, len(labels))
	for key, value := range labels {
		if strings.TrimSpace(value) == "" {
			continue
		}
		out = append(out, otelAttribute{Key: key, Value: otelValue{StringValue: value}})
	}
	return out
}

func postOTLP(ctx context.Context, endpoint, service string, metrics []otelMetric) error {
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if !strings.HasSuffix(endpoint, "/v1/metrics") {
		endpoint += "/v1/metrics"
	}
	payload := otelPayload{ResourceMetrics: []otelResourceMetric{{
		Resource: otelResource{Attributes: []otelAttribute{
			{Key: "service.name", Value: otelValue{StringValue: service}},
		}},
		ScopeMetrics: []otelScopeMetric{{
			Scope:   otelScope{Name: service},
			Metrics: metrics,
		}},
	}}}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("otel export failed: %s", resp.Status)
	}
	return nil
}
