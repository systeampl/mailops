package mailcheck

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func exchangeDNS(ctx context.Context, server, name string, qtype uint16, timeout time.Duration) (*dns.Msg, error) {
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), qtype)
	message.SetEdns0(1232, true)
	client := &dns.Client{Net: "udp", Timeout: timeout}
	response, _, err := client.ExchangeContext(ctx, message, server)
	if err != nil {
		return nil, err
	}
	if response.Truncated {
		client.Net = "tcp"
		response, _, err = client.ExchangeContext(ctx, message, server)
		if err != nil {
			return nil, err
		}
	}
	if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("DNS response code %s", dns.RcodeToString[response.Rcode])
	}
	return response, nil
}

func checkDNSSEC(ctx context.Context, server, configError, domain string, timeout time.Duration) DNSSECReport {
	report := DNSSECReport{Resolver: server}
	if configError != "" {
		report.Error = configError
		return report
	}
	response, err := exchangeDNS(ctx, server, domain, dns.TypeMX, timeout)
	if err != nil {
		report.Error = err.Error()
		return report
	}
	report.Checked = true
	report.Secure = response.AuthenticatedData
	report.Signed = dnsMessageSigned(response)
	if keys, keyErr := exchangeDNS(ctx, server, domain, dns.TypeDNSKEY, timeout); keyErr == nil {
		report.Signed = report.Signed || dnsMessageSigned(keys) || messageHasType(keys, dns.TypeDNSKEY)
		report.Secure = report.Secure || keys.AuthenticatedData
	}
	return report
}

func dnsMessageSigned(message *dns.Msg) bool {
	return messageHasType(message, dns.TypeRRSIG) || messageHasType(message, dns.TypeNSEC) || messageHasType(message, dns.TypeNSEC3)
}

func messageHasType(message *dns.Msg, recordType uint16) bool {
	if message == nil {
		return false
	}
	for _, section := range [][]dns.RR{message.Answer, message.Ns, message.Extra} {
		for _, record := range section {
			if record.Header().Rrtype == recordType {
				return true
			}
		}
	}
	return false
}

func dnsSECFindings(report DNSSECReport) []Finding {
	if report.Error != "" {
		return []Finding{{Severity: SeverityWarn, Scope: "dnssec", Message: "DNSSEC check failed: " + report.Error}}
	}
	if !report.Checked {
		return nil
	}
	if report.Signed && !report.Secure {
		return []Finding{{Severity: SeverityWarn, Scope: "dnssec", Message: "DNSSEC records are present but the resolver did not authenticate the response"}}
	}
	if !report.Secure {
		return []Finding{{Severity: SeverityInfo, Scope: "dnssec", Message: "domain is not authenticated with DNSSEC"}}
	}
	return nil
}

type daneTarget struct {
	host        string
	port        int
	certificate *x509.Certificate
}

func checkDANE(ctx context.Context, server, configError string, mxs []MXRecord, smtp []SMTPReport, timeout time.Duration) []DANEReport {
	targets := map[string]daneTarget{}
	for _, mx := range mxs {
		if mx.Host == "" || mx.Host == "." {
			continue
		}
		key := net.JoinHostPort(strings.TrimSuffix(mx.Host, "."), "25")
		targets[key] = daneTarget{host: strings.TrimSuffix(mx.Host, "."), port: 25}
	}
	for index := range smtp {
		row := &smtp[index]
		key := net.JoinHostPort(strings.TrimSuffix(row.Host, "."), fmt.Sprintf("%d", row.Port))
		target := daneTarget{host: strings.TrimSuffix(row.Host, "."), port: row.Port}
		if row.certificate != nil {
			target.certificate = row.certificate
		}
		targets[key] = target
	}
	keys := make([]string, 0, len(targets))
	for key := range targets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	reports := make([]DANEReport, 0, len(keys))
	for _, key := range keys {
		target := targets[key]
		reports = append(reports, checkDANETarget(ctx, server, configError, target, timeout))
	}
	return reports
}

func checkDANETarget(ctx context.Context, server, configError string, target daneTarget, timeout time.Duration) DANEReport {
	queryName := fmt.Sprintf("_%d._tcp.%s", target.port, target.host)
	report := DANEReport{Host: target.host, Port: target.port, QueryName: queryName}
	if configError != "" {
		report.Error = configError
		return report
	}
	response, err := exchangeDNS(ctx, server, queryName, dns.TypeTLSA, timeout)
	if err != nil {
		report.Error = err.Error()
		return report
	}
	return analyzeDANEResponse(report, response, target.certificate)
}

func analyzeDANEResponse(report DANEReport, response *dns.Msg, certificate *x509.Certificate) DANEReport {
	report.DNSSECSecure = response != nil && response.AuthenticatedData
	allValid := true
	for _, answer := range response.Answer {
		tlsa, ok := answer.(*dns.TLSA)
		if !ok {
			continue
		}
		report.Present = true
		record := TLSARecord{
			Usage:           tlsa.Usage,
			Selector:        tlsa.Selector,
			MatchingType:    tlsa.MatchingType,
			AssociationData: strings.ToLower(tlsa.Certificate),
		}
		record.Valid = validTLSARecord(record)
		allValid = allValid && record.Valid
		if record.Valid && certificate != nil {
			record.Matched = matchTLSARecord(record, certificate)
			report.Matched = report.Matched || record.Matched
		}
		report.Records = append(report.Records, record)
	}
	if !report.Present {
		return report
	}
	report.Valid = allValid && report.DNSSECSecure
	if !report.DNSSECSecure {
		report.Warning = "TLSA records are not protected by an authenticated DNSSEC response"
	} else if !allValid {
		report.Error = "one or more TLSA records are syntactically invalid"
	} else if certificate != nil && !report.Matched {
		report.Error = "TLSA records do not match the observed SMTP certificate"
	}
	return report
}

func validTLSARecord(record TLSARecord) bool {
	if record.Usage > 3 || record.Selector > 1 || record.MatchingType > 2 || record.AssociationData == "" {
		return false
	}
	decoded, err := hex.DecodeString(record.AssociationData)
	if err != nil {
		return false
	}
	switch record.MatchingType {
	case 1:
		return len(decoded) == 32
	case 2:
		return len(decoded) == 64
	default:
		return len(decoded) > 0
	}
}

func matchTLSARecord(record TLSARecord, certificate *x509.Certificate) bool {
	var selected []byte
	if record.Selector == 0 {
		selected = certificate.Raw
	} else {
		selected = certificate.RawSubjectPublicKeyInfo
	}
	var association string
	switch record.MatchingType {
	case 0:
		association = hex.EncodeToString(selected)
	case 1:
		digest := sha256.Sum256(selected)
		association = hex.EncodeToString(digest[:])
	case 2:
		digest := sha512.Sum512(selected)
		association = hex.EncodeToString(digest[:])
	}
	return strings.EqualFold(association, record.AssociationData)
}

func daneFindings(reports []DANEReport) []Finding {
	var findings []Finding
	for _, report := range reports {
		prefix := fmt.Sprintf("%s:%d", report.Host, report.Port)
		switch {
		case report.Error != "" && report.Present:
			findings = append(findings, Finding{Severity: SeverityCritical, Scope: "dane", Message: prefix + ": " + report.Error})
		case report.Error != "":
			findings = append(findings, Finding{Severity: SeverityWarn, Scope: "dane", Message: prefix + ": TLSA lookup failed: " + report.Error})
		case report.Warning != "":
			findings = append(findings, Finding{Severity: SeverityCritical, Scope: "dane", Message: prefix + ": " + report.Warning})
		}
	}
	return findings
}
