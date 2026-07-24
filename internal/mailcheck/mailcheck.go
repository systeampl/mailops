package mailcheck

import (
	"bufio"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

const (
	SeverityInfo     = "info"
	SeverityWarn     = "warn"
	SeverityCritical = "critical"
	SeverityError    = "error"
)

var defaultDKIMSelectors = []string{
	"default", "dkim", "google", "selector1", "selector2", "mail", "k1", "s1",
	"20230601", "20210112", "20161025", "amazonses", "s2048", "smtpapi", "mailgun", "mandrill",
}

var defaultRBLServers = []string{
	"zen.spamhaus.org",
	"bl.spamcop.net",
	"b.barracudacentral.org",
	"dnsbl.sorbs.net",
	"spam.dnsbl.sorbs.net",
	"dnsbl-1.uceprotect.net",
}

var defaultDomainBLServers = []string{
	"dbl.spamhaus.org",
	"multi.surbl.org",
	"multi.uribl.com",
}

type Options struct {
	Domain          string
	Profiles        []string
	DKIMSelectors   []string
	DKIMExplicit    bool
	RBLServers      []string
	DomainBLServers []string
	Timeout         time.Duration
	Strict          bool
	CheckRBL        bool
	CheckReputation bool
	CheckMTASTS     bool
	CheckTLSRPT     bool
	CheckBIMI       bool
	CheckSMTP       bool
	SMTPHosts       []string
	SMTPPort        int
	SMTPPorts       []int
	CheckOpenRelay  bool
	CheckMDA        bool
	MDAHosts        []string
	MDAExplicit     bool
	MDAPorts        []int
}

type Report struct {
	Domain       string           `json:"domain" yaml:"domain"`
	Status       string           `json:"status" yaml:"status"`
	Resolver     string           `json:"resolver" yaml:"resolver"`
	Profiles     []string         `json:"profiles,omitempty" yaml:"profiles,omitempty"`
	DurationMS   int64            `json:"duration_ms" yaml:"duration_ms"`
	MX           []MXRecord       `json:"mx" yaml:"mx"`
	SPF          SPFReport        `json:"spf" yaml:"spf"`
	DKIM         []DKIMReport     `json:"dkim" yaml:"dkim"`
	DMARC        DMARCReport      `json:"dmarc" yaml:"dmarc"`
	MTASTS       MTASTSReport     `json:"mta_sts" yaml:"mta_sts"`
	TLSRPT       TLSRPTReport     `json:"tls_rpt" yaml:"tls_rpt"`
	BIMI         BIMIReport       `json:"bimi" yaml:"bimi"`
	PTR          []PTRReport      `json:"ptr" yaml:"ptr"`
	RBL          []RBLReport      `json:"rbl" yaml:"rbl"`
	DomainBL     []DomainBLReport `json:"domain_bl" yaml:"domain_bl"`
	SMTP         []SMTPReport     `json:"smtp" yaml:"smtp"`
	MDA          []MDAReport      `json:"mda" yaml:"mda"`
	Findings     []Finding        `json:"findings" yaml:"findings"`
	Error        string           `json:"error,omitempty" yaml:"error,omitempty"`
	GeneratedAt  time.Time        `json:"generated_at" yaml:"generated_at"`
	RecordCounts RecordCounts     `json:"record_counts" yaml:"record_counts"`
	Summary      ReportSummary    `json:"summary" yaml:"summary"`
}

type RecordCounts struct {
	MX           int `json:"mx" yaml:"mx"`
	SPF          int `json:"spf" yaml:"spf"`
	DKIM         int `json:"dkim" yaml:"dkim"`
	DMARC        int `json:"dmarc" yaml:"dmarc"`
	MTASTS       int `json:"mta_sts" yaml:"mta_sts"`
	TLSRPT       int `json:"tls_rpt" yaml:"tls_rpt"`
	BIMI         int `json:"bimi" yaml:"bimi"`
	PTR          int `json:"ptr" yaml:"ptr"`
	RBLHits      int `json:"rbl_hits" yaml:"rbl_hits"`
	DomainBLHits int `json:"domain_bl_hits" yaml:"domain_bl_hits"`
	SMTP         int `json:"smtp" yaml:"smtp"`
	MDA          int `json:"mda" yaml:"mda"`
}

type ReportSummary struct {
	Info     int `json:"info" yaml:"info"`
	Warn     int `json:"warn" yaml:"warn"`
	Critical int `json:"critical" yaml:"critical"`
	Error    int `json:"error" yaml:"error"`
}

type Finding struct {
	Severity string `json:"severity" yaml:"severity"`
	Scope    string `json:"scope" yaml:"scope"`
	Message  string `json:"message" yaml:"message"`
}

type MXRecord struct {
	Host       string   `json:"host" yaml:"host"`
	Preference uint16   `json:"preference" yaml:"preference"`
	IPs        []string `json:"ips" yaml:"ips"`
	Error      string   `json:"error,omitempty" yaml:"error,omitempty"`
}

type SPFReport struct {
	Records          []string `json:"records" yaml:"records"`
	Present          bool     `json:"present" yaml:"present"`
	Valid            bool     `json:"valid" yaml:"valid"`
	AllMechanism     string   `json:"all_mechanism,omitempty" yaml:"all_mechanism,omitempty"`
	EstimatedLookups int      `json:"estimated_lookups" yaml:"estimated_lookups"`
	Errors           []string `json:"errors,omitempty" yaml:"errors,omitempty"`
	Warnings         []string `json:"warnings,omitempty" yaml:"warnings,omitempty"`
}

type DKIMReport struct {
	Selector  string `json:"selector" yaml:"selector"`
	Present   bool   `json:"present" yaml:"present"`
	Record    string `json:"record,omitempty" yaml:"record,omitempty"`
	KeyType   string `json:"key_type,omitempty" yaml:"key_type,omitempty"`
	KeyBits   int    `json:"key_bits,omitempty" yaml:"key_bits,omitempty"`
	Valid     bool   `json:"valid" yaml:"valid"`
	Error     string `json:"error,omitempty" yaml:"error,omitempty"`
	Warning   string `json:"warning,omitempty" yaml:"warning,omitempty"`
	QueryName string `json:"query_name" yaml:"query_name"`
}

type DMARCReport struct {
	Records   []string          `json:"records" yaml:"records"`
	Present   bool              `json:"present" yaml:"present"`
	Valid     bool              `json:"valid" yaml:"valid"`
	Policy    string            `json:"policy,omitempty" yaml:"policy,omitempty"`
	SubPolicy string            `json:"subdomain_policy,omitempty" yaml:"subdomain_policy,omitempty"`
	Pct       int               `json:"pct" yaml:"pct"`
	Tags      map[string]string `json:"tags,omitempty" yaml:"tags,omitempty"`
	RUA       []string          `json:"rua,omitempty" yaml:"rua,omitempty"`
	RUF       []string          `json:"ruf,omitempty" yaml:"ruf,omitempty"`
	Warnings  []string          `json:"warnings,omitempty" yaml:"warnings,omitempty"`
	Errors    []string          `json:"errors,omitempty" yaml:"errors,omitempty"`
}

type MTASTSReport struct {
	TXTRecord     string   `json:"txt_record,omitempty" yaml:"txt_record,omitempty"`
	TXTPresent    bool     `json:"txt_present" yaml:"txt_present"`
	PolicyURL     string   `json:"policy_url,omitempty" yaml:"policy_url,omitempty"`
	PolicyPresent bool     `json:"policy_present" yaml:"policy_present"`
	Valid         bool     `json:"valid" yaml:"valid"`
	Mode          string   `json:"mode,omitempty" yaml:"mode,omitempty"`
	MaxAge        int      `json:"max_age,omitempty" yaml:"max_age,omitempty"`
	MXPatterns    []string `json:"mx_patterns,omitempty" yaml:"mx_patterns,omitempty"`
	MXMatched     int      `json:"mx_matched" yaml:"mx_matched"`
	MXTotal       int      `json:"mx_total" yaml:"mx_total"`
	MXUnmatched   []string `json:"mx_unmatched,omitempty" yaml:"mx_unmatched,omitempty"`
	Error         string   `json:"error,omitempty" yaml:"error,omitempty"`
	Warning       string   `json:"warning,omitempty" yaml:"warning,omitempty"`
}

type TLSRPTReport struct {
	Records []string `json:"records" yaml:"records"`
	Present bool     `json:"present" yaml:"present"`
	Valid   bool     `json:"valid" yaml:"valid"`
	RUA     []string `json:"rua,omitempty" yaml:"rua,omitempty"`
	Error   string   `json:"error,omitempty" yaml:"error,omitempty"`
}

type BIMIReport struct {
	Records      []string          `json:"records" yaml:"records"`
	Present      bool              `json:"present" yaml:"present"`
	Valid        bool              `json:"valid" yaml:"valid"`
	LogoURL      string            `json:"logo_url,omitempty" yaml:"logo_url,omitempty"`
	AuthorityURL string            `json:"authority_url,omitempty" yaml:"authority_url,omitempty"`
	Declined     bool              `json:"declined" yaml:"declined"`
	Tags         map[string]string `json:"tags,omitempty" yaml:"tags,omitempty"`
	Warning      string            `json:"warning,omitempty" yaml:"warning,omitempty"`
	Error        string            `json:"error,omitempty" yaml:"error,omitempty"`
}

type PTRReport struct {
	IP               string   `json:"ip" yaml:"ip"`
	Names            []string `json:"names" yaml:"names"`
	ForwardConfirmed bool     `json:"forward_confirmed" yaml:"forward_confirmed"`
	Error            string   `json:"error,omitempty" yaml:"error,omitempty"`
}

type RBLReport struct {
	IP       string   `json:"ip" yaml:"ip"`
	ListedOn []string `json:"listed_on" yaml:"listed_on"`
	CleanOn  []string `json:"clean_on" yaml:"clean_on"`
	Errors   []string `json:"errors,omitempty" yaml:"errors,omitempty"`
}

type DomainBLReport struct {
	Domain   string   `json:"domain" yaml:"domain"`
	ListedOn []string `json:"listed_on" yaml:"listed_on"`
	CleanOn  []string `json:"clean_on" yaml:"clean_on"`
	ErrorOn  []string `json:"error_on,omitempty" yaml:"error_on,omitempty"`
	Errors   []string `json:"errors,omitempty" yaml:"errors,omitempty"`
}

type SMTPReport struct {
	Host              string    `json:"host" yaml:"host"`
	Port              int       `json:"port" yaml:"port"`
	ConnectOK         bool      `json:"connect_ok" yaml:"connect_ok"`
	Banner            string    `json:"banner,omitempty" yaml:"banner,omitempty"`
	EHLOOK            bool      `json:"ehlo_ok" yaml:"ehlo_ok"`
	ImplicitTLS       bool      `json:"implicit_tls" yaml:"implicit_tls"`
	TLSOK             bool      `json:"tls_ok" yaml:"tls_ok"`
	STARTTLSOffered   bool      `json:"starttls_offered" yaml:"starttls_offered"`
	STARTTLSOK        bool      `json:"starttls_ok" yaml:"starttls_ok"`
	AuthMechanisms    []string  `json:"auth_mechanisms,omitempty" yaml:"auth_mechanisms,omitempty"`
	RelayCheck        bool      `json:"relay_check" yaml:"relay_check"`
	OpenRelay         bool      `json:"open_relay" yaml:"open_relay"`
	RelayStage        string    `json:"relay_stage,omitempty" yaml:"relay_stage,omitempty"`
	RelayMailCode     int       `json:"relay_mail_code,omitempty" yaml:"relay_mail_code,omitempty"`
	RelayRcptCode     int       `json:"relay_rcpt_code,omitempty" yaml:"relay_rcpt_code,omitempty"`
	RelayError        string    `json:"relay_error,omitempty" yaml:"relay_error,omitempty"`
	TLSVersion        string    `json:"tls_version,omitempty" yaml:"tls_version,omitempty"`
	CertNotAfter      time.Time `json:"cert_not_after,omitempty" yaml:"cert_not_after,omitempty"`
	CertDaysRemaining int       `json:"cert_days_remaining,omitempty" yaml:"cert_days_remaining,omitempty"`
	Error             string    `json:"error,omitempty" yaml:"error,omitempty"`
	Warning           string    `json:"warning,omitempty" yaml:"warning,omitempty"`
}

type MDAReport struct {
	Host              string    `json:"host" yaml:"host"`
	Port              int       `json:"port" yaml:"port"`
	Protocol          string    `json:"protocol" yaml:"protocol"`
	ConnectOK         bool      `json:"connect_ok" yaml:"connect_ok"`
	Banner            string    `json:"banner,omitempty" yaml:"banner,omitempty"`
	CapabilityOK      bool      `json:"capability_ok" yaml:"capability_ok"`
	STARTTLSOffered   bool      `json:"starttls_offered" yaml:"starttls_offered"`
	TLSOK             bool      `json:"tls_ok" yaml:"tls_ok"`
	TLSVersion        string    `json:"tls_version,omitempty" yaml:"tls_version,omitempty"`
	CertNotAfter      time.Time `json:"cert_not_after,omitempty" yaml:"cert_not_after,omitempty"`
	CertDaysRemaining int       `json:"cert_days_remaining,omitempty" yaml:"cert_days_remaining,omitempty"`
	Error             string    `json:"error,omitempty" yaml:"error,omitempty"`
	Warning           string    `json:"warning,omitempty" yaml:"warning,omitempty"`
}

type resolver interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupIPAddr(ctx context.Context, name string) ([]net.IPAddr, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

func Run(ctx context.Context, opts Options) Report {
	return run(ctx, opts, net.DefaultResolver)
}

func run(ctx context.Context, opts Options, r resolver) Report {
	start := time.Now()
	domain := normalizeDomain(opts.Domain)
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if len(opts.SMTPPorts) == 0 {
		if opts.SMTPPort == 0 {
			opts.SMTPPort = 25
		}
		opts.SMTPPorts = []int{opts.SMTPPort}
	}
	if len(opts.MDAPorts) == 0 {
		opts.MDAPorts = []int{143, 993, 110, 995}
	}
	if len(opts.DKIMSelectors) == 0 {
		opts.DKIMSelectors = defaultDKIMSelectors
	}
	if len(opts.RBLServers) == 0 {
		opts.RBLServers = defaultRBLServers
	}
	if len(opts.DomainBLServers) == 0 {
		opts.DomainBLServers = defaultDomainBLServers
	}
	if !opts.CheckMTASTS && !opts.CheckTLSRPT && !opts.CheckBIMI {
		opts.CheckMTASTS = true
		opts.CheckTLSRPT = true
		opts.CheckBIMI = true
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	rep := Report{
		Domain:      domain,
		Status:      "ok",
		Resolver:    "system",
		Profiles:    opts.Profiles,
		GeneratedAt: time.Now().UTC(),
	}
	if domain == "" {
		rep.Error = "domain is required"
		rep.Status = SeverityError
		rep.Findings = append(rep.Findings, Finding{Severity: SeverityError, Scope: "input", Message: "domain is required"})
		return finalize(rep, start)
	}
	if !validMailDomain(domain) {
		rep.Error = "invalid domain: " + domain
		rep.Status = SeverityError
		rep.Findings = append(rep.Findings, Finding{Severity: SeverityError, Scope: "input", Message: rep.Error})
		return finalize(rep, start)
	}

	var mxErr error
	rep.MX, mxErr = checkMX(ctx, r, domain)
	rep.RecordCounts.MX = len(rep.MX)
	if mxErr != nil && !dnsNotFound(mxErr) {
		rep.Findings = append(rep.Findings, Finding{Severity: SeverityError, Scope: "mx", Message: "MX lookup failed: " + mxErr.Error()})
	} else if len(rep.MX) == 0 {
		rep.Findings = append(rep.Findings, Finding{Severity: SeverityCritical, Scope: "mx", Message: "no MX records found"})
	}
	for _, mx := range rep.MX {
		if mx.Host == "." {
			rep.Findings = append(rep.Findings, Finding{Severity: SeverityCritical, Scope: "mx", Message: "null MX record declares that the domain does not accept email"})
			continue
		}
		if mx.Error != "" {
			rep.Findings = append(rep.Findings, Finding{Severity: SeverityWarn, Scope: "mx", Message: fmt.Sprintf("%s does not resolve: %s", mx.Host, mx.Error)})
		}
	}

	rep.SPF = checkSPF(ctx, r, domain)
	rep.RecordCounts.SPF = len(rep.SPF.Records)
	rep.Findings = append(rep.Findings, spfFindings(rep.SPF)...)

	rep.DMARC = checkDMARC(ctx, r, domain)
	rep.RecordCounts.DMARC = len(rep.DMARC.Records)
	rep.Findings = append(rep.Findings, dmarcFindings(rep.DMARC, opts.Strict)...)

	rep.DKIM = checkDKIM(ctx, r, domain, opts.DKIMSelectors)
	for _, row := range rep.DKIM {
		if row.Valid {
			rep.RecordCounts.DKIM++
		}
		if row.Error != "" {
			if opts.DKIMExplicit {
				rep.Findings = append(rep.Findings, Finding{Severity: SeverityWarn, Scope: "dkim", Message: fmt.Sprintf("%s: %s", row.Selector, row.Error)})
			}
			continue
		}
		if row.Warning != "" {
			rep.Findings = append(rep.Findings, Finding{Severity: SeverityWarn, Scope: "dkim", Message: row.Warning})
		}
	}
	if rep.RecordCounts.DKIM == 0 {
		severity := SeverityInfo
		message := "no valid DKIM selector found among common selectors; configure --selector for known providers"
		if opts.DKIMExplicit {
			severity = SeverityWarn
			message = "configured DKIM selector(s) are missing or invalid"
		}
		rep.Findings = append(rep.Findings, Finding{Severity: severity, Scope: "dkim", Message: message})
	}

	if opts.CheckMTASTS {
		rep.MTASTS = checkMTASTS(ctx, r, domain, opts.Timeout)
		applyMTASTSMXCoverage(&rep.MTASTS, rep.MX)
		if rep.MTASTS.TXTPresent {
			rep.RecordCounts.MTASTS = 1
		}
		rep.Findings = append(rep.Findings, mtaSTSFindings(rep.MTASTS, opts.Strict)...)
	}
	if opts.CheckTLSRPT {
		rep.TLSRPT = checkTLSRPT(ctx, r, domain)
		rep.RecordCounts.TLSRPT = len(rep.TLSRPT.Records)
		rep.Findings = append(rep.Findings, tlsRPTFindings(rep.TLSRPT, opts.Strict)...)
	}
	if opts.CheckBIMI {
		rep.BIMI = checkBIMI(ctx, r, domain, rep.DMARC)
		rep.RecordCounts.BIMI = len(rep.BIMI.Records)
		rep.Findings = append(rep.Findings, bimiFindings(rep.BIMI)...)
	}

	ips := mxIPs(rep.MX)
	rep.PTR = checkPTR(ctx, r, ips)
	for _, ptr := range rep.PTR {
		if len(ptr.Names) > 0 {
			rep.RecordCounts.PTR++
		}
		if ptr.Error != "" {
			rep.Findings = append(rep.Findings, Finding{Severity: SeverityWarn, Scope: "ptr", Message: fmt.Sprintf("%s has no PTR record: %s", ptr.IP, ptr.Error)})
		} else if !ptr.ForwardConfirmed {
			rep.Findings = append(rep.Findings, Finding{Severity: SeverityWarn, Scope: "ptr", Message: fmt.Sprintf("%s PTR is not forward-confirmed", ptr.IP)})
		}
	}

	if opts.CheckRBL {
		rep.RBL = checkRBL(ctx, r, ips, opts.RBLServers)
		for _, row := range rep.RBL {
			rep.RecordCounts.RBLHits += len(row.ListedOn)
			if len(row.ListedOn) > 0 {
				rep.Findings = append(rep.Findings, Finding{Severity: SeverityCritical, Scope: "rbl", Message: fmt.Sprintf("%s listed on %s", row.IP, strings.Join(row.ListedOn, ", "))})
			}
			for _, errText := range row.Errors {
				rep.Findings = append(rep.Findings, Finding{Severity: SeverityWarn, Scope: "rbl", Message: errText})
			}
		}
	}
	if opts.CheckReputation {
		rep.DomainBL = checkDomainBL(ctx, r, domain, opts.DomainBLServers)
		for _, row := range rep.DomainBL {
			rep.RecordCounts.DomainBLHits += len(row.ListedOn)
			if len(row.ListedOn) > 0 {
				rep.Findings = append(rep.Findings, Finding{Severity: SeverityCritical, Scope: "reputation", Message: fmt.Sprintf("%s listed on domain reputation list(s): %s", row.Domain, strings.Join(row.ListedOn, ", "))})
			}
			for _, errText := range row.Errors {
				rep.Findings = append(rep.Findings, Finding{Severity: SeverityWarn, Scope: "reputation", Message: errText})
			}
		}
	}

	if opts.CheckSMTP {
		rep.SMTP = checkSMTP(ctx, rep.MX, opts.SMTPHosts, opts.SMTPPorts, opts.Timeout, opts.CheckOpenRelay)
		rep.RecordCounts.SMTP = len(rep.SMTP)
		rep.Findings = append(rep.Findings, smtpFindings(rep.SMTP, opts.Strict)...)
	}
	if opts.CheckMDA {
		rep.MDA = checkMDA(ctx, domain, opts.MDAHosts, opts.MDAPorts, opts.Timeout, opts.MDAExplicit)
		rep.RecordCounts.MDA = len(rep.MDA)
		rep.Findings = append(rep.Findings, mdaFindings(rep.MDA, opts.MDAExplicit, opts.Strict)...)
	}

	return finalize(rep, start)
}

func finalize(rep Report, start time.Time) Report {
	rep.DurationMS = time.Since(start).Milliseconds()
	rep.Summary = summarize(rep.Findings)
	switch {
	case rep.Summary.Error > 0:
		rep.Status = SeverityError
	case rep.Summary.Critical > 0:
		rep.Status = SeverityCritical
	case rep.Summary.Warn > 0:
		rep.Status = SeverityWarn
	default:
		rep.Status = "ok"
	}
	return rep
}

func summarize(findings []Finding) ReportSummary {
	var out ReportSummary
	for _, f := range findings {
		switch f.Severity {
		case SeverityError:
			out.Error++
		case SeverityCritical:
			out.Critical++
		case SeverityWarn:
			out.Warn++
		default:
			out.Info++
		}
	}
	return out
}

func checkMX(ctx context.Context, r resolver, domain string) ([]MXRecord, error) {
	mxs, err := r.LookupMX(ctx, domain)
	if err != nil {
		return nil, err
	}
	sort.Slice(mxs, func(i, j int) bool { return mxs[i].Pref < mxs[j].Pref })
	out := make([]MXRecord, 0, len(mxs))
	for _, mx := range mxs {
		host := strings.TrimSpace(mx.Host)
		if host == "." {
			out = append(out, MXRecord{Host: ".", Preference: mx.Pref, Error: "null MX record"})
			continue
		}
		host = strings.TrimSuffix(host, ".")
		row := MXRecord{Host: host, Preference: mx.Pref}
		ips, err := r.LookupIPAddr(ctx, host)
		if err != nil {
			row.Error = err.Error()
		} else {
			for _, ip := range ips {
				row.IPs = append(row.IPs, ip.IP.String())
			}
			sort.Strings(row.IPs)
		}
		out = append(out, row)
	}
	return out, nil
}

func checkSPF(ctx context.Context, r resolver, domain string) SPFReport {
	txts, err := lookupTXT(ctx, r, domain)
	rep := SPFReport{}
	if err != nil {
		if !dnsNotFound(err) {
			rep.Errors = append(rep.Errors, "SPF TXT lookup failed: "+err.Error())
		}
		return rep
	}
	for _, txt := range txts {
		if hasSPFVersion(txt) {
			rep.Records = append(rep.Records, txt)
		}
	}
	rep.Present = len(rep.Records) > 0
	if len(rep.Records) != 1 {
		rep.Valid = false
		if len(rep.Records) > 1 {
			rep.Errors = append(rep.Errors, "multiple SPF records found")
		}
		return rep
	}
	parsed := parseSPFRecord(rep.Records[0])
	rep.Valid = true
	rep.AllMechanism = parsed.All
	rep.Warnings = append(rep.Warnings, parsed.Warnings...)
	count, countErrs := countSPFLookups(ctx, r, domain, map[string]bool{}, 0)
	rep.EstimatedLookups = count
	rep.Errors = append(rep.Errors, countErrs...)
	if count > 10 {
		rep.Valid = false
		rep.Errors = append(rep.Errors, fmt.Sprintf("SPF exceeds 10 DNS lookup limit (%d lookups)", count))
	}
	return rep
}

type parsedSPF struct {
	All      string
	Redirect bool
	Warnings []string
}

func parseSPFRecord(record string) parsedSPF {
	var out parsedSPF
	for _, field := range strings.Fields(record) {
		lower := strings.ToLower(field)
		if strings.HasPrefix(lower, "redirect=") {
			out.Redirect = true
		}
		mechanism := strings.TrimLeft(lower, "+-~?")
		if mechanism == "all" {
			out.All = lower
			switch lower {
			case "+all":
				out.Warnings = append(out.Warnings, "SPF uses +all and permits every sender")
			case "?all":
				out.Warnings = append(out.Warnings, "SPF uses ?all neutral policy")
			case "~all":
				out.Warnings = append(out.Warnings, "SPF uses ~all softfail; -all is stricter")
			}
		}
	}
	if out.All == "" {
		if !out.Redirect {
			out.Warnings = append(out.Warnings, "SPF has no all mechanism")
		}
	}
	return out
}

func countSPFLookups(ctx context.Context, r resolver, domain string, seen map[string]bool, depth int) (int, []string) {
	if depth > 10 {
		return 0, []string{"SPF include/redirect recursion too deep"}
	}
	key := strings.ToLower(domain)
	if seen[key] {
		return 0, []string{"SPF include/redirect loop detected at " + domain}
	}
	seen[key] = true
	defer delete(seen, key)

	txts, err := lookupTXT(ctx, r, domain)
	if err != nil {
		return 0, []string{fmt.Sprintf("%s SPF lookup failed: %s", domain, err)}
	}
	var record string
	for _, txt := range txts {
		if hasSPFVersion(txt) {
			record = txt
			break
		}
	}
	if record == "" {
		return 0, nil
	}

	total := 0
	var errs []string
	for _, field := range strings.Fields(record) {
		mech := strings.TrimLeft(field, "+-~?")
		lower := strings.ToLower(mech)
		switch {
		case strings.HasPrefix(lower, "include:"):
			total++
			child := strings.TrimSpace(mech[len("include:"):])
			childCount, childErrs := countSPFLookups(ctx, r, child, seen, depth+1)
			total += childCount
			errs = append(errs, childErrs...)
		case strings.HasPrefix(lower, "redirect="):
			total++
			child := strings.TrimSpace(mech[len("redirect="):])
			childCount, childErrs := countSPFLookups(ctx, r, child, seen, depth+1)
			total += childCount
			errs = append(errs, childErrs...)
		case lower == "a" || strings.HasPrefix(lower, "a:") || strings.HasPrefix(lower, "a/"):
			total++
		case lower == "mx" || strings.HasPrefix(lower, "mx:") || strings.HasPrefix(lower, "mx/"):
			total++
		case lower == "ptr" || strings.HasPrefix(lower, "ptr:"):
			total++
		case strings.HasPrefix(lower, "exists:"):
			total++
		}
	}
	return total, errs
}

func spfFindings(rep SPFReport) []Finding {
	var out []Finding
	if !rep.Present {
		if len(rep.Errors) > 0 {
			for _, errText := range rep.Errors {
				out = append(out, Finding{Severity: SeverityError, Scope: "spf", Message: errText})
			}
			return out
		}
		return []Finding{{Severity: SeverityCritical, Scope: "spf", Message: "no SPF record found"}}
	}
	for _, err := range rep.Errors {
		severity := SeverityCritical
		if strings.Contains(err, "lookup failed") {
			severity = SeverityWarn
		}
		out = append(out, Finding{Severity: severity, Scope: "spf", Message: err})
	}
	for _, warning := range rep.Warnings {
		severity := SeverityWarn
		if strings.Contains(warning, "+all") {
			severity = SeverityCritical
		}
		out = append(out, Finding{Severity: severity, Scope: "spf", Message: warning})
	}
	return out
}

func checkDMARC(ctx context.Context, r resolver, domain string) DMARCReport {
	name := "_dmarc." + domain
	txts, err := lookupTXT(ctx, r, name)
	rep := DMARCReport{Pct: 100}
	if err != nil {
		if !dnsNotFound(err) {
			rep.Errors = append(rep.Errors, "DMARC TXT lookup failed: "+err.Error())
		}
		return rep
	}
	for _, txt := range txts {
		if hasTagVersion(txt, "DMARC1") {
			rep.Records = append(rep.Records, txt)
		}
	}
	rep.Present = len(rep.Records) > 0
	if len(rep.Records) != 1 {
		if len(rep.Records) > 1 {
			rep.Errors = append(rep.Errors, "multiple DMARC records found")
		}
		return rep
	}
	tags := parseTags(rep.Records[0])
	rep.Tags = tags
	rep.Policy = strings.ToLower(tags["p"])
	rep.SubPolicy = strings.ToLower(tags["sp"])
	pctValid := true
	if rawPct, present := tags["pct"]; present {
		pct, err := strconv.Atoi(rawPct)
		if err != nil || pct < 0 || pct > 100 {
			pctValid = false
			rep.Errors = append(rep.Errors, "DMARC pct must be an integer from 0 to 100")
		} else {
			rep.Pct = pct
		}
	}
	rep.RUA = parseMailtoList(tags["rua"])
	rep.RUF = parseMailtoList(tags["ruf"])
	rep.Valid = pctValid && (rep.Policy == "none" || rep.Policy == "quarantine" || rep.Policy == "reject")
	if !rep.Valid {
		rep.Errors = append(rep.Errors, "DMARC policy p= is missing or invalid")
	}
	if rep.Policy == "none" {
		rep.Warnings = append(rep.Warnings, "DMARC policy is p=none")
	}
	if rep.Pct < 100 {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("DMARC pct is %d, not 100", rep.Pct))
	}
	if len(rep.RUA) == 0 {
		rep.Warnings = append(rep.Warnings, "DMARC has no rua aggregate report destination")
	}
	for _, rua := range rep.RUA {
		if externalReportDomain(domain, rua) {
			dest := domainFromMailto(rua)
			authName := domain + "._report._dmarc." + dest
			authTXT, err := lookupTXT(ctx, r, authName)
			if err != nil || !containsDMARCReportAuth(authTXT) {
				rep.Warnings = append(rep.Warnings, "external DMARC rua destination lacks authorization record: "+authName)
			}
		}
	}
	return rep
}

func dmarcFindings(rep DMARCReport, strict bool) []Finding {
	if !rep.Present {
		if len(rep.Errors) > 0 {
			out := make([]Finding, 0, len(rep.Errors))
			for _, errText := range rep.Errors {
				out = append(out, Finding{Severity: SeverityError, Scope: "dmarc", Message: errText})
			}
			return out
		}
		return []Finding{{Severity: SeverityCritical, Scope: "dmarc", Message: "no DMARC record found"}}
	}
	var out []Finding
	for _, err := range rep.Errors {
		out = append(out, Finding{Severity: SeverityCritical, Scope: "dmarc", Message: err})
	}
	for _, warning := range rep.Warnings {
		severity := SeverityWarn
		if strict && strings.Contains(warning, "p=none") {
			severity = SeverityCritical
		}
		out = append(out, Finding{Severity: severity, Scope: "dmarc", Message: warning})
	}
	if rep.Policy == "quarantine" {
		out = append(out, Finding{Severity: SeverityInfo, Scope: "dmarc", Message: "DMARC policy is quarantine; reject is stricter"})
	}
	return out
}

func checkDKIM(ctx context.Context, r resolver, domain string, selectors []string) []DKIMReport {
	out := make([]DKIMReport, 0, len(selectors))
	seen := map[string]bool{}
	for _, selector := range selectors {
		selector = strings.TrimSpace(selector)
		if selector == "" || seen[selector] {
			continue
		}
		seen[selector] = true
		name := selector + "._domainkey." + domain
		row := DKIMReport{Selector: selector, QueryName: name}
		txts, err := lookupTXT(ctx, r, name)
		if err != nil {
			row.Error = err.Error()
			out = append(out, row)
			continue
		}
		for _, txt := range txts {
			tags := parseTags(txt)
			if strings.EqualFold(tags["v"], "DKIM1") || tags["p"] != "" {
				row.Present = true
				row.Record = txt
				row.KeyType = tags["k"]
				if row.KeyType == "" {
					row.KeyType = "rsa"
				}
				key := strings.TrimSpace(tags["p"])
				if key == "" {
					row.Error = "DKIM public key p= is empty"
				} else if decoded, err := base64.StdEncoding.DecodeString(stripSpaces(key)); err != nil {
					row.Error = "DKIM public key p= is not valid base64: " + err.Error()
				} else if bits, err := dkimPublicKeyBits(row.KeyType, decoded); err != nil {
					row.Error = err.Error()
				} else {
					row.KeyBits = bits
				}
				row.Valid = row.Error == ""
				if row.Valid && row.KeyType == "rsa" {
					if row.KeyBits > 0 && row.KeyBits < 1024 {
						row.Warning = fmt.Sprintf("DKIM selector %s RSA key is weak (%d bits)", selector, row.KeyBits)
					} else if row.KeyBits > 0 && row.KeyBits < 2048 {
						row.Warning = fmt.Sprintf("DKIM selector %s RSA key is %d bits; 2048+ is recommended", selector, row.KeyBits)
					}
				}
				break
			}
		}
		if !row.Present && row.Error == "" {
			row.Error = "no DKIM record found"
		}
		out = append(out, row)
	}
	return out
}

func dkimPublicKeyBits(keyType string, der []byte) (int, error) {
	switch strings.ToLower(strings.TrimSpace(keyType)) {
	case "rsa":
		if parsed, err := x509.ParsePKIXPublicKey(der); err == nil {
			if publicKey, ok := parsed.(*rsa.PublicKey); ok {
				return publicKey.N.BitLen(), nil
			}
			return 0, fmt.Errorf("DKIM public key is not RSA")
		}
		if publicKey, err := x509.ParsePKCS1PublicKey(der); err == nil {
			return publicKey.N.BitLen(), nil
		}
		return 0, fmt.Errorf("DKIM RSA public key is not valid DER")
	case "ed25519":
		if len(der) != 32 {
			return 0, fmt.Errorf("DKIM Ed25519 public key must be 32 bytes")
		}
		return 256, nil
	default:
		return 0, fmt.Errorf("unsupported DKIM key type %q", keyType)
	}
}

func checkMTASTS(ctx context.Context, r resolver, domain string, timeout time.Duration) MTASTSReport {
	return checkMTASTSWithClient(ctx, r, domain, timeout, nil)
}

func checkMTASTSWithClient(ctx context.Context, r resolver, domain string, timeout time.Duration, client *http.Client) MTASTSReport {
	rep := MTASTSReport{PolicyURL: "https://mta-sts." + domain + "/.well-known/mta-sts.txt"}
	txts, err := lookupTXT(ctx, r, "_mta-sts."+domain)
	if err != nil {
		if !dnsNotFound(err) {
			rep.Error = "MTA-STS TXT lookup failed: " + err.Error()
			return rep
		}
	} else {
		validRecords := validMTASTSTXTRecords(txts)
		if len(validRecords) > 1 {
			rep.Error = "multiple valid MTA-STS TXT records found"
			return rep
		}
		if len(validRecords) == 1 {
			rep.TXTRecord = validRecords[0]
			rep.TXTPresent = true
		} else if hasMTASTSTXTRecord(txts) {
			rep.Error = "MTA-STS TXT record is syntactically invalid or has no id"
			return rep
		}
	}
	if !rep.TXTPresent {
		rep.Warning = "MTA-STS TXT record is missing"
		return rep
	}
	if client == nil {
		client = newMTASTSHTTPClient(timeout)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rep.PolicyURL, nil)
	if err != nil {
		rep.Error = err.Error()
		return rep
	}
	resp, err := client.Do(req)
	if err != nil {
		rep.Error = err.Error()
		return rep
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		rep.Error = fmt.Sprintf("MTA-STS policy returned HTTP %d", resp.StatusCode)
		return rep
	}
	const maxPolicySize = 64 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicySize+1))
	if err != nil {
		rep.Error = err.Error()
		return rep
	}
	if len(body) > maxPolicySize {
		rep.Error = fmt.Sprintf("MTA-STS policy exceeds %d byte size limit", maxPolicySize)
		return rep
	}
	policy := parseMTASTSPolicy(string(body))
	rep.PolicyPresent = true
	rep.Mode = policy["mode"]
	rep.MaxAge, _ = strconv.Atoi(policy["max_age"])
	rep.MXPatterns = splitPolicyValues(policy["mx"])
	if err := validateMTASTSPolicy(policy); err != nil {
		rep.Error = err.Error()
	} else if rep.Mode == "testing" {
		rep.Valid = true
		rep.Warning = "MTA-STS policy mode is testing"
	} else if rep.Mode == "none" {
		rep.Valid = true
		rep.Warning = "MTA-STS policy mode is none"
	} else {
		rep.Valid = true
	}
	return rep
}

func validMTASTSTXTRecords(txts []string) []string {
	var out []string
	for _, txt := range txts {
		trimmed := strings.TrimSpace(txt)
		if !strings.HasPrefix(trimmed, "v=STSv1;") {
			continue
		}
		id := parseTags(trimmed)["id"]
		if len(id) == 0 || len(id) > 32 {
			continue
		}
		valid := true
		for _, char := range id {
			if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') {
				valid = false
				break
			}
		}
		if valid {
			out = append(out, txt)
		}
	}
	return out
}

func hasMTASTSTXTRecord(txts []string) bool {
	for _, txt := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=stsv1") {
			return true
		}
	}
	return false
}

func newMTASTSHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func validateMTASTSPolicy(policy map[string]string) error {
	if policy["version"] != "STSv1" {
		return fmt.Errorf("MTA-STS policy version must be STSv1")
	}
	mode := policy["mode"]
	if mode != "enforce" && mode != "testing" && mode != "none" {
		return fmt.Errorf("MTA-STS policy mode must be enforce, testing, or none")
	}
	rawMaxAge := policy["max_age"]
	if len(rawMaxAge) == 0 || len(rawMaxAge) > 10 {
		return fmt.Errorf("MTA-STS policy max_age must be an integer from 0 to 31557600")
	}
	for _, char := range rawMaxAge {
		if char < '0' || char > '9' {
			return fmt.Errorf("MTA-STS policy max_age must be an integer from 0 to 31557600")
		}
	}
	maxAge, err := strconv.Atoi(rawMaxAge)
	if err != nil || maxAge > 31557600 {
		return fmt.Errorf("MTA-STS policy max_age must be an integer from 0 to 31557600")
	}
	mxPatterns := splitPolicyValues(policy["mx"])
	if mode != "none" && len(mxPatterns) == 0 {
		return fmt.Errorf("MTA-STS policy requires at least one mx pattern unless mode is none")
	}
	for _, pattern := range mxPatterns {
		if !validMTASTSMXPattern(pattern) {
			return fmt.Errorf("MTA-STS policy has invalid mx pattern %q", pattern)
		}
	}
	return nil
}

func validMTASTSMXPattern(pattern string) bool {
	pattern = strings.TrimSpace(strings.ToLower(pattern))
	if strings.HasPrefix(pattern, "*.") {
		pattern = strings.TrimPrefix(pattern, "*.")
	}
	if pattern == "" || len(pattern) > 253 || strings.Contains(pattern, "*") {
		return false
	}
	for _, label := range strings.Split(pattern, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func mtaSTSFindings(rep MTASTSReport, strict bool) []Finding {
	if rep.Error != "" {
		severity := SeverityWarn
		if strict {
			severity = SeverityCritical
		}
		return []Finding{{Severity: severity, Scope: "mta-sts", Message: rep.Error}}
	}
	var out []Finding
	if rep.Warning != "" {
		severity := SeverityWarn
		if strict {
			severity = SeverityCritical
		}
		out = append(out, Finding{Severity: severity, Scope: "mta-sts", Message: rep.Warning})
	}
	for _, host := range rep.MXUnmatched {
		severity := SeverityWarn
		if strict {
			severity = SeverityCritical
		}
		out = append(out, Finding{Severity: severity, Scope: "mta-sts", Message: fmt.Sprintf("MX host %s is not covered by MTA-STS policy", host)})
	}
	return out
}

func applyMTASTSMXCoverage(rep *MTASTSReport, mxs []MXRecord) {
	if rep == nil || !rep.Valid || len(rep.MXPatterns) == 0 {
		return
	}
	rep.MXTotal = len(mxs)
	for _, mx := range mxs {
		if matchMTASTSMX(mx.Host, rep.MXPatterns) {
			rep.MXMatched++
			continue
		}
		rep.MXUnmatched = append(rep.MXUnmatched, mx.Host)
	}
	sort.Strings(rep.MXUnmatched)
}

func matchMTASTSMX(host string, patterns []string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	for _, pattern := range patterns {
		pattern = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
		if pattern == "" {
			continue
		}
		if pattern == host {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := strings.TrimPrefix(pattern, "*")
			if strings.HasSuffix(host, suffix) && host != strings.TrimPrefix(suffix, ".") {
				return true
			}
		}
	}
	return false
}

func checkTLSRPT(ctx context.Context, r resolver, domain string) TLSRPTReport {
	txts, err := lookupTXT(ctx, r, "_smtp._tls."+domain)
	rep := TLSRPTReport{}
	if err != nil {
		if !dnsNotFound(err) {
			rep.Error = "TLS-RPT TXT lookup failed: " + err.Error()
		}
		return rep
	}
	for _, txt := range txts {
		if strings.HasPrefix(strings.TrimSpace(txt), "v=TLSRPTv1;") {
			rep.Records = append(rep.Records, txt)
		}
	}
	rep.Present = len(rep.Records) > 0
	if len(rep.Records) > 1 {
		rep.Error = "multiple TLS-RPT records found"
		return rep
	}
	if len(rep.Records) == 1 {
		rep.RUA = parseTLSRPTURIList(parseTags(rep.Records[0])["rua"])
	}
	rep.Valid = len(rep.Records) == 1 && len(rep.RUA) > 0
	if rep.Present && !rep.Valid {
		rep.Error = "TLS-RPT record has no rua destination"
	}
	return rep
}

func tlsRPTFindings(rep TLSRPTReport, strict bool) []Finding {
	if !rep.Present {
		if rep.Error != "" {
			return []Finding{{Severity: SeverityError, Scope: "tls-rpt", Message: rep.Error}}
		}
		severity := SeverityWarn
		if strict {
			severity = SeverityCritical
		}
		return []Finding{{Severity: severity, Scope: "tls-rpt", Message: "TLS-RPT record is missing"}}
	}
	if rep.Error != "" {
		severity := SeverityWarn
		if strict {
			severity = SeverityCritical
		}
		return []Finding{{Severity: severity, Scope: "tls-rpt", Message: rep.Error}}
	}
	return nil
}

func checkBIMI(ctx context.Context, r resolver, domain string, dmarc DMARCReport) BIMIReport {
	txts, err := lookupTXT(ctx, r, "default._bimi."+domain)
	rep := BIMIReport{}
	if err != nil {
		rep.Error = err.Error()
		return rep
	}
	for _, txt := range txts {
		if hasExactBIMIVersion(txt) {
			rep.Records = append(rep.Records, txt)
		}
	}
	rep.Present = len(rep.Records) > 0
	if len(rep.Records) > 1 {
		rep.Error = "multiple BIMI records found for default selector"
		return rep
	}
	if len(rep.Records) == 0 {
		return rep
	}
	rep.Tags = parseTags(rep.Records[0])
	logoURL, hasLogoTag := rep.Tags["l"]
	if !hasLogoTag {
		rep.Error = "BIMI record has no required logo location l= tag"
		return rep
	}
	rep.LogoURL = strings.TrimSpace(logoURL)
	rep.AuthorityURL = strings.TrimSpace(rep.Tags["a"])
	if rep.LogoURL != "" {
		if err := validateBIMIHTTPSURI(rep.LogoURL, true); err != nil {
			rep.Error = "BIMI logo location l= is invalid: " + err.Error()
			return rep
		}
	}
	if rep.AuthorityURL != "" {
		if err := validateBIMIHTTPSURI(rep.AuthorityURL, false); err != nil {
			rep.Error = "BIMI authority evidence location a= is invalid: " + err.Error()
			return rep
		}
	}
	rep.Valid = true
	rep.Declined = rep.LogoURL == "" && rep.AuthorityURL == ""
	switch {
	case rep.Declined:
		rep.Warning = "BIMI record explicitly declines to publish an indicator"
	case rep.LogoURL == "":
		rep.Warning = "BIMI record has no logo location; indicator discovery cannot complete"
	case (dmarc.Policy != "quarantine" && dmarc.Policy != "reject") || dmarc.Pct != 100:
		rep.Warning = "BIMI is present but DMARC is not enforced at quarantine or reject with pct=100"
	}
	return rep
}

func hasExactBIMIVersion(record string) bool {
	first, _, _ := strings.Cut(strings.TrimSpace(record), ";")
	key, value, ok := strings.Cut(strings.TrimSpace(first), "=")
	return ok && strings.TrimSpace(key) == "v" && strings.TrimSpace(value) == "BIMI1"
}

func validateBIMIHTTPSURI(raw string, requireSVG bool) error {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return fmt.Errorf("not a valid URI")
	}
	if parsed.Scheme != "https" || parsed.Hostname() == "" {
		return fmt.Errorf("must use HTTPS with a fully qualified host")
	}
	host := strings.ToLower(parsed.Hostname())
	if net.ParseIP(host) != nil || !strings.Contains(host, ".") || !validMTASTSMXPattern(host) {
		return fmt.Errorf("must use HTTPS with a fully qualified host")
	}
	if requireSVG {
		path := strings.ToLower(parsed.Path)
		if !strings.HasSuffix(path, ".svg") && !strings.HasSuffix(path, ".svgz") {
			return fmt.Errorf("must reference an SVG or SVGZ image")
		}
	}
	return nil
}

func bimiFindings(rep BIMIReport) []Finding {
	if !rep.Present {
		return nil
	}
	if rep.Error != "" {
		return []Finding{{Severity: SeverityWarn, Scope: "bimi", Message: rep.Error}}
	}
	if rep.Warning != "" {
		return []Finding{{Severity: SeverityWarn, Scope: "bimi", Message: rep.Warning}}
	}
	return nil
}

func checkPTR(ctx context.Context, r resolver, ips []string) []PTRReport {
	out := make([]PTRReport, 0, len(ips))
	for _, ip := range ips {
		row := PTRReport{IP: ip}
		names, err := r.LookupAddr(ctx, ip)
		if err != nil {
			row.Error = err.Error()
			out = append(out, row)
			continue
		}
		for _, name := range names {
			row.Names = append(row.Names, strings.TrimSuffix(name, "."))
		}
		sort.Strings(row.Names)
		for _, name := range row.Names {
			addrs, err := r.LookupIPAddr(ctx, name)
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if addr.IP.String() == ip {
					row.ForwardConfirmed = true
					break
				}
			}
		}
		out = append(out, row)
	}
	return out
}

func checkRBL(ctx context.Context, r resolver, ips []string, servers []string) []RBLReport {
	out := make([]RBLReport, 0, len(ips))
	for _, ip := range ips {
		if net.ParseIP(ip).To4() == nil {
			continue
		}
		row := RBLReport{IP: ip}
		reversed := reverseIPv4(ip)
		for _, server := range servers {
			server = strings.TrimSpace(server)
			if server == "" {
				continue
			}
			query := reversed + "." + server
			addrs, err := r.LookupIPAddr(ctx, query)
			if err != nil {
				if dnsNotFound(err) {
					row.CleanOn = append(row.CleanOn, server)
				} else {
					row.Errors = append(row.Errors, server+": lookup failed: "+err.Error())
				}
				continue
			}
			blocked := false
			listed := false
			for _, addr := range addrs {
				ip4 := addr.IP.To4()
				if ip4 == nil {
					continue
				}
				if ip4[0] == 127 && ip4[1] == 0 && ip4[2] == 0 && ip4[3] == 1 {
					blocked = true
					continue
				}
				if ip4[0] == 127 && ip4[1] == 0 && ip4[2] == 0 && ip4[3] >= 2 {
					listed = true
				}
			}
			if blocked && !listed {
				row.Errors = append(row.Errors, server+": query blocked or rate limited")
			} else if listed {
				row.ListedOn = append(row.ListedOn, server)
			} else {
				row.CleanOn = append(row.CleanOn, server)
			}
		}
		sort.Strings(row.CleanOn)
		sort.Strings(row.Errors)
		sort.Strings(row.ListedOn)
		out = append(out, row)
	}
	return out
}

func checkDomainBL(ctx context.Context, r resolver, domain string, servers []string) []DomainBLReport {
	row := DomainBLReport{Domain: domain}
	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		query := domain + "." + server
		addrs, err := r.LookupIPAddr(ctx, query)
		if err != nil {
			if dnsNotFound(err) {
				row.CleanOn = append(row.CleanOn, server)
			} else {
				row.ErrorOn = append(row.ErrorOn, server)
				row.Errors = append(row.Errors, server+": lookup failed: "+err.Error())
			}
			continue
		}
		blocked := false
		listed := false
		for _, addr := range addrs {
			ip4 := addr.IP.To4()
			if ip4 == nil {
				continue
			}
			if ip4[0] == 127 && ip4[1] == 0 && ip4[2] == 0 && ip4[3] == 1 {
				blocked = true
				continue
			}
			if ip4[0] == 127 {
				listed = true
				break
			}
		}
		if blocked && !listed {
			row.ErrorOn = append(row.ErrorOn, server)
			row.Errors = append(row.Errors, server+": query blocked or rate limited")
		} else if listed {
			row.ListedOn = append(row.ListedOn, server)
		} else {
			row.CleanOn = append(row.CleanOn, server)
		}
	}
	sort.Strings(row.CleanOn)
	sort.Strings(row.ErrorOn)
	sort.Strings(row.ListedOn)
	return []DomainBLReport{row}
}

func checkSMTP(ctx context.Context, mxs []MXRecord, hosts []string, ports []int, timeout time.Duration, checkOpenRelay bool) []SMTPReport {
	if len(hosts) == 0 {
		for _, mx := range mxs {
			hosts = append(hosts, mx.Host)
		}
	}
	hosts = normalizeHosts(hosts)
	out := make([]SMTPReport, 0, len(hosts)*len(ports))
	for _, host := range hosts {
		for _, port := range ports {
			out = append(out, SMTPReport{Host: host, Port: port})
		}
	}
	var wg sync.WaitGroup
	for i := range out {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out[i] = checkSMTPHost(ctx, out[i].Host, out[i].Port, timeout, checkOpenRelay)
		}(i)
	}
	wg.Wait()
	return out
}

func checkSMTPHost(ctx context.Context, host string, port int, timeout time.Duration, checkOpenRelay bool) SMTPReport {
	return checkSMTPHostWithDial(ctx, host, port, timeout, checkOpenRelay, nil)
}

func checkSMTPHostWithDial(ctx context.Context, host string, port int, timeout time.Duration, checkOpenRelay bool, dial func(context.Context, string, string) (net.Conn, error)) SMTPReport {
	return checkSMTPHostWithDialAndTLS(ctx, host, port, timeout, checkOpenRelay, dial, nil)
}

func checkSMTPHostWithDialAndTLS(ctx context.Context, host string, port int, timeout time.Duration, checkOpenRelay bool, dial func(context.Context, string, string) (net.Conn, error), tlsConfig func(string) *tls.Config) SMTPReport {
	rep := SMTPReport{Host: host, Port: port}
	if host == "" {
		rep.Error = "empty MX host"
		return rep
	}
	if timeout <= 0 || timeout > 10*time.Second {
		timeout = 10 * time.Second
	}
	if dial == nil {
		dialer := net.Dialer{Timeout: timeout}
		dial = dialer.DialContext
	}
	if tlsConfig == nil {
		tlsConfig = defaultProbeTLSConfig
	}
	conn, err := dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		rep.Error = err.Error()
		return rep
	}
	defer conn.Close()
	rep.ConnectOK = true
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if port == 465 {
		rep.ImplicitTLS = true
		tlsConn := tls.Client(conn, tlsConfig(host))
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rep.Error = "implicit TLS handshake failed: " + err.Error()
			return rep
		}
		rep.TLSOK = true
		applySMTPState(&rep, tlsConn.ConnectionState())
		reader := bufio.NewReader(tlsConn)
		code, lines, err := readSMTPResponse(reader)
		rep.Banner = strings.Join(lines, " ")
		if err != nil {
			rep.Error = "SMTP banner read failed: " + err.Error()
			return rep
		}
		if code != 220 {
			rep.Error = fmt.Sprintf("SMTP banner returned %d", code)
			return rep
		}
		if _, err := fmt.Fprintf(tlsConn, "EHLO mailops.local\r\n"); err != nil {
			rep.Error = "EHLO write failed: " + err.Error()
			return rep
		}
		code, lines, err = readSMTPResponse(reader)
		if err != nil {
			rep.Error = "EHLO read failed: " + err.Error()
			return rep
		}
		rep.EHLOOK = code == 250
		rep.AuthMechanisms = parseSMTPAuthMechanisms(lines)
		if !rep.EHLOOK {
			rep.Error = fmt.Sprintf("EHLO returned %d", code)
		}
		if checkOpenRelay {
			runSMTPRelayProbe(&rep, tlsConn, reader, "implicit_tls")
		}
		return rep
	}

	reader := bufio.NewReader(conn)
	code, lines, err := readSMTPResponse(reader)
	rep.Banner = strings.Join(lines, " ")
	if err != nil {
		rep.Error = "SMTP banner read failed: " + err.Error()
		return rep
	}
	if code != 220 {
		rep.Error = fmt.Sprintf("SMTP banner returned %d", code)
		return rep
	}

	if _, err := fmt.Fprintf(conn, "EHLO mailops.local\r\n"); err != nil {
		rep.Error = "EHLO write failed: " + err.Error()
		return rep
	}
	code, lines, err = readSMTPResponse(reader)
	if err != nil {
		rep.Error = "EHLO read failed: " + err.Error()
		return rep
	}
	rep.EHLOOK = code == 250
	rep.AuthMechanisms = parseSMTPAuthMechanisms(lines)
	if !rep.EHLOOK {
		rep.Error = fmt.Sprintf("EHLO returned %d", code)
		return rep
	}
	if checkOpenRelay {
		runSMTPRelayProbe(&rep, conn, reader, "plain")
	}
	rep.STARTTLSOffered = smtpLinesContain(lines, "STARTTLS")
	if !rep.STARTTLSOffered {
		rep.Warning = "STARTTLS is not advertised"
		return rep
	}

	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		rep.Error = "STARTTLS write failed: " + err.Error()
		return rep
	}
	code, _, err = readSMTPResponse(reader)
	if err != nil {
		rep.Error = "STARTTLS read failed: " + err.Error()
		return rep
	}
	if code != 220 {
		rep.Error = fmt.Sprintf("STARTTLS returned %d", code)
		return rep
	}

	tlsConn := tls.Client(conn, tlsConfig(host))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rep.Error = "STARTTLS handshake failed: " + err.Error()
		return rep
	}
	rep.STARTTLSOK = true
	rep.TLSOK = true
	applySMTPState(&rep, tlsConn.ConnectionState())
	tlsReader := bufio.NewReader(tlsConn)
	if _, err := fmt.Fprintf(tlsConn, "EHLO mailops.local\r\n"); err != nil {
		rep.Error = "post-STARTTLS EHLO write failed: " + err.Error()
		return rep
	}
	code, lines, err = readSMTPResponse(tlsReader)
	if err != nil {
		rep.Error = "post-STARTTLS EHLO read failed: " + err.Error()
		return rep
	}
	if code != 250 {
		rep.Error = fmt.Sprintf("post-STARTTLS EHLO returned %d", code)
		return rep
	}
	rep.AuthMechanisms = mergeStrings(rep.AuthMechanisms, parseSMTPAuthMechanisms(lines))
	if checkOpenRelay && !rep.OpenRelay {
		runSMTPRelayProbe(&rep, tlsConn, tlsReader, "tls")
	}
	return rep
}

func applySMTPState(rep *SMTPReport, state tls.ConnectionState) {
	rep.TLSVersion = tlsVersionName(state.Version)
	if len(state.PeerCertificates) == 0 {
		return
	}
	cert := state.PeerCertificates[0]
	rep.CertNotAfter = cert.NotAfter.UTC()
	rep.CertDaysRemaining = int(time.Until(cert.NotAfter).Hours() / 24)
	if rep.CertDaysRemaining < 0 {
		rep.Error = fmt.Sprintf("SMTP TLS certificate expired %d days ago", -rep.CertDaysRemaining)
	} else if rep.CertDaysRemaining < 14 {
		rep.Warning = fmt.Sprintf("SMTP TLS certificate expires in %d days", rep.CertDaysRemaining)
	}
}

func readSMTPResponse(reader *bufio.Reader) (int, []string, error) {
	var lines []string
	var code int
	for i := 0; i < 50; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			return code, lines, err
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		if len(line) < 3 {
			continue
		}
		if parsed, err := strconv.Atoi(line[:3]); err == nil {
			code = parsed
		}
		if len(line) < 4 || line[3] != '-' {
			return code, lines, nil
		}
	}
	return code, lines, fmt.Errorf("SMTP response exceeded continuation limit")
}

func runSMTPRelayProbe(rep *SMTPReport, conn net.Conn, reader *bufio.Reader, stage string) {
	rep.RelayCheck = true
	rep.RelayStage = stage
	if _, err := fmt.Fprintf(conn, "MAIL FROM:<mailops-open-relay-test@example.net>\r\n"); err != nil {
		rep.RelayError = "MAIL FROM write failed: " + err.Error()
		return
	}
	code, _, err := readSMTPResponse(reader)
	rep.RelayMailCode = code
	if err != nil {
		rep.RelayError = "MAIL FROM read failed: " + err.Error()
		return
	}
	if code < 200 || code >= 400 {
		_, _ = fmt.Fprintf(conn, "RSET\r\n")
		_, _, _ = readSMTPResponse(reader)
		return
	}
	if _, err := fmt.Fprintf(conn, "RCPT TO:<mailops-open-relay-test@example.org>\r\n"); err != nil {
		rep.RelayError = "RCPT TO write failed: " + err.Error()
		return
	}
	code, _, err = readSMTPResponse(reader)
	rep.RelayRcptCode = code
	if err != nil {
		rep.RelayError = "RCPT TO read failed: " + err.Error()
		return
	}
	rep.OpenRelay = code >= 200 && code < 300
	_, _ = fmt.Fprintf(conn, "RSET\r\n")
	_, _, _ = readSMTPResponse(reader)
}

func smtpLinesContain(lines []string, token string) bool {
	token = strings.ToUpper(token)
	for _, line := range lines {
		line = strings.TrimSpace(strings.ToUpper(line))
		if len(line) >= 4 && line[0] >= '0' && line[0] <= '9' && line[1] >= '0' && line[1] <= '9' && line[2] >= '0' && line[2] <= '9' && (line[3] == '-' || line[3] == ' ') {
			line = strings.TrimSpace(line[4:])
		}
		for _, field := range strings.Fields(line) {
			field = strings.Trim(field, "[](),")
			if field == token || strings.HasPrefix(field, token+"=") {
				return true
			}
		}
	}
	return false
}

func parseSMTPAuthMechanisms(lines []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, line := range lines {
		if len(line) >= 4 {
			line = strings.TrimSpace(line[4:])
		}
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "AUTH=") {
			line = "AUTH " + line[len("AUTH="):]
			upper = strings.ToUpper(line)
		}
		if !strings.HasPrefix(upper, "AUTH ") {
			continue
		}
		for _, mech := range strings.Fields(line[len("AUTH "):]) {
			mech = strings.ToUpper(strings.TrimSpace(mech))
			if mech == "" || seen[mech] {
				continue
			}
			seen[mech] = true
			out = append(out, mech)
		}
	}
	sort.Strings(out)
	return out
}

func mergeStrings(left, right []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(left)+len(right))
	for _, value := range append(left, right...) {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func defaultProbeTLSConfig(serverName string) *tls.Config {
	return &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	default:
		return fmt.Sprintf("0x%x", version)
	}
}

func smtpFindings(rows []SMTPReport, strict bool) []Finding {
	var out []Finding
	for _, row := range rows {
		scope := "smtp"
		prefix := row.Host
		if prefix == "" {
			prefix = "mx"
		}
		if row.Port > 0 {
			prefix = fmt.Sprintf("%s:%d", prefix, row.Port)
		}
		if row.Error != "" {
			severity := SeverityCritical
			if !row.ConnectOK {
				severity = SeverityCritical
			}
			out = append(out, Finding{Severity: severity, Scope: scope, Message: fmt.Sprintf("%s: %s", prefix, row.Error)})
			continue
		}
		if row.OpenRelay {
			out = append(out, Finding{Severity: SeverityCritical, Scope: scope, Message: fmt.Sprintf("%s accepted unauthenticated external relay recipient during %s probe", prefix, row.RelayStage)})
			continue
		}
		if row.RelayError != "" {
			out = append(out, Finding{Severity: SeverityWarn, Scope: scope, Message: fmt.Sprintf("%s open relay probe incomplete: %s", prefix, row.RelayError)})
		}
		if (row.Port == 465 || row.Port == 587) && len(row.AuthMechanisms) == 0 {
			out = append(out, Finding{Severity: SeverityWarn, Scope: scope, Message: fmt.Sprintf("%s does not advertise SMTP AUTH mechanisms", prefix)})
		}
		if row.Warning != "" {
			severity := SeverityWarn
			if strict && strings.Contains(row.Warning, "STARTTLS") {
				severity = SeverityCritical
			}
			out = append(out, Finding{Severity: severity, Scope: scope, Message: fmt.Sprintf("%s: %s", prefix, row.Warning)})
		}
	}
	return out
}

func checkMDA(ctx context.Context, domain string, hosts []string, ports []int, timeout time.Duration, explicit bool) []MDAReport {
	if len(hosts) == 0 {
		hosts = []string{"imap." + domain, "pop." + domain, "mail." + domain}
	}
	normalizedHosts := normalizeHosts(hosts)
	out := make([]MDAReport, 0, len(normalizedHosts)*len(ports))
	for _, host := range normalizedHosts {
		hostPorts := ports
		if !explicit {
			hostPorts = probableMDAPorts(host, ports)
		}
		for _, port := range hostPorts {
			out = append(out, MDAReport{Host: host, Port: port, Protocol: mdaProtocol(port)})
		}
	}
	var wg sync.WaitGroup
	for i := range out {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out[i] = checkMDAHost(ctx, out[i].Host, out[i].Port, timeout)
		}(i)
	}
	wg.Wait()
	return out
}

func probableMDAPorts(host string, ports []int) []int {
	firstLabel := strings.Split(strings.ToLower(strings.TrimSpace(host)), ".")[0]
	var allowed map[int]bool
	switch {
	case strings.HasPrefix(firstLabel, "imap"):
		allowed = map[int]bool{143: true, 993: true}
	case strings.HasPrefix(firstLabel, "pop"):
		allowed = map[int]bool{110: true, 995: true}
	default:
		return ports
	}
	filtered := make([]int, 0, len(ports))
	for _, port := range ports {
		if allowed[port] {
			filtered = append(filtered, port)
		}
	}
	return filtered
}

func normalizeHosts(hosts []string) []string {
	seenHosts := map[string]bool{}
	normalizedHosts := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(host)), ".")
		if host == "" || seenHosts[host] {
			continue
		}
		seenHosts[host] = true
		normalizedHosts = append(normalizedHosts, host)
	}
	return normalizedHosts
}

func checkMDAHost(ctx context.Context, host string, port int, timeout time.Duration) MDAReport {
	return checkMDAHostWithDial(ctx, host, port, timeout, nil)
}

func checkMDAHostWithDial(ctx context.Context, host string, port int, timeout time.Duration, dial func(context.Context, string, string) (net.Conn, error)) MDAReport {
	return checkMDAHostWithDialAndTLS(ctx, host, port, timeout, dial, nil)
}

func checkMDAHostWithDialAndTLS(ctx context.Context, host string, port int, timeout time.Duration, dial func(context.Context, string, string) (net.Conn, error), tlsConfig func(string) *tls.Config) MDAReport {
	rep := MDAReport{Host: host, Port: port, Protocol: mdaProtocol(port)}
	if timeout <= 0 || timeout > 10*time.Second {
		timeout = 10 * time.Second
	}
	if dial == nil {
		dialer := net.Dialer{Timeout: timeout}
		dial = dialer.DialContext
	}
	if tlsConfig == nil {
		tlsConfig = defaultProbeTLSConfig
	}
	conn, err := dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		rep.Error = err.Error()
		return rep
	}
	defer conn.Close()
	rep.ConnectOK = true
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if mdaImplicitTLS(port) {
		tlsConn := tls.Client(conn, tlsConfig(host))
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rep.Error = "TLS handshake failed: " + err.Error()
			return rep
		}
		rep.TLSOK = true
		applyMDAState(&rep, tlsConn.ConnectionState())
		return checkMDAProtocolWithTLS(ctx, &rep, tlsConn, tlsConfig)
	}
	return checkMDAProtocolWithTLS(ctx, &rep, conn, tlsConfig)
}

func checkMDAProtocol(rep *MDAReport, conn net.Conn) MDAReport {
	return checkMDAProtocolWithTLS(context.Background(), rep, conn, defaultProbeTLSConfig)
}

func checkMDAProtocolWithTLS(ctx context.Context, rep *MDAReport, conn net.Conn, tlsConfig func(string) *tls.Config) MDAReport {
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		rep.Error = "banner read failed: " + err.Error()
		return *rep
	}
	rep.Banner = strings.TrimRight(line, "\r\n")

	switch rep.Protocol {
	case "imap", "imaps":
		if !strings.HasPrefix(strings.ToUpper(rep.Banner), "* OK") {
			rep.Warning = "IMAP banner is not OK"
		}
		return checkIMAPCapabilityWithTLS(ctx, rep, conn, reader, tlsConfig)
	case "pop3", "pop3s":
		if !strings.HasPrefix(strings.ToUpper(rep.Banner), "+OK") {
			rep.Warning = "POP3 banner is not OK"
		}
		return checkPOP3CapabilityWithTLS(ctx, rep, conn, reader, tlsConfig)
	default:
		rep.CapabilityOK = true
		return *rep
	}
}

func checkIMAPCapability(rep *MDAReport, conn net.Conn, reader *bufio.Reader) MDAReport {
	return checkIMAPCapabilityWithTLS(context.Background(), rep, conn, reader, defaultProbeTLSConfig)
}

func checkIMAPCapabilityWithTLS(ctx context.Context, rep *MDAReport, conn net.Conn, reader *bufio.Reader, tlsConfig func(string) *tls.Config) MDAReport {
	if _, err := fmt.Fprintf(conn, "a001 CAPABILITY\r\n"); err != nil {
		rep.Error = "IMAP CAPABILITY write failed: " + err.Error()
		return *rep
	}
	lines, err := readTaggedResponse(reader, "a001")
	if err != nil {
		rep.Error = "IMAP CAPABILITY read failed: " + err.Error()
		return *rep
	}
	rep.CapabilityOK = taggedOK(lines, "a001")
	if !rep.CapabilityOK {
		rep.Error = "IMAP CAPABILITY was rejected"
		return *rep
	}
	rep.STARTTLSOffered = smtpLinesContain(lines, "STARTTLS")
	if rep.Protocol == "imaps" {
		return *rep
	}
	if !rep.STARTTLSOffered {
		if rep.Warning == "" {
			rep.Warning = "IMAP STARTTLS is not advertised"
		}
		return *rep
	}
	if _, err := fmt.Fprintf(conn, "a002 STARTTLS\r\n"); err != nil {
		rep.Error = "IMAP STARTTLS write failed: " + err.Error()
		return *rep
	}
	lines, err = readTaggedResponse(reader, "a002")
	if err != nil {
		rep.Error = "IMAP STARTTLS read failed: " + err.Error()
		return *rep
	}
	if !taggedOK(lines, "a002") {
		rep.Error = "IMAP STARTTLS was rejected"
		return *rep
	}
	tlsConn := tls.Client(conn, tlsConfig(rep.Host))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rep.Error = "IMAP STARTTLS handshake failed: " + err.Error()
		return *rep
	}
	rep.TLSOK = true
	applyMDAState(rep, tlsConn.ConnectionState())
	return *rep
}

func checkPOP3Capability(rep *MDAReport, conn net.Conn, reader *bufio.Reader) MDAReport {
	return checkPOP3CapabilityWithTLS(context.Background(), rep, conn, reader, defaultProbeTLSConfig)
}

func checkPOP3CapabilityWithTLS(ctx context.Context, rep *MDAReport, conn net.Conn, reader *bufio.Reader, tlsConfig func(string) *tls.Config) MDAReport {
	if _, err := fmt.Fprintf(conn, "CAPA\r\n"); err != nil {
		rep.Error = "POP3 CAPA write failed: " + err.Error()
		return *rep
	}
	lines, err := readPOP3Multiline(reader)
	if err != nil {
		rep.Error = "POP3 CAPA read failed: " + err.Error()
		return *rep
	}
	rep.CapabilityOK = len(lines) > 0 && strings.HasPrefix(strings.ToUpper(lines[0]), "+OK")
	if !rep.CapabilityOK {
		rep.Error = "POP3 CAPA was rejected"
		return *rep
	}
	rep.STARTTLSOffered = smtpLinesContain(lines, "STLS")
	if rep.Protocol == "pop3s" {
		return *rep
	}
	if !rep.STARTTLSOffered {
		if rep.Warning == "" {
			rep.Warning = "POP3 STLS is not advertised"
		}
		return *rep
	}
	if _, err := fmt.Fprintf(conn, "STLS\r\n"); err != nil {
		rep.Error = "POP3 STLS write failed: " + err.Error()
		return *rep
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		rep.Error = "POP3 STLS read failed: " + err.Error()
		return *rep
	}
	if !strings.HasPrefix(strings.ToUpper(line), "+OK") {
		rep.Error = "POP3 STLS was rejected"
		return *rep
	}
	tlsConn := tls.Client(conn, tlsConfig(rep.Host))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rep.Error = "POP3 STLS handshake failed: " + err.Error()
		return *rep
	}
	rep.TLSOK = true
	applyMDAState(rep, tlsConn.ConnectionState())
	return *rep
}

func readTaggedResponse(reader *bufio.Reader, tag string) ([]string, error) {
	var lines []string
	tag = strings.ToUpper(tag)
	for i := 0; i < 100; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			return lines, err
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		if strings.HasPrefix(strings.ToUpper(line), tag+" ") {
			return lines, nil
		}
	}
	return lines, fmt.Errorf("IMAP response exceeded continuation limit")
}

func taggedOK(lines []string, tag string) bool {
	tag = strings.ToUpper(tag)
	for _, line := range lines {
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, tag+" OK") {
			return true
		}
	}
	return false
}

func readPOP3Multiline(reader *bufio.Reader) ([]string, error) {
	var lines []string
	for i := 0; i < 100; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			return lines, err
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		if line == "." {
			return lines, nil
		}
		if len(lines) == 1 && !strings.HasPrefix(strings.ToUpper(line), "+OK") {
			return lines, nil
		}
	}
	return lines, fmt.Errorf("POP3 response exceeded continuation limit")
}

func mdaProtocol(port int) string {
	switch port {
	case 143:
		return "imap"
	case 993:
		return "imaps"
	case 110:
		return "pop3"
	case 995:
		return "pop3s"
	default:
		return "tcp"
	}
}

func mdaImplicitTLS(port int) bool {
	return port == 993 || port == 995
}

func applyMDAState(rep *MDAReport, state tls.ConnectionState) {
	rep.TLSVersion = tlsVersionName(state.Version)
	if len(state.PeerCertificates) == 0 {
		return
	}
	cert := state.PeerCertificates[0]
	rep.CertNotAfter = cert.NotAfter.UTC()
	rep.CertDaysRemaining = int(time.Until(cert.NotAfter).Hours() / 24)
	if rep.CertDaysRemaining < 0 {
		rep.Error = fmt.Sprintf("%s TLS certificate expired %d days ago", strings.ToUpper(rep.Protocol), -rep.CertDaysRemaining)
	} else if rep.CertDaysRemaining < 14 {
		rep.Warning = fmt.Sprintf("%s TLS certificate expires in %d days", strings.ToUpper(rep.Protocol), rep.CertDaysRemaining)
	}
}

func mdaFindings(rows []MDAReport, explicit bool, strict bool) []Finding {
	var out []Finding
	for _, row := range rows {
		prefix := fmt.Sprintf("%s:%d", row.Host, row.Port)
		if row.Error != "" {
			severity := SeverityWarn
			if explicit || strict {
				severity = SeverityCritical
			}
			out = append(out, Finding{Severity: severity, Scope: "mda", Message: fmt.Sprintf("%s: %s", prefix, row.Error)})
			continue
		}
		if row.Warning != "" {
			severity := SeverityWarn
			if explicit && strict && (strings.Contains(row.Warning, "STARTTLS") || strings.Contains(row.Warning, "STLS")) {
				severity = SeverityCritical
			}
			out = append(out, Finding{Severity: severity, Scope: "mda", Message: fmt.Sprintf("%s: %s", prefix, row.Warning)})
		}
	}
	return out
}

func lookupTXT(ctx context.Context, r resolver, name string) ([]string, error) {
	txts, err := r.LookupTXT(ctx, strings.TrimSuffix(name, "."))
	if err != nil {
		return nil, err
	}
	return txts, nil
}

func mxIPs(records []MXRecord) []string {
	seen := map[string]bool{}
	var out []string
	for _, mx := range records {
		for _, ip := range mx.IPs {
			if !seen[ip] {
				seen[ip] = true
				out = append(out, ip)
			}
		}
	}
	sort.Strings(out)
	return out
}

func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return ""
	}
	toParse := domain
	if !strings.Contains(toParse, "://") {
		toParse = "//" + toParse
	}
	if parsed, err := url.Parse(toParse); err == nil && parsed.Hostname() != "" {
		return strings.TrimSuffix(parsed.Hostname(), ".")
	}
	domain = strings.Split(domain, "/")[0]
	return strings.TrimSuffix(domain, ".")
}

func validMailDomain(domain string) bool {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	return domain != "" && net.ParseIP(domain) == nil && validMTASTSMXPattern(domain)
}

func parseTags(record string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		tags[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(val)
	}
	return tags
}

func parseMailtoList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "mailto:") {
			out = append(out, part)
		}
	}
	return out
}

func parseTLSRPTURIList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		parsed, err := url.Parse(part)
		if err != nil {
			continue
		}
		switch strings.ToLower(parsed.Scheme) {
		case "mailto":
			if domainFromMailto(part) != "" {
				out = append(out, part)
			}
		case "https":
			if parsed.Host != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func domainFromMailto(mailto string) string {
	u, err := url.Parse(mailto)
	if err != nil {
		return ""
	}
	addr := u.Opaque
	if addr == "" {
		addr = u.Path
	}
	_, domain, ok := strings.Cut(addr, "@")
	if !ok {
		return ""
	}
	domain, _, _ = strings.Cut(domain, "!")
	return strings.TrimSuffix(strings.ToLower(domain), ".")
}

func externalReportDomain(source, mailto string) bool {
	dest := domainFromMailto(mailto)
	if dest == "" {
		return false
	}
	return !strings.EqualFold(organizationalDomain(dest), organizationalDomain(source))
}

func organizationalDomain(domain string) string {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	orgDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return domain
	}
	return orgDomain
}

func containsDMARCReportAuth(txts []string) bool {
	for _, txt := range txts {
		if hasTagVersion(txt, "DMARC1") {
			return true
		}
	}
	return false
}

func hasSPFVersion(record string) bool {
	fields := strings.Fields(strings.TrimSpace(record))
	return len(fields) > 0 && strings.EqualFold(fields[0], "v=spf1")
}

func hasTagVersion(record, version string) bool {
	first, _, _ := strings.Cut(strings.TrimSpace(record), ";")
	key, value, ok := strings.Cut(strings.TrimSpace(first), "=")
	return ok && strings.EqualFold(strings.TrimSpace(key), "v") && strings.EqualFold(strings.TrimSpace(value), version)
}

func stripSpaces(s string) string {
	return strings.Join(strings.Fields(s), "")
}

func parseMTASTSPolicy(body string) map[string]string {
	out := map[string]string{}
	var mx []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		if key == "mx" {
			mx = append(mx, val)
		} else if _, exists := out[key]; !exists {
			out[key] = val
		}
	}
	if len(mx) > 0 {
		out["mx"] = strings.Join(mx, ",")
	}
	return out
}

func splitPolicyValues(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func reverseIPv4(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ip
	}
	return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
}

func dnsNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

func DecodeX5CCertDays(raw string) (int, error) {
	der, err := base64.StdEncoding.DecodeString(stripSpaces(raw))
	if err != nil {
		return 0, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return 0, err
	}
	return int(time.Until(cert.NotAfter).Hours() / 24), nil
}
