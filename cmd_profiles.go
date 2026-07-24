package main

import (
	"fmt"
	"sort"
	"strings"
)

type providerProfile struct {
	Name          string
	DKIMSelectors []string
	SMTPHosts     []string
	SMTPPorts     []int
	MDAHosts      []string
	MDAPorts      []int
}

var providerProfiles = map[string]providerProfile{
	"google-workspace": {
		Name:          "google-workspace",
		DKIMSelectors: []string{"google", "selector1", "selector2", "20230601", "20210112"},
		SMTPHosts:     []string{"smtp.gmail.com"},
		SMTPPorts:     []int{465, 587},
		MDAHosts:      []string{"imap.gmail.com", "pop.gmail.com"},
		MDAPorts:      []int{993, 995},
	},
	"gmail": {
		Name:          "gmail",
		DKIMSelectors: []string{"google", "selector1", "selector2", "20230601", "20210112"},
		SMTPHosts:     []string{"smtp.gmail.com"},
		SMTPPorts:     []int{465, 587},
		MDAHosts:      []string{"imap.gmail.com", "pop.gmail.com"},
		MDAPorts:      []int{993, 995},
	},
	"microsoft-365": {
		Name:          "microsoft-365",
		DKIMSelectors: []string{"selector1", "selector2"},
		SMTPHosts:     []string{"smtp.office365.com"},
		SMTPPorts:     []int{587},
		MDAHosts:      []string{"outlook.office365.com"},
		MDAPorts:      []int{993, 995},
	},
	"office365": {
		Name:          "office365",
		DKIMSelectors: []string{"selector1", "selector2"},
		SMTPHosts:     []string{"smtp.office365.com"},
		SMTPPorts:     []int{587},
		MDAHosts:      []string{"outlook.office365.com"},
		MDAPorts:      []int{993, 995},
	},
	"amazonses": {
		Name:          "amazonses",
		DKIMSelectors: []string{"amazonses"},
	},
	"sendgrid": {
		Name:          "sendgrid",
		DKIMSelectors: []string{"s1", "s2", "smtpapi"},
		SMTPHosts:     []string{"smtp.sendgrid.net"},
		SMTPPorts:     []int{465, 587},
	},
	"mailgun": {
		Name:          "mailgun",
		DKIMSelectors: []string{"mailgun", "smtp", "k1", "k2"},
		SMTPHosts:     []string{"smtp.mailgun.org"},
		SMTPPorts:     []int{465, 587},
	},
	"postmark": {
		Name:          "postmark",
		DKIMSelectors: []string{"pm", "pm1", "pm2", "postmark"},
		SMTPHosts:     []string{"smtp.postmarkapp.com"},
		SMTPPorts:     []int{465, 587},
	},
	"mandrill": {
		Name:          "mandrill",
		DKIMSelectors: []string{"mandrill", "dkim"},
		SMTPHosts:     []string{"smtp.mandrillapp.com"},
		SMTPPorts:     []int{465, 587},
	},
	"zoho": {
		Name:          "zoho",
		DKIMSelectors: []string{"zoho", "zmail", "selector1", "selector2"},
		SMTPHosts:     []string{"smtp.zoho.com"},
		SMTPPorts:     []int{465, 587},
		MDAHosts:      []string{"imap.zoho.com", "pop.zoho.com"},
		MDAPorts:      []int{993, 995},
	},
}

func applyProfiles(names []string, selectors []string, smtpHosts []string, smtpPorts []int, smtpPortsExplicit bool, mdaHosts []string, mdaPorts []int, mdaPortsExplicit bool) ([]string, []string, []int, []string, []int, []string, error) {
	applied := make([]string, 0, len(names))
	smtpHostsExplicit := len(smtpHosts) > 0
	mdaHostsExplicit := len(mdaHosts) > 0
	for _, raw := range names {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		profile, ok := providerProfiles[name]
		if !ok {
			return nil, nil, nil, nil, nil, nil, fmt.Errorf("unknown profile %q", raw)
		}
		applied = append(applied, profile.Name)
		selectors = appendUniqueStrings(selectors, profile.DKIMSelectors...)
		if !smtpHostsExplicit {
			smtpHosts = appendUniqueStrings(smtpHosts, profile.SMTPHosts...)
		}
		if !smtpPortsExplicit && len(profile.SMTPPorts) > 0 {
			smtpPorts = appendUniqueInts(smtpPorts, profile.SMTPPorts...)
		}
		if !mdaHostsExplicit {
			mdaHosts = appendUniqueStrings(mdaHosts, profile.MDAHosts...)
		}
		if !mdaPortsExplicit && len(profile.MDAPorts) > 0 {
			mdaPorts = appendUniqueInts(mdaPorts, profile.MDAPorts...)
		}
	}
	return appendUniqueStrings(nil, applied...), selectors, smtpPorts, smtpHosts, mdaPorts, mdaHosts, nil
}

func appendUniqueStrings(base []string, values ...string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(base)+len(values))
	for _, value := range append(base, values...) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	return out
}

func appendUniqueInts(base []int, values ...int) []int {
	seen := map[int]bool{}
	out := make([]int, 0, len(base)+len(values))
	for _, value := range append(base, values...) {
		if value <= 0 || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Ints(out)
	return out
}
