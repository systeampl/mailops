package mailcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxBIMIAssetSize = 2 * 1024 * 1024

func inspectBIMIAssets(ctx context.Context, r resolver, report *BIMIReport, timeout time.Duration, allowPrivate bool) {
	if report == nil || !report.Present || !report.Valid || report.Declined || report.LogoURL == "" {
		return
	}
	client := newBIMIHTTPClient(r, timeout, allowPrivate)
	inspectBIMIAssetsWithClient(ctx, r, report, allowPrivate, client)
}

func newBIMIHTTPClient(r resolver, timeout time.Duration, allowPrivate bool) *http.Client {
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		Proxy:             nil,
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, err := r.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, resolved := range ips {
				if !allowPrivate {
					if err := validateTargetHost(ctx, r, resolved.IP.String()); err != nil {
						continue
					}
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(resolved.IP.String(), port))
			}
			return nil, fmt.Errorf("no permitted address for %s", host)
		},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func inspectBIMIAssetsWithClient(ctx context.Context, r resolver, report *BIMIReport, allowPrivate bool, client *http.Client) {
	logo, mediaType, err := fetchBIMIAsset(ctx, r, client, report.LogoURL, allowPrivate)
	if err != nil {
		report.AssetError = "BIMI logo fetch failed: " + err.Error()
		return
	}
	report.LogoFetched = true
	report.LogoMediaType = mediaType
	if err := validateBIMISVG(logo, mediaType); err != nil {
		report.AssetError = "BIMI logo is invalid: " + err.Error()
		return
	}
	report.LogoValid = true

	if report.AuthorityURL == "" {
		return
	}
	authority, _, err := fetchBIMIAsset(ctx, r, client, report.AuthorityURL, allowPrivate)
	if err != nil {
		report.AssetError = "BIMI authority evidence fetch failed: " + err.Error()
		return
	}
	report.AuthorityFetched = true
	if err := validateBIMIAuthority(authority, time.Now()); err != nil {
		report.AssetError = "BIMI authority evidence is invalid: " + err.Error()
		return
	}
	report.AuthorityValid = true
}

func fetchBIMIAsset(ctx context.Context, r resolver, client *http.Client, rawURL string, allowPrivate bool) ([]byte, string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" {
		return nil, "", fmt.Errorf("invalid URL")
	}
	if !allowPrivate {
		if err := validateTargetHost(ctx, r, parsed.Hostname()); err != nil {
			return nil, "", fmt.Errorf("target blocked: %w", err)
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", err
	}
	request.Header.Set("Accept", "image/svg+xml, application/pem-certificate-chain, application/x-pem-file, */*;q=0.1")
	response, err := client.Do(request)
	if err != nil {
		return nil, "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBIMIAssetSize+1))
	if err != nil {
		return nil, "", err
	}
	if len(body) > maxBIMIAssetSize {
		return nil, "", fmt.Errorf("asset exceeds %d bytes", maxBIMIAssetSize)
	}
	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	return body, strings.ToLower(mediaType), nil
}

func validateBIMISVG(body []byte, mediaType string) error {
	if mediaType != "image/svg+xml" {
		return fmt.Errorf("Content-Type must be image/svg+xml")
	}
	var root struct {
		XMLName     xml.Name
		Version     string `xml:"version,attr"`
		BaseProfile string `xml:"baseProfile,attr"`
	}
	decoder := xml.NewDecoder(strings.NewReader(string(body)))
	decoder.Strict = true
	if err := decoder.Decode(&root); err != nil {
		return fmt.Errorf("malformed SVG XML: %w", err)
	}
	if root.XMLName.Local != "svg" {
		return fmt.Errorf("document root is not svg")
	}
	if root.Version != "1.2" || !strings.EqualFold(root.BaseProfile, "tiny-ps") {
		return fmt.Errorf("SVG must use version 1.2 and baseProfile tiny-ps")
	}
	lower := strings.ToLower(string(body))
	lower = strings.ReplaceAll(lower, `xmlns="http://www.w3.org/2000/svg"`, "")
	lower = strings.ReplaceAll(lower, `xmlns='http://www.w3.org/2000/svg'`, "")
	if strings.Contains(lower, "<script") || strings.Contains(lower, "javascript:") || strings.Contains(lower, "http://") || strings.Contains(lower, "https://") {
		return fmt.Errorf("SVG contains active or external content")
	}
	return nil
}

func validateBIMIAuthority(body []byte, now time.Time) error {
	der := body
	if block, _ := pem.Decode(body); block != nil {
		der = block.Bytes
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("not an X.509 certificate: %w", err)
	}
	if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
		return fmt.Errorf("certificate is outside its validity period")
	}
	return nil
}
