// Package mailops exposes the supported, versioned mail checking engine.
//
// Consumers should use this package instead of internal/mailcheck. Additive
// fields may appear within a schema version; breaking changes increment the
// major component of SchemaVersion.
package mailops

import (
	"context"

	"github.com/systeampl/mailops/internal/mailcheck"
)

const (
	SchemaVersion    = mailcheck.SchemaVersion
	SeverityInfo     = mailcheck.SeverityInfo
	SeverityWarn     = mailcheck.SeverityWarn
	SeverityCritical = mailcheck.SeverityCritical
	SeverityError    = mailcheck.SeverityError
)

type (
	Options        = mailcheck.Options
	Report         = mailcheck.Report
	Finding        = mailcheck.Finding
	RecordCounts   = mailcheck.RecordCounts
	ReportSummary  = mailcheck.ReportSummary
	MXRecord       = mailcheck.MXRecord
	SPFReport      = mailcheck.SPFReport
	DKIMReport     = mailcheck.DKIMReport
	DMARCReport    = mailcheck.DMARCReport
	DNSSECReport   = mailcheck.DNSSECReport
	DANEReport     = mailcheck.DANEReport
	TLSARecord     = mailcheck.TLSARecord
	MTASTSReport   = mailcheck.MTASTSReport
	TLSRPTReport   = mailcheck.TLSRPTReport
	BIMIReport     = mailcheck.BIMIReport
	PTRReport      = mailcheck.PTRReport
	RBLReport      = mailcheck.RBLReport
	DomainBLReport = mailcheck.DomainBLReport
	SMTPReport     = mailcheck.SMTPReport
	MDAReport      = mailcheck.MDAReport
)

// Run evaluates one domain and always returns a complete report. Input and
// runtime failures are represented in Report.Error and Report.Findings.
func Run(ctx context.Context, options Options) Report {
	return mailcheck.Run(ctx, options)
}
