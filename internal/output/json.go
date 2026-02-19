package output

import (
	"encoding/json"
	"io"
	"time"

	"github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/finding"
)

type JSONReport struct {
	ScanID        string           `json:"scan_id"`
	ScanTimestamp string           `json:"scan_timestamp_utc"`
	Version       string           `json:"version"`
	TotalFindings int              `json:"total_findings"`
	Findings      []finding.Finding `json:"findings"`
}

func WriteJSON(w io.Writer, scanID, version string, findings []finding.Finding) error {
	report := JSONReport{
		ScanID:        scanID,
		ScanTimestamp: time.Now().UTC().Format(time.RFC3339),
		Version:       version,
		TotalFindings: len(findings),
		Findings:      findings,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
