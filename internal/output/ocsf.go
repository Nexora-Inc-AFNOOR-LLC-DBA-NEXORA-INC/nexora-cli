package output

import (
	"bufio"
	"encoding/json"
	"io"
	"time"

	"github.com/Nexora-NHI/nexora-cli/internal/finding"
	"github.com/Nexora-NHI/nexora-cli/internal/redact"
)

type ocsfFinding struct {
	ClassUID    int             `json:"class_uid"`
	CategoryUID int             `json:"category_uid"`
	ActivityID  int             `json:"activity_id"`
	TypeUID     int             `json:"type_uid"`
	Time        int64           `json:"time"`
	Severity    string          `json:"severity"`
	SeverityID  int             `json:"severity_id"`
	Status      string          `json:"status"`
	FindingInfo ocsfFindingInfo `json:"finding_info"`
	Resources   []ocsfResource  `json:"resources"`
	Metadata    ocsfMetadata    `json:"metadata"`
}

type ocsfFindingInfo struct {
	UID   string   `json:"uid"`
	Title string   `json:"title"`
	Desc  string   `json:"desc"`
	Types []string `json:"types"`
}

type ocsfResource struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type ocsfMetadata struct {
	Product ocsfProduct `json:"product"`
	Version string      `json:"version"`
}

type ocsfProduct struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func WriteOCSF(w io.Writer, toolVersion string, findings []finding.Finding) error {
	bw := bufio.NewWriter(w)
	now := time.Now().UTC().UnixMilli()

	for _, f := range findings {
		desc := redact.String(f.Description)
		if f.Evidence != "" {
			desc += " | Evidence: " + redact.String(f.Evidence)
		}

		obj := ocsfFinding{
			ClassUID:    2001,
			CategoryUID: 2,
			ActivityID:  1,
			TypeUID:     200101,
			Time:        now,
			Severity:    f.Severity.String(),
			SeverityID:  severityToOCSFID(f.Severity),
			Status:      "New",
			FindingInfo: ocsfFindingInfo{
				UID:   f.Fingerprint,
				Title: f.Title,
				Desc:  desc,
				Types: []string{f.RuleID},
			},
			Resources: []ocsfResource{
				{Name: f.FilePath, Type: "File"},
			},
			Metadata: ocsfMetadata{
				Product: ocsfProduct{
					Name:    "nexora-cli",
					Version: toolVersion,
				},
				Version: "1.1.0",
			},
		}

		data, err := json.Marshal(obj)
		if err != nil {
			return err
		}
		if _, err := bw.Write(data); err != nil {
			return err
		}
		if err := bw.WriteByte('\n'); err != nil {
			return err
		}
	}
	return bw.Flush()
}

func severityToOCSFID(s finding.Severity) int {
	switch s {
	case finding.SeverityInfo:
		return 1
	case finding.SeverityLow:
		return 2
	case finding.SeverityMedium:
		return 3
	case finding.SeverityHigh:
		return 4
	case finding.SeverityCritical:
		return 5
	default:
		return 0
	}
}
