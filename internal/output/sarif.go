package output

import (
	"encoding/json"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Nexora-NHI/nexora-cli/internal/finding"
	"github.com/Nexora-NHI/nexora-cli/internal/redact"
)

var reAbsoluteURI = regexp.MustCompile(`^(?:[A-Za-z]:[\\/]|/)`)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	HelpURI          string            `json:"helpUri,omitempty"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
}

func WriteSARIF(w io.Writer, toolVersion string, findings []finding.Finding) error {
	rulesMap := make(map[string]sarifRule)
	for _, f := range findings {
		if _, exists := rulesMap[f.RuleID]; !exists {
			rulesMap[f.RuleID] = sarifRule{
				ID:               f.RuleID,
				Name:             sanitizeRuleName(f.RuleID),
				ShortDescription: sarifMessage{Text: f.Title},
				Properties:       map[string]string{"severity": f.Severity.String()},
			}
		}
	}

	rules := make([]sarifRule, 0, len(rulesMap))
	for _, r := range rulesMap {
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		uri := filepath.ToSlash(strings.ReplaceAll(f.FilePath, "\\", "/"))
		// Strip Windows drive letters (C:/) and Unix absolute paths so URI is always relative
		if reAbsoluteURI.MatchString(uri) {
			// Remove drive letter prefix e.g. "C:/" → ""
			if len(uri) >= 3 && uri[1] == ':' {
				uri = uri[3:]
			} else {
				uri = strings.TrimPrefix(uri, "/")
			}
		}
		uri = strings.TrimPrefix(uri, "./")

		startLine := f.LineStart
		if startLine < 1 {
			startLine = 1
		}
		endLine := f.LineEnd
		if endLine < startLine {
			endLine = startLine
		}

		msgText := redact.String(f.Description)
		if f.Evidence != "" {
			msgText += " Evidence: " + redact.String(f.Evidence)
		}

		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Level:   severityToSARIFLevel(f.Severity),
			Message: sarifMessage{Text: msgText},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI:       uri,
							URIBaseID: "%SRCROOT%",
						},
						Region: sarifRegion{
							StartLine: startLine,
							EndLine:   endLine,
						},
					},
				},
			},
		})
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "nexora-cli",
						Version:        toolVersion,
						InformationURI: "https://github.com/Nexora-NHI/nexora-cli",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func severityToSARIFLevel(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func sanitizeRuleName(ruleID string) string {
	return strings.ReplaceAll(ruleID, "-", "")
}
