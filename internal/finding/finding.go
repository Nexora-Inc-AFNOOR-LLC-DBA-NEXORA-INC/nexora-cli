package finding

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

type Finding struct {
	RuleID      string   `json:"rule_id"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	NHIContext  string   `json:"nhi_context"`
	FilePath    string   `json:"file_path"`
	LineStart   int      `json:"line_start"`
	LineEnd     int      `json:"line_end"`
	Evidence    string   `json:"evidence"`
	Fix         string   `json:"fix"`
	References  []string `json:"references"`
	Fingerprint string   `json:"fingerprint"`
}

func (f *Finding) ComputeFingerprint() {
	normalized := filepath.ToSlash(strings.ToLower(f.FilePath))
	evidenceKey := strings.SplitN(f.Evidence, ":", 2)[0]
	raw := fmt.Sprintf("%s|%s|%s", f.RuleID, normalized, evidenceKey)
	sum := sha256.Sum256([]byte(raw))
	f.Fingerprint = fmt.Sprintf("%x", sum[:8])
}

func Sort(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.FilePath != b.FilePath {
			return a.FilePath < b.FilePath
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.LineStart != b.LineStart {
			return a.LineStart < b.LineStart
		}
		return a.Fingerprint < b.Fingerprint
	})
}

func Filter(findings []Finding, threshold Severity) []Finding {
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if f.Severity >= threshold {
			out = append(out, f)
		}
	}
	return out
}
