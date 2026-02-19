package finding

import (
	"fmt"
	"strings"
)

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityInfo:     "INFO",
	SeverityLow:      "LOW",
	SeverityMedium:   "MEDIUM",
	SeverityHigh:     "HIGH",
	SeverityCritical: "CRITICAL",
}

func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return "UNKNOWN"
}

func ParseSeverity(s string) (Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "INFO":
		return SeverityInfo, nil
	case "LOW":
		return SeverityLow, nil
	case "MEDIUM":
		return SeverityMedium, nil
	case "HIGH":
		return SeverityHigh, nil
	case "CRITICAL":
		return SeverityCritical, nil
	default:
		return SeverityInfo, fmt.Errorf("unknown severity %q", s)
	}
}
