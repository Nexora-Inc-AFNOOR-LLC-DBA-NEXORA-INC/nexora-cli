package finding

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeverityString(t *testing.T) {
	cases := []struct {
		sev  Severity
		want string
	}{
		{SeverityInfo, "INFO"},
		{SeverityLow, "LOW"},
		{SeverityMedium, "MEDIUM"},
		{SeverityHigh, "HIGH"},
		{SeverityCritical, "CRITICAL"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.sev.String())
	}
}

func TestParseSeverity(t *testing.T) {
	sev, err := ParseSeverity("HIGH")
	require.NoError(t, err)
	assert.Equal(t, SeverityHigh, sev)

	sev, err = ParseSeverity("critical")
	require.NoError(t, err)
	assert.Equal(t, SeverityCritical, sev)

	_, err = ParseSeverity("BOGUS")
	assert.Error(t, err)
}

func TestSort(t *testing.T) {
	findings := []Finding{
		{RuleID: "NXR-GH-001", Severity: SeverityHigh, FilePath: "b.yml", LineStart: 1},
		{RuleID: "NXR-GH-002", Severity: SeverityCritical, FilePath: "a.yml", LineStart: 5},
		{RuleID: "NXR-GH-001", Severity: SeverityHigh, FilePath: "a.yml", LineStart: 2},
	}
	Sort(findings)
	assert.Equal(t, SeverityCritical, findings[0].Severity)
	assert.Equal(t, "a.yml", findings[1].FilePath)
}
