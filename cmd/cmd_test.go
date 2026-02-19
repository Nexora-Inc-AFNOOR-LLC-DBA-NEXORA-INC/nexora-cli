package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- parseSeverityFlag ---

func TestParseSeverityFlag_Valid(t *testing.T) {
	cases := []struct {
		input string
		want  finding.Severity
	}{
		{"info", finding.SeverityInfo},
		{"low", finding.SeverityLow},
		{"medium", finding.SeverityMedium},
		{"high", finding.SeverityHigh},
		{"critical", finding.SeverityCritical},
		{"INFO", finding.SeverityInfo},
		{"CRITICAL", finding.SeverityCritical},
	}
	for _, tc := range cases {
		got, err := parseSeverityFlag(tc.input)
		require.NoError(t, err, "input: %s", tc.input)
		assert.Equal(t, tc.want, got, "input: %s", tc.input)
	}
}

func TestParseSeverityFlag_Invalid(t *testing.T) {
	_, err := parseSeverityFlag("bogus")
	assert.Error(t, err)
}

// --- splitRepo ---

func TestSplitRepo_Valid(t *testing.T) {
	owner, repo, err := splitRepo("my-org/my-repo")
	require.NoError(t, err)
	assert.Equal(t, "my-org", owner)
	assert.Equal(t, "my-repo", repo)
}

func TestSplitRepo_Invalid(t *testing.T) {
	_, _, err := splitRepo("no-slash-here")
	assert.Error(t, err)
}

// --- writeFindings ---

func TestWriteFindings_TableToBuffer(t *testing.T) {
	findings := []finding.Finding{
		{
			RuleID:   "NXR-GH-001",
			Severity: finding.SeverityHigh,
			Title:    "Test finding",
			FilePath: "test.yml",
		},
	}

	rootCmd.SetOut(&bytes.Buffer{})
	err := writeFindings(rootCmd, findings, "table", "", "")
	assert.NoError(t, err)
}

func TestWriteFindings_JSONToFile(t *testing.T) {
	findings := []finding.Finding{
		{
			RuleID:   "NXR-K8S-001",
			Severity: finding.SeverityCritical,
			Title:    "Cluster admin binding",
			FilePath: "binding.yaml",
		},
	}

	dir := t.TempDir()
	outFile := filepath.Join(dir, "out.json")

	err := writeFindings(rootCmd, findings, "json", outFile, "")
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var report map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &report))
	assert.NotEmpty(t, report["scan_id"])
	assert.EqualValues(t, 1, report["total_findings"])
}

func TestWriteFindings_SARIFToFile(t *testing.T) {
	findings := []finding.Finding{
		{
			RuleID:    "NXR-IAC-001",
			Severity:  finding.SeverityCritical,
			Title:     "IAM wildcard",
			FilePath:  "main.tf",
			LineStart: 3,
		},
	}

	dir := t.TempDir()
	outFile := filepath.Join(dir, "out.sarif")

	err := writeFindings(rootCmd, findings, "sarif", outFile, "")
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sarif map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sarif))
	assert.Equal(t, "2.1.0", sarif["version"])
}

func TestWriteFindings_OCSFToFile(t *testing.T) {
	findings := []finding.Finding{
		{
			RuleID:   "NXR-IAC-002",
			Severity: finding.SeverityCritical,
			Title:    "Hardcoded key",
			FilePath: "main.tf",
		},
	}

	dir := t.TempDir()
	outFile := filepath.Join(dir, "out.jsonl")

	err := writeFindings(rootCmd, findings, "ocsf", outFile, "")
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

// --- fixture path sanity checks ---

func TestFixturePaths_Exist(t *testing.T) {
	paths := []string{
		filepath.Join("..", "fixtures", "vulnerable", "k8s"),
		filepath.Join("..", "fixtures", "vulnerable", "terraform"),
		filepath.Join("..", "fixtures", "clean", "k8s"),
		filepath.Join("..", "fixtures", "clean", "terraform"),
	}
	for _, p := range paths {
		_, err := os.Stat(p)
		assert.NoError(t, err, "expected fixture path to exist: %s", p)
	}
}
