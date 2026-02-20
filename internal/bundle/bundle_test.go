package bundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/finding"
)

func TestWriteAndVerify(t *testing.T) {
	dir := t.TempDir()
	findings := []finding.Finding{
		{
			RuleID:      "NXR-GH-001",
			Severity:    finding.SeverityHigh,
			Title:       "Test finding",
			Description: "Test description",
			FilePath:    "test.yml",
			LineStart:   1,
			Fingerprint: "abc123",
		},
	}

	err := Write(dir, "test-scan-id", "dev", findings)
	require.NoError(t, err)

	for _, name := range []string{"findings.json", "findings.sarif", "findings.ocsf.jsonl", "scan-metadata.json", "manifest.json"} {
		_, err := os.Stat(filepath.Join(dir, name))
		assert.NoError(t, err, "expected file %s to exist", name)
	}

	results, err := Verify(dir)
	require.NoError(t, err)
	for _, r := range results {
		assert.True(t, r.Passed, "expected %s to pass verification, got: %s", r.File, r.Reason)
	}
}

func TestVerify_TamperedFile(t *testing.T) {
	dir := t.TempDir()
	err := Write(dir, "test-scan-id", "dev", nil)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(dir, "findings.json"), []byte("tampered"), 0o600)
	require.NoError(t, err)

	results, err := Verify(dir)
	require.NoError(t, err)

	failed := false
	for _, r := range results {
		if r.File == "findings.json" && !r.Passed {
			failed = true
		}
	}
	assert.True(t, failed, "expected findings.json to fail verification after tampering")
}

func TestManifestHasRequiredFields(t *testing.T) {
	dir := t.TempDir()
	err := Write(dir, "", "dev", nil)
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	require.NoError(t, err)

	var m Manifest
	require.NoError(t, json.Unmarshal(data, &m))
	assert.NotEmpty(t, m.ScanID)
	assert.NotEmpty(t, m.ScanTimestampUTC)
	assert.NotEmpty(t, m.FilesRootHash)
	assert.Len(t, m.Files, 4)
}
