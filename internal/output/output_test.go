package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Nexora-NHI/nexora-cli/internal/finding"
)

var testFindings = []finding.Finding{
	{
		RuleID:      "NXR-GH-001",
		Severity:    finding.SeverityHigh,
		Title:       "Broad workflow-level write permissions",
		Description: "Workflow sets broad write permissions.",
		FilePath:    "test/workflow.yml",
		LineStart:   5,
		LineEnd:     5,
		Evidence:    "permissions: write-all",
		Fingerprint: "aabbccdd",
	},
	{
		RuleID:      "NXR-K8S-001",
		Severity:    finding.SeverityCritical,
		Title:       "ServiceAccount bound to cluster-admin",
		Description: "SA bound to cluster-admin.",
		FilePath:    "test/binding.yaml",
		LineStart:   10,
		LineEnd:     10,
		Evidence:    "subject: default/sa, roleRef: cluster-admin",
		Fingerprint: "11223344",
	},
}

func TestWriteTable_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	err := WriteTable(&buf, nil)
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "SEVERITY")
	assert.Contains(t, out, "RULE ID")
}

func TestWriteTable_WithFindings(t *testing.T) {
	var buf bytes.Buffer
	err := WriteTable(&buf, testFindings)
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "NXR-GH-001")
	assert.Contains(t, out, "NXR-K8S-001")
	assert.Contains(t, out, "HIGH")
	assert.Contains(t, out, "CRITICAL")
}

func TestWriteJSON_Structure(t *testing.T) {
	var buf bytes.Buffer
	err := WriteJSON(&buf, "scan-123", "v0.1.0", testFindings)
	require.NoError(t, err)

	var report JSONReport
	require.NoError(t, json.Unmarshal(buf.Bytes(), &report))

	assert.Equal(t, "scan-123", report.ScanID)
	assert.Equal(t, "v0.1.0", report.Version)
	assert.Equal(t, 2, report.TotalFindings)
	assert.Len(t, report.Findings, 2)
}

func TestWriteJSON_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	err := WriteJSON(&buf, "scan-empty", "v0.1.0", nil)
	require.NoError(t, err)

	var report JSONReport
	require.NoError(t, json.Unmarshal(buf.Bytes(), &report))
	assert.Equal(t, 0, report.TotalFindings)
}

func TestWriteSARIF_ValidStructure(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSARIF(&buf, "v0.1.0", testFindings)
	require.NoError(t, err)

	var sarif map[string]interface{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &sarif))

	assert.Equal(t, "2.1.0", sarif["version"])
	runs := sarif["runs"].([]interface{})
	require.Len(t, runs, 1)

	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	assert.Len(t, results, 2)
}

func TestWriteSARIF_LevelMapping(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSARIF(&buf, "v0.1.0", testFindings)
	require.NoError(t, err)

	var sarif map[string]interface{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &sarif))
	runs := sarif["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})

	levels := make(map[string]bool)
	for _, r := range results {
		res := r.(map[string]interface{})
		levels[res["level"].(string)] = true
	}
	assert.True(t, levels["error"], "HIGH and CRITICAL should map to 'error'")
}

func TestWriteSARIF_RedactsEvidence(t *testing.T) {
	findings := []finding.Finding{
		{
			RuleID:      "NXR-GH-004",
			Severity:    finding.SeverityCritical,
			Title:       "Hardcoded credential",
			Description: "Token found",
			Evidence:    "TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			FilePath:    "workflow.yml",
			LineStart:   1,
		},
	}
	var buf bytes.Buffer
	err := WriteSARIF(&buf, "v0.1.0", findings)
	require.NoError(t, err)
	assert.NotContains(t, buf.String(), "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
	assert.Contains(t, buf.String(), "REDACTED")
}

func TestWriteOCSF_ValidJSONL(t *testing.T) {
	var buf bytes.Buffer
	err := WriteOCSF(&buf, "v0.1.0", testFindings)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.Len(t, lines, 2)

	for _, line := range lines {
		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(line), &obj))
		assert.EqualValues(t, 2001, obj["class_uid"])
		assert.NotEmpty(t, obj["severity"])
	}
}

func TestWriteOCSF_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	err := WriteOCSF(&buf, "v0.1.0", nil)
	require.NoError(t, err)
	assert.Empty(t, strings.TrimSpace(buf.String()))
}

func TestWriteOCSF_RedactsEvidence(t *testing.T) {
	findings := []finding.Finding{
		{
			RuleID:      "NXR-IAC-002",
			Severity:    finding.SeverityCritical,
			Title:       "Hardcoded key",
			Description: "Key found",
			Evidence:    "AKIAIOSFODNN7EXAMPLE in terraform",
			FilePath:    "main.tf",
			LineStart:   1,
		},
	}
	var buf bytes.Buffer
	err := WriteOCSF(&buf, "v0.1.0", findings)
	require.NoError(t, err)
	assert.NotContains(t, buf.String(), "AKIAIOSFODNN7EXAMPLE")
	assert.Contains(t, buf.String(), "REDACTED")
}

func TestTruncate(t *testing.T) {
	assert.Equal(t, "hello", truncate("hello", 10))
	assert.Equal(t, "...orld", truncate("hello world", 7))
}

func TestWriteSARIF_RulesAreSorted(t *testing.T) {
	findings := []finding.Finding{
		{RuleID: "NXR-K8S-001", Severity: finding.SeverityCritical, Title: "K8S rule", FilePath: "a.yaml", LineStart: 1},
		{RuleID: "NXR-GH-001", Severity: finding.SeverityHigh, Title: "GH rule", FilePath: "b.yml", LineStart: 1},
		{RuleID: "NXR-IAC-001", Severity: finding.SeverityCritical, Title: "IAC rule", FilePath: "c.tf", LineStart: 1},
	}
	var buf bytes.Buffer
	require.NoError(t, WriteSARIF(&buf, "v0.1.0", findings))

	var log map[string]interface{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &log))

	runs := log["runs"].([]interface{})
	driver := runs[0].(map[string]interface{})["tool"].(map[string]interface{})["driver"].(map[string]interface{})
	rules := driver["rules"].([]interface{})
	require.Len(t, rules, 3)

	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.(map[string]interface{})["id"].(string)
	}
	assert.Equal(t, []string{"NXR-GH-001", "NXR-IAC-001", "NXR-K8S-001"}, ids, "rules must be sorted by ID")
}

func TestWriteSARIF_URIIsRelative(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"relative/path/file.yml", "relative/path/file.yml"},
		{"./relative/path/file.yml", "relative/path/file.yml"},
		{"/absolute/unix/path.yml", "absolute/unix/path.yml"},
		{"C:/Users/user/project/file.tf", "Users/user/project/file.tf"},
		{"C:\\Users\\user\\project\\file.tf", "Users/user/project/file.tf"},
	}
	for _, tc := range cases {
		findings := []finding.Finding{
			{RuleID: "NXR-GH-001", Severity: finding.SeverityHigh, Title: "T", FilePath: tc.input, LineStart: 1},
		}
		var buf bytes.Buffer
		require.NoError(t, WriteSARIF(&buf, "v0.1.0", findings))

		var log map[string]interface{}
		require.NoError(t, json.Unmarshal(buf.Bytes(), &log))

		runs := log["runs"].([]interface{})
		results := runs[0].(map[string]interface{})["results"].([]interface{})
		loc := results[0].(map[string]interface{})["locations"].([]interface{})[0].(map[string]interface{})
		physLoc := loc["physicalLocation"].(map[string]interface{})
		uri := physLoc["artifactLocation"].(map[string]interface{})["uri"].(string)

		assert.Equal(t, tc.want, uri, "input: %s", tc.input)
	}
}

func TestWriteSARIF_MessageTextRedacted(t *testing.T) {
	findings := []finding.Finding{
		{
			RuleID:      "NXR-IAC-002",
			Severity:    finding.SeverityCritical,
			Title:       "Hardcoded key",
			Description: "Key found",
			Evidence:    "AKIAIOSFODNN7EXAMPLE in terraform",
			FilePath:    "main.tf",
			LineStart:   1,
		},
	}
	var buf bytes.Buffer
	require.NoError(t, WriteSARIF(&buf, "v0.1.0", findings))
	assert.NotContains(t, buf.String(), "AKIAIOSFODNN7EXAMPLE")
	assert.Contains(t, buf.String(), "REDACTED")
}

func TestWriteSARIF_ToolMetadataNotRedacted(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, WriteSARIF(&buf, "v0.1.0", testFindings))

	out := buf.String()
	assert.Contains(t, out, `"name": "nexora-cli"`, "tool name must not be redacted")
	assert.Contains(t, out, `"version": "v0.1.0"`, "tool version must not be redacted")
	assert.Contains(t, out, `"version": "2.1.0"`, "SARIF schema version must not be redacted")
}
