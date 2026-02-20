package github

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/finding"
)

func TestScanBytes_UnpinnedAction(t *testing.T) {
	data := []byte(`
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`)
	s := New()
	findings, err := s.ScanBytes(data, ".github/workflows/test.yml")
	require.NoError(t, err)
	assert.True(t, hasRuleID(findings, "NXR-GH-002"))
}

func TestScanBytes_PinnedAction_NoFinding(t *testing.T) {
	data := []byte(`
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
`)
	s := New()
	findings, err := s.ScanBytes(data, ".github/workflows/test.yml")
	require.NoError(t, err)
	assert.False(t, hasRuleID(findings, "NXR-GH-002"))
}

func TestScanBytes_BroadPermissions(t *testing.T) {
	data := []byte(`
on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`)
	s := New()
	findings, err := s.ScanBytes(data, ".github/workflows/test.yml")
	require.NoError(t, err)
	assert.True(t, hasRuleID(findings, "NXR-GH-001"))
}

func TestScanBytes_PRTCheckout(t *testing.T) {
	data := []byte(`
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`)
	s := New()
	findings, err := s.ScanBytes(data, ".github/workflows/test.yml")
	require.NoError(t, err)
	assert.True(t, hasRuleID(findings, "NXR-GH-003"))
}

func TestScanBytes_SelfHostedRunner(t *testing.T) {
	data := []byte(`
on: push
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo hello
`)
	s := New()
	findings, err := s.ScanBytes(data, ".github/workflows/test.yml")
	require.NoError(t, err)
	assert.True(t, hasRuleID(findings, "NXR-GH-005"))
}

func TestScanBytes_InvalidYAML_NoError(t *testing.T) {
	s := New()
	findings, err := s.ScanBytes([]byte("{{{{invalid"), ".github/workflows/test.yml")
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func hasRuleID(findings []finding.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}
