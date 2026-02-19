package github

import (
	"testing"

	"github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func parseDoc(t *testing.T, src string) *yaml.Node {
	t.Helper()
	var doc yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(src), &doc))
	return &doc
}

func hasRule(findings []finding.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func TestCheckBroadPermissions_WriteAll(t *testing.T) {
	doc := parseDoc(t, `
on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`)
	findings, err := CheckBroadPermissions(doc, "test.yml")
	require.NoError(t, err)
	assert.True(t, hasRule(findings, "NXR-GH-001"))
}

func TestCheckBroadPermissions_JobScoped_NoFinding(t *testing.T) {
	doc := parseDoc(t, `
on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - run: echo hi
`)
	findings, err := CheckBroadPermissions(doc, "test.yml")
	require.NoError(t, err)
	assert.False(t, hasRule(findings, "NXR-GH-001"))
}

func TestCheckUnpinnedActions_Unpinned(t *testing.T) {
	doc := parseDoc(t, `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`)
	findings, err := CheckUnpinnedActions(doc, "test.yml")
	require.NoError(t, err)
	assert.True(t, hasRule(findings, "NXR-GH-002"))
}

func TestCheckUnpinnedActions_Pinned_NoFinding(t *testing.T) {
	doc := parseDoc(t, `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
`)
	findings, err := CheckUnpinnedActions(doc, "test.yml")
	require.NoError(t, err)
	assert.False(t, hasRule(findings, "NXR-GH-002"))
}

func TestCheckUnpinnedActions_Local_NoFinding(t *testing.T) {
	doc := parseDoc(t, `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./local-action
`)
	findings, err := CheckUnpinnedActions(doc, "test.yml")
	require.NoError(t, err)
	assert.False(t, hasRule(findings, "NXR-GH-002"))
}

func TestCheckPRTMisuse_HeadCheckout(t *testing.T) {
	doc := parseDoc(t, `
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
	findings, err := CheckPRTMisuse(doc, "test.yml")
	require.NoError(t, err)
	assert.True(t, hasRule(findings, "NXR-GH-003"))
}

func TestCheckSelfHostedRunner(t *testing.T) {
	doc := parseDoc(t, `
on: push
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo hi
`)
	findings, err := CheckSelfHostedRunner(doc, "test.yml")
	require.NoError(t, err)
	assert.True(t, hasRule(findings, "NXR-GH-005"))
}

func TestCheckSelfHostedRunner_WithLabels_NoFinding(t *testing.T) {
	doc := parseDoc(t, `
on: push
jobs:
  build:
    runs-on: [self-hosted, linux, x64]
    steps:
      - run: echo hi
`)
	findings, err := CheckSelfHostedRunner(doc, "test.yml")
	require.NoError(t, err)
	assert.False(t, hasRule(findings, "NXR-GH-005"))
}

func TestCheckScheduledWritePermissions(t *testing.T) {
	doc := parseDoc(t, `
on:
  schedule:
    - cron: '0 0 * * *'
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`)
	findings, err := CheckScheduledWritePermissions(doc, "test.yml")
	require.NoError(t, err)
	assert.True(t, hasRule(findings, "NXR-GH-008"))
}
