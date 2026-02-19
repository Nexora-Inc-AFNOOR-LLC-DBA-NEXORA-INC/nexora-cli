package iac

import (
	"testing"

	"github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hasRuleID(findings []finding.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func TestScanBytes_WildcardAction_TF(t *testing.T) {
	data := []byte(`
resource "aws_iam_role_policy" "bad" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
`)
	s := New()
	findings, err := s.ScanBytes(data, "main.tf")
	require.NoError(t, err)
	assert.True(t, hasRuleID(findings, "NXR-IAC-001"))
}

func TestScanBytes_HardcodedAccessKey(t *testing.T) {
	data := []byte(`
resource "aws_iam_access_key" "bad" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
}
`)
	s := New()
	findings, err := s.ScanBytes(data, "main.tf")
	require.NoError(t, err)
	assert.True(t, hasRuleID(findings, "NXR-IAC-002"))
}

func TestScanBytes_WildcardPrincipal(t *testing.T) {
	data := []byte(`{
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "sts:AssumeRole"
  }]
}`)
	s := New()
	findings, err := s.ScanBytes(data, "trust.json")
	require.NoError(t, err)
	assert.True(t, hasRuleID(findings, "NXR-IAC-003"))
}
