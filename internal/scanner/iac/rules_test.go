package iac

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckIAMWildcardAction_WildcardStar(t *testing.T) {
	data := []byte(`"Action": "*"`)
	findings, err := CheckIAMWildcardAction(data, "policy.json")
	require.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Equal(t, "NXR-IAC-001", findings[0].RuleID)
}

func TestCheckIAMWildcardAction_ServiceWildcard(t *testing.T) {
	data := []byte(`actions = ["iam:*"]`)
	findings, err := CheckIAMWildcardAction(data, "main.tf")
	require.NoError(t, err)
	assert.True(t, len(findings) > 0)
}

func TestCheckIAMWildcardAction_ExplicitActions_NoFinding(t *testing.T) {
	data := []byte(`"Action": ["s3:GetObject", "s3:PutObject"]`)
	findings, err := CheckIAMWildcardAction(data, "policy.json")
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCheckHardcodedCredentials_AccessKey(t *testing.T) {
	data := []byte(`access_key = "AKIAIOSFODNN7EXAMPLE"`)
	findings, err := CheckHardcodedCredentials(data, "main.tf")
	require.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Equal(t, "NXR-IAC-002", findings[0].RuleID)
}

func TestCheckHardcodedCredentials_SecretKey(t *testing.T) {
	data := []byte(`aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`)
	findings, err := CheckHardcodedCredentials(data, "main.tf")
	require.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Equal(t, "NXR-IAC-002", findings[0].RuleID)
}

func TestCheckIAMTrustPolicyTooBroad_WildcardPrincipal(t *testing.T) {
	data := []byte(`"Principal": "*"`)
	findings, err := CheckIAMTrustPolicyTooBroad(data, "trust.json")
	require.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Equal(t, "NXR-IAC-003", findings[0].RuleID)
}

func TestCheckIAMTrustPolicyTooBroad_SpecificPrincipal_NoFinding(t *testing.T) {
	data := []byte(`"Principal": {"AWS": "arn:aws:iam::123456789012:role/MyRole"}`)
	findings, err := CheckIAMTrustPolicyTooBroad(data, "trust.json")
	require.NoError(t, err)
	assert.Empty(t, findings)
}
