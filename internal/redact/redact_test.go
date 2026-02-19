package redact

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedactGHTokens(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"token: ghp_" + repeat("A", 36), "token: [REDACTED:GH_TOKEN_CLASSIC]"},
		{"token: gho_" + repeat("A", 36), "token: [REDACTED:GH_TOKEN_OAUTH]"},
		{"token: ghs_" + repeat("A", 36), "token: [REDACTED:GH_TOKEN_SERVER]"},
		{"token: ghr_" + repeat("A", 36), "token: [REDACTED:GH_TOKEN_REFRESH]"},
		{"key: AKIAIOSFODNN7EXAMPLE", "key: [REDACTED:AWS_ACCESS_KEY_ID]"},
		{"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----", "[REDACTED:PEM_PRIVATE_KEY]"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, String(tc.input))
	}
}

func TestNoRedactionOnSafeStrings(t *testing.T) {
	safe := "permissions: contents: read"
	assert.Equal(t, safe, String(safe))
}

func TestHasSecret(t *testing.T) {
	assert.True(t, HasSecret("AKIAIOSFODNN7EXAMPLE"))
	assert.False(t, HasSecret("no secrets here"))
}

func TestRedactAWSSecretKey(t *testing.T) {
	input := `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`
	out := String(input)
	assert.Contains(t, out, "[REDACTED:AWS_SECRET_KEY]")
	assert.Contains(t, out, "aws_secret_access_key")
	assert.NotContains(t, out, "wJalrXUtnFEMI/K7MDENG")
}

func TestRedactFinegrainedPAT(t *testing.T) {
	pat := "github_pat_" + repeat("A", 82)
	out := String("token: " + pat)
	assert.Contains(t, out, "[REDACTED:GH_FINE_GRAINED_PAT]")
	assert.NotContains(t, out, pat)
}

func TestRedactBytes(t *testing.T) {
	input := []byte("key: AKIAIOSFODNN7EXAMPLE")
	out := Bytes(input)
	assert.Contains(t, string(out), "[REDACTED:AWS_ACCESS_KEY_ID]")
}

func TestHasSecret_PEM(t *testing.T) {
	assert.True(t, HasSecret("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"))
}

func TestHasSecret_GHToken(t *testing.T) {
	assert.True(t, HasSecret("ghp_"+repeat("Z", 36)))
}

func repeat(s string, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = s[0]
	}
	return string(out)
}
