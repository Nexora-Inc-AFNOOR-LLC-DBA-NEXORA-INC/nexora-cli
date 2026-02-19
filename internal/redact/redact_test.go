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
		{"-----BEGIN RSA PRIVATE KEY-----", "[REDACTED:PEM_PRIVATE_KEY]"},
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

func repeat(s string, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = s[0]
	}
	return string(out)
}
