package k8s

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

func TestScanBytes_ClusterAdmin(t *testing.T) {
	data := []byte(`
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bad-binding
subjects:
  - kind: ServiceAccount
    name: my-sa
    namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
`)
	s := New()
	findings, err := s.ScanBytes(data, "crb.yaml")
	require.NoError(t, err)
	assert.True(t, hasRuleID(findings, "NXR-K8S-001"))
}

func TestScanBytes_WildcardRBAC(t *testing.T) {
	data := []byte(`
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: bad-role
rules:
  - verbs: ["*"]
    resources: ["secrets"]
    apiGroups: [""]
`)
	s := New()
	findings, err := s.ScanBytes(data, "role.yaml")
	require.NoError(t, err)
	assert.True(t, hasRuleID(findings, "NXR-K8S-004"))
}

func TestScanBytes_MultiDoc(t *testing.T) {
	data := []byte(`
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bad
subjects:
  - kind: ServiceAccount
    name: sa
    namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sa
  namespace: default
`)
	s := New()
	findings, err := s.ScanBytes(data, "multi.yaml")
	require.NoError(t, err)
	assert.True(t, hasRuleID(findings, "NXR-K8S-001"))
}

func TestScanBytes_InvalidYAML_NoError(t *testing.T) {
	s := New()
	findings, err := s.ScanBytes([]byte("{{{{invalid"), "bad.yaml")
	require.NoError(t, err)
	assert.Empty(t, findings)
}
