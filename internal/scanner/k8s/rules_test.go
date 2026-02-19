package k8s

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

func TestCheckClusterAdminBinding(t *testing.T) {
	doc := parseDoc(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bad
subjects:
  - kind: ServiceAccount
    name: my-sa
    namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
`)
	findings, err := CheckClusterAdminBinding(doc, "test.yaml")
	require.NoError(t, err)
	assert.True(t, hasRule(findings, "NXR-K8S-001"))
}

func TestCheckClusterAdminBinding_NotClusterAdmin_NoFinding(t *testing.T) {
	doc := parseDoc(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ok
subjects:
  - kind: ServiceAccount
    name: my-sa
    namespace: default
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
`)
	findings, err := CheckClusterAdminBinding(doc, "test.yaml")
	require.NoError(t, err)
	assert.False(t, hasRule(findings, "NXR-K8S-001"))
}

func TestCheckWildcardRBACVerbs_WildcardSecrets(t *testing.T) {
	doc := parseDoc(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: bad
rules:
  - verbs: ["*"]
    resources: ["secrets"]
    apiGroups: [""]
`)
	findings, err := CheckWildcardRBACVerbs(doc, "test.yaml")
	require.NoError(t, err)
	assert.True(t, hasRule(findings, "NXR-K8S-004"))
}

func TestCheckWildcardRBACVerbs_ExplicitVerbs_NoFinding(t *testing.T) {
	doc := parseDoc(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ok
rules:
  - verbs: ["get", "list"]
    resources: ["secrets"]
    apiGroups: [""]
`)
	findings, err := CheckWildcardRBACVerbs(doc, "test.yaml")
	require.NoError(t, err)
	assert.False(t, hasRule(findings, "NXR-K8S-004"))
}

func TestCheckProjectedTokenExpiry_TooLong(t *testing.T) {
	doc := parseDoc(t, `
apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  volumes:
    - name: token
      projected:
        sources:
          - serviceAccountToken:
              expirationSeconds: 172800
              path: token
  containers:
    - name: app
      image: nginx
`)
	findings, err := CheckProjectedTokenExpiry(doc, "test.yaml")
	require.NoError(t, err)
	assert.True(t, hasRule(findings, "NXR-K8S-005"))
}

func TestCheckProjectedTokenExpiry_Short_NoFinding(t *testing.T) {
	doc := parseDoc(t, `
apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  volumes:
    - name: token
      projected:
        sources:
          - serviceAccountToken:
              expirationSeconds: 3600
              path: token
  containers:
    - name: app
      image: nginx
`)
	findings, err := CheckProjectedTokenExpiry(doc, "test.yaml")
	require.NoError(t, err)
	assert.False(t, hasRule(findings, "NXR-K8S-005"))
}
