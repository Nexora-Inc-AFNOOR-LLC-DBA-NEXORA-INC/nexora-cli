// Package integration contains fixture-level integration tests.
// Each test scans a specific fixture file and asserts the expected rule IDs
// and that clean fixtures produce zero findings.
package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/finding"
	ghscanner "github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/scanner/github"
	iacscanner "github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/scanner/iac"
	k8sscanner "github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/scanner/k8s"
)

// fixtureRoot returns the absolute path to the fixtures directory.
func fixtureRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", "fixtures"))
	require.NoError(t, err)
	_, err = os.Stat(abs)
	require.NoError(t, err, "fixtures directory must exist at %s", abs)
	return abs
}

// collectRuleIDs returns a set of rule IDs present in the findings slice.
func collectRuleIDs(findings []finding.Finding) map[string]bool {
	ids := make(map[string]bool, len(findings))
	for _, f := range findings {
		ids[f.RuleID] = true
	}
	return ids
}

// ── GitHub Actions fixtures ──────────────────────────────────────────────────

func TestFixture_GH_BadPermissions(t *testing.T) {
	root := fixtureRoot(t)
	path := filepath.Join(root, "vulnerable", ".github", "workflows", "bad_permissions.yml")
	s := ghscanner.New()
	findings, err := s.ScanFile(path)
	require.NoError(t, err)

	ids := collectRuleIDs(findings)
	assert.Contains(t, ids, "NXR-GH-001", "bad_permissions.yml must trigger NXR-GH-001")
}

func TestFixture_GH_UnpinnedAction(t *testing.T) {
	root := fixtureRoot(t)
	path := filepath.Join(root, "vulnerable", ".github", "workflows", "unpinned_action.yml")
	s := ghscanner.New()
	findings, err := s.ScanFile(path)
	require.NoError(t, err)

	ids := collectRuleIDs(findings)
	assert.Contains(t, ids, "NXR-GH-002", "unpinned_action.yml must trigger NXR-GH-002")
}

func TestFixture_GH_PRTMisuse(t *testing.T) {
	root := fixtureRoot(t)
	path := filepath.Join(root, "vulnerable", ".github", "workflows", "prt_misuse.yml")
	s := ghscanner.New()
	findings, err := s.ScanFile(path)
	require.NoError(t, err)

	ids := collectRuleIDs(findings)
	assert.Contains(t, ids, "NXR-GH-003", "prt_misuse.yml must trigger NXR-GH-003")
	assert.Contains(t, ids, "NXR-GH-006", "prt_misuse.yml must trigger NXR-GH-006")
}

func TestFixture_GH_SecretInEnv(t *testing.T) {
	root := fixtureRoot(t)
	path := filepath.Join(root, "vulnerable", ".github", "workflows", "secret_in_env.yml")
	s := ghscanner.New()
	findings, err := s.ScanFile(path)
	require.NoError(t, err)

	ids := collectRuleIDs(findings)
	assert.Contains(t, ids, "NXR-GH-004", "secret_in_env.yml must trigger NXR-GH-004")
}

func TestFixture_GH_Clean(t *testing.T) {
	root := fixtureRoot(t)
	path := filepath.Join(root, "clean", ".github", "workflows", "good_workflow.yml")
	s := ghscanner.New()
	findings, err := s.ScanFile(path)
	require.NoError(t, err)
	assert.Empty(t, findings, "good_workflow.yml must produce zero findings")
}

// ── Kubernetes fixtures ──────────────────────────────────────────────────────

func TestFixture_K8S_ClusterAdminSA(t *testing.T) {
	root := fixtureRoot(t)
	path := filepath.Join(root, "vulnerable", "k8s", "cluster_admin_sa.yaml")
	s := k8sscanner.New()
	findings, err := s.ScanFile(path)
	require.NoError(t, err)

	ids := collectRuleIDs(findings)
	assert.Contains(t, ids, "NXR-K8S-001", "cluster_admin_sa.yaml must trigger NXR-K8S-001")
}

func TestFixture_K8S_AutomountSA(t *testing.T) {
	root := fixtureRoot(t)
	path := filepath.Join(root, "vulnerable", "k8s", "automount_sa.yaml")
	s := k8sscanner.New()
	findings, err := s.ScanFile(path)
	require.NoError(t, err)

	ids := collectRuleIDs(findings)
	assert.Contains(t, ids, "NXR-K8S-002", "automount_sa.yaml must trigger NXR-K8S-002")
}

func TestFixture_K8S_DefaultSA(t *testing.T) {
	root := fixtureRoot(t)
	path := filepath.Join(root, "vulnerable", "k8s", "default_sa.yaml")
	s := k8sscanner.New()
	findings, err := s.ScanFile(path)
	require.NoError(t, err)

	ids := collectRuleIDs(findings)
	assert.Contains(t, ids, "NXR-K8S-004", "default_sa.yaml must trigger NXR-K8S-004")
}

func TestFixture_K8S_Clean(t *testing.T) {
	root := fixtureRoot(t)
	path := filepath.Join(root, "clean", "k8s", "good_manifests.yaml")
	s := k8sscanner.New()
	findings, err := s.ScanFile(path)
	require.NoError(t, err)
	assert.Empty(t, findings, "good_manifests.yaml must produce zero findings")
}

// ── IaC fixtures ─────────────────────────────────────────────────────────────

func TestFixture_IAC_WildcardIAM(t *testing.T) {
	root := fixtureRoot(t)
	path := filepath.Join(root, "vulnerable", "terraform", "wildcard_iam.tf")
	s := iacscanner.New()
	findings, err := s.ScanFile(path)
	require.NoError(t, err)

	ids := collectRuleIDs(findings)
	assert.Contains(t, ids, "NXR-IAC-001", "wildcard_iam.tf must trigger NXR-IAC-001")
}

func TestFixture_IAC_HardcodedKey(t *testing.T) {
	root := fixtureRoot(t)
	path := filepath.Join(root, "vulnerable", "terraform", "hardcoded_key.tf")
	s := iacscanner.New()
	findings, err := s.ScanFile(path)
	require.NoError(t, err)

	ids := collectRuleIDs(findings)
	assert.Contains(t, ids, "NXR-IAC-002", "hardcoded_key.tf must trigger NXR-IAC-002")
}

func TestFixture_IAC_Clean(t *testing.T) {
	root := fixtureRoot(t)
	path := filepath.Join(root, "clean", "terraform", "good_iam.tf")
	s := iacscanner.New()
	findings, err := s.ScanFile(path)
	require.NoError(t, err)
	assert.Empty(t, findings, "good_iam.tf must produce zero findings")
}
