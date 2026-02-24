package k8s

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"

	"github.com/Nexora-NHI/nexora-cli/internal/finding"
)

const (
	maxFileSize   = 10 * 1024 * 1024
	maxDepth      = 200
	maxNodesTotal = 200_000
)

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) ScanPath(root string) ([]finding.Finding, error) {
	var all []finding.Finding
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			log.Warn().Err(err).Str("path", path).Msg("walk error")
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !isManifestFile(path) {
			return nil
		}
		findings, scanErr := s.ScanFile(path)
		if scanErr != nil {
			log.Warn().Err(scanErr).Str("file", path).Msg("scan error")
			return nil
		}
		all = append(all, findings...)
		return nil
	})
	return all, err
}

func (s *Scanner) ScanFile(filePath string) ([]finding.Finding, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", filePath, err)
	}
	if info.Size() > maxFileSize {
		log.Warn().Str("file", filePath).Int64("size", info.Size()).Msg("file exceeds max size, skipping")
		return nil, nil
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filePath, err)
	}
	return s.ScanBytes(data, filePath)
}

func (s *Scanner) ScanBytes(data []byte, filePath string) ([]finding.Finding, error) {
	var all []finding.Finding
	dec := yaml.NewDecoder(bytes.NewReader(data))

	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			if err == io.EOF {
				break
			}
			log.Warn().Err(err).Str("file", filePath).Msg("yaml parse error, skipping")
			return nil, nil
		}
		if !checkNodeLimits(&doc) {
			log.Warn().Str("file", filePath).Msg("yaml node limits exceeded, skipping")
			return nil, nil
		}
		findings, err := runAllRules(&doc, filePath)
		if err != nil {
			log.Warn().Err(err).Str("file", filePath).Msg("rule error")
		}
		all = append(all, findings...)
	}
	return all, nil
}

func runAllRules(doc *yaml.Node, filePath string) ([]finding.Finding, error) {
	type ruleFunc func(*yaml.Node, string) ([]finding.Finding, error)
	rules := []ruleFunc{
		CheckClusterAdminBinding,
		CheckAutomountServiceAccountToken,
		CheckDefaultServiceAccount,
		CheckWildcardRBACVerbs,
		CheckProjectedTokenExpiry,
	}
	var all []finding.Finding
	for _, rule := range rules {
		findings, err := rule(doc, filePath)
		if err != nil {
			return all, err
		}
		all = append(all, findings...)
	}
	return all, nil
}

func isManifestFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}

func checkNodeLimits(node *yaml.Node) bool {
	count := 0
	return checkNodeLimitsRecursive(node, 0, &count)
}

func checkNodeLimitsRecursive(node *yaml.Node, depth int, count *int) bool {
	if node == nil {
		return true
	}
	*count++
	if depth > maxDepth || *count > maxNodesTotal {
		return false
	}
	for _, child := range node.Content {
		if !checkNodeLimitsRecursive(child, depth+1, count) {
			return false
		}
	}
	return true
}
