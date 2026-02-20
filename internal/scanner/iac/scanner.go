package iac

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/finding"
)

const maxFileSize = 10 * 1024 * 1024

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
		if !isIaCFile(path) {
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
	type ruleFunc func([]byte, string) ([]finding.Finding, error)
	rules := []ruleFunc{
		CheckIAMWildcardAction,
		CheckHardcodedCredentials,
		CheckIAMTrustPolicyTooBroad,
		CheckResourceWildcardWithBroadActions,
	}

	var all []finding.Finding
	for _, rule := range rules {
		findings, err := rule(data, filePath)
		if err != nil {
			log.Warn().Err(err).Str("file", filePath).Msg("rule error")
			continue
		}
		all = append(all, findings...)
	}
	return all, nil
}

func isIaCFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".tf" || ext == ".json" || ext == ".yaml" || ext == ".yml"
}
