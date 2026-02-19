package bundle

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type VerifyResult struct {
	File   string
	Passed bool
	Reason string
}

func Verify(dir string) ([]VerifyResult, error) {
	manifestPath := filepath.Join(dir, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read manifest.json: %w", err)
	}

	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest.json: %w", err)
	}

	results := make([]VerifyResult, 0, len(manifest.Files)+1)

	for _, entry := range manifest.Files {
		path := filepath.Join(dir, entry.Name)
		actual256, actual512, err := hashFile(path)
		if err != nil {
			results = append(results, VerifyResult{
				File:   entry.Name,
				Passed: false,
				Reason: fmt.Sprintf("cannot hash file: %v", err),
			})
			continue
		}

		if actual256 != entry.SHA256 {
			results = append(results, VerifyResult{
				File:   entry.Name,
				Passed: false,
				Reason: fmt.Sprintf("sha256 mismatch: expected %s got %s", entry.SHA256, actual256),
			})
			continue
		}

		if actual512 != entry.SHA512 {
			results = append(results, VerifyResult{
				File:   entry.Name,
				Passed: false,
				Reason: fmt.Sprintf("sha512 mismatch: expected %s got %s", entry.SHA512, actual512),
			})
			continue
		}

		results = append(results, VerifyResult{
			File:   entry.Name,
			Passed: true,
		})
	}

	actualRootHash, err := computeRootHash(manifest.Files)
	if err != nil {
		return results, fmt.Errorf("recompute root hash: %w", err)
	}

	if actualRootHash != manifest.FilesRootHash {
		results = append(results, VerifyResult{
			File:   "manifest.json (root hash)",
			Passed: false,
			Reason: fmt.Sprintf("files_root_hash mismatch: expected %s got %s", manifest.FilesRootHash, actualRootHash),
		})
	} else {
		results = append(results, VerifyResult{
			File:   "manifest.json (root hash)",
			Passed: true,
		})
	}

	return results, nil
}
