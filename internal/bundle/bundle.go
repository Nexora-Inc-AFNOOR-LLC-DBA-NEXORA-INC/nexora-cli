package bundle

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/finding"
	"github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/output"
)

type FileEntry struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512"`
}

type Manifest struct {
	ScanID           string      `json:"scan_id"`
	ScanTimestampUTC string      `json:"scan_timestamp_utc"`
	Files            []FileEntry `json:"files"`
	FilesRootHash    string      `json:"files_root_hash"`
}

type ScanMetadata struct {
	ScanID           string `json:"scan_id"`
	ScanTimestampUTC string `json:"scan_timestamp_utc"`
	Version          string `json:"version"`
	TotalFindings    int    `json:"total_findings"`
}

func Write(dir, scanID, version string, findings []finding.Finding) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create bundle dir: %w", err)
	}

	if scanID == "" {
		scanID = uuid.New().String()
	}
	now := time.Now().UTC().Format(time.RFC3339)

	files := map[string]func() error{
		"findings.json": func() error {
			f, err := os.Create(filepath.Join(dir, "findings.json"))
			if err != nil {
				return err
			}
			defer f.Close()
			return output.WriteJSON(f, scanID, version, findings)
		},
		"findings.sarif": func() error {
			f, err := os.Create(filepath.Join(dir, "findings.sarif"))
			if err != nil {
				return err
			}
			defer f.Close()
			return output.WriteSARIF(f, version, findings)
		},
		"findings.ocsf.jsonl": func() error {
			f, err := os.Create(filepath.Join(dir, "findings.ocsf.jsonl"))
			if err != nil {
				return err
			}
			defer f.Close()
			return output.WriteOCSF(f, version, findings)
		},
		"scan-metadata.json": func() error {
			meta := ScanMetadata{
				ScanID:           scanID,
				ScanTimestampUTC: now,
				Version:          version,
				TotalFindings:    len(findings),
			}
			f, err := os.Create(filepath.Join(dir, "scan-metadata.json"))
			if err != nil {
				return err
			}
			defer f.Close()
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			return enc.Encode(meta)
		},
	}

	orderedNames := []string{"findings.json", "findings.sarif", "findings.ocsf.jsonl", "scan-metadata.json"}
	for _, name := range orderedNames {
		if err := files[name](); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}

	entries, err := computeFileEntries(dir, orderedNames)
	if err != nil {
		return fmt.Errorf("compute checksums: %w", err)
	}

	rootHash, err := computeRootHash(entries)
	if err != nil {
		return fmt.Errorf("compute root hash: %w", err)
	}

	manifest := Manifest{
		ScanID:           scanID,
		ScanTimestampUTC: now,
		Files:            entries,
		FilesRootHash:    rootHash,
	}

	mf, err := os.Create(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return fmt.Errorf("create manifest.json: %w", err)
	}
	defer mf.Close()

	enc := json.NewEncoder(mf)
	enc.SetIndent("", "  ")
	return enc.Encode(manifest)
}

func computeFileEntries(dir string, names []string) ([]FileEntry, error) {
	entries := make([]FileEntry, 0, len(names))
	for _, name := range names {
		path := filepath.Join(dir, name)
		s256, s512, err := hashFile(path)
		if err != nil {
			return nil, fmt.Errorf("hash %s: %w", name, err)
		}
		entries = append(entries, FileEntry{
			Name:   name,
			SHA256: s256,
			SHA512: s512,
		})
	}
	return entries, nil
}

func hashFile(path string) (sha256sum, sha512sum string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	h256 := sha256.New()
	h512 := sha512.New()
	mw := io.MultiWriter(h256, h512)

	if _, err := io.Copy(mw, f); err != nil {
		return "", "", err
	}
	return fmt.Sprintf("%x", h256.Sum(nil)), fmt.Sprintf("%x", h512.Sum(nil)), nil
}

func computeRootHash(entries []FileEntry) (string, error) {
	sorted := make([]FileEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Name < sorted[j].Name
	})

	data, err := json.Marshal(sorted)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:]), nil
}
