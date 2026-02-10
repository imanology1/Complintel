package discovery

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LoadPacks scans a directory for agent packs. Each subdirectory containing
// a pack.yaml manifest is loaded and validated.
func LoadPacks(packsDir string) (map[string]*Pack, []string, error) {
	packs := make(map[string]*Pack)
	var warnings []string

	entries, err := os.ReadDir(packsDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read packs directory %q: %w", packsDir, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		packDir := filepath.Join(packsDir, entry.Name())
		manifestPath := filepath.Join(packDir, "pack.yaml")

		if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("skipping %q: no pack.yaml found", entry.Name()))
			continue
		}

		pack, err := loadPack(packDir, manifestPath)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("WARNING: %s pack is malformed and will be disabled. Reason: %s", entry.Name(), err))
			continue
		}

		packs[pack.Name] = pack
	}

	if len(packs) == 0 {
		return nil, warnings, fmt.Errorf("no valid agent packs found in %q", packsDir)
	}

	return packs, warnings, nil
}

func loadPack(dir, manifestPath string) (*Pack, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read pack.yaml: %w", err)
	}

	var pack Pack
	if err := yaml.Unmarshal(data, &pack); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}

	pack.Dir = dir

	if pack.Name == "" {
		return nil, fmt.Errorf("'name' key is missing")
	}
	if pack.Version == "" {
		return nil, fmt.Errorf("'version' key is missing")
	}

	for i, chk := range pack.Checks {
		if chk.ID == "" {
			return nil, fmt.Errorf("check #%d is missing 'id' key", i+1)
		}
		if chk.Script == "" {
			return nil, fmt.Errorf("'script' key missing for check %q", chk.ID)
		}

		scriptPath := filepath.Join(dir, "scripts", chk.Script)
		if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("script %q for check %q not found", chk.Script, chk.ID)
		}
	}

	return &pack, nil
}

// FindCheck looks up a specific check within a pack by ID.
func FindCheck(pack *Pack, checkID string) (*Check, error) {
	for i := range pack.Checks {
		if pack.Checks[i].ID == checkID {
			return &pack.Checks[i], nil
		}
	}
	return nil, fmt.Errorf("check %q not found in pack %q", checkID, pack.Name)
}
