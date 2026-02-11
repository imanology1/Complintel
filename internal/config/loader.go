package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load reads and validates a config.yaml file from the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}

	cfg := &Config{
		PacksDir:    "./packs",
		Concurrency: 4,
		Timeout:     "60s",
		Output: OutputConfig{
			Format: "table",
			Target: "stdout",
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, formatYAMLError(path, err)
	}

	if err := validate(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func validate(cfg *Config) error {
	if len(cfg.Checks) == 0 {
		return fmt.Errorf("config error: no checks defined — add at least one entry under 'checks'")
	}

	validFormats := map[string]bool{"json": true, "table": true, "csv": true}
	if !validFormats[cfg.Output.Format] {
		return fmt.Errorf("config error: invalid output format %q — must be one of: json, table, csv", cfg.Output.Format)
	}

	validTargets := map[string]bool{"stdout": true, "file": true}
	if !validTargets[cfg.Output.Target] {
		return fmt.Errorf("config error: invalid output target %q — must be one of: stdout, file", cfg.Output.Target)
	}

	if cfg.Output.Target == "file" && cfg.Output.Path == "" {
		return fmt.Errorf("config error: output target is 'file' but no 'path' specified")
	}

	if cfg.Concurrency < 1 {
		return fmt.Errorf("config error: concurrency must be at least 1, got %d", cfg.Concurrency)
	}

	for i, chk := range cfg.Checks {
		if chk.Pack == "" {
			return fmt.Errorf("config error: check #%d is missing the 'pack' field", i+1)
		}
		if chk.Check == "" {
			return fmt.Errorf("config error: check #%d is missing the 'check' field", i+1)
		}
	}

	return nil
}

func formatYAMLError(path string, err error) error {
	msg := err.Error()
	// Try to extract line number from yaml error for a friendlier message
	if strings.Contains(msg, "line") {
		return fmt.Errorf("syntax error in %s: %s", path, msg)
	}
	return fmt.Errorf("failed to parse %s: %s", path, msg)
}
