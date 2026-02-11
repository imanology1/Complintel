package config

import "time"

// Config is the top-level user configuration loaded from config.yaml.
type Config struct {
	PacksDir    string            `yaml:"packs_dir"`
	Schedule    string            `yaml:"schedule"`
	Concurrency int              `yaml:"concurrency"`
	Timeout     string            `yaml:"timeout"`
	Output      OutputConfig      `yaml:"output"`
	Credentials map[string]string `yaml:"credentials"`
	Checks      []CheckConfig     `yaml:"checks"`
}

// OutputConfig controls where results are written.
type OutputConfig struct {
	Format string `yaml:"format"` // "json", "table", "csv"
	Target string `yaml:"target"` // "stdout", "file"
	Path   string `yaml:"path"`   // file path when target is "file"
}

// CheckConfig maps a check from a pack with user-supplied parameters.
type CheckConfig struct {
	Pack   string            `yaml:"pack"`
	Check  string            `yaml:"check"`
	Params map[string]string `yaml:"params"`
}

// ParsedTimeout returns the timeout as a time.Duration.
func (c *Config) ParsedTimeout() time.Duration {
	d, err := time.ParseDuration(c.Timeout)
	if err != nil {
		return 60 * time.Second
	}
	return d
}
