package discovery

// Pack represents a loaded agent pack with its metadata and checks.
type Pack struct {
	Name        string  `yaml:"name"`
	Version     string  `yaml:"version"`
	Description string  `yaml:"description"`
	Checks      []Check `yaml:"checks"`
	Dir         string  `yaml:"-"` // filesystem path to the pack directory
}

// Check describes a single compliance check within a pack.
type Check struct {
	ID          string   `yaml:"id"`
	Description string   `yaml:"description"`
	Script      string   `yaml:"script"`
	Severity    string   `yaml:"severity"`
	Frameworks  []string `yaml:"frameworks"`
	Params      []Param  `yaml:"params"`
}

// Param describes a parameter that a check script accepts.
type Param struct {
	Name     string `yaml:"name"`
	Required bool   `yaml:"required"`
	Default  string `yaml:"default"`
}
