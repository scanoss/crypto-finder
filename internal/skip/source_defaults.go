package skip

var DefaultSkippedDirs = []string{
	"nbproject",
	"nbbuild",
	"nbdist",
	"__pycache__",
	"venv",
	"_yardoc",
	"eggs",
	"wheels",
	"htmlcov",
	"__pypackages__",
	"example",
	"examples",
	"docs",
	"doc",
	"node_modules",
	"dist",
	"build",
	"target",
	"vendor",
}

// DefaultsSource provides the built-in default skip patterns.
// These patterns represent commonly excluded directories across projects.
type DefaultsSource struct{}

// NewDefaultsSource creates a new source that returns the built-in default patterns.
//
// Returns:
//   - *DefaultsSource: Source providing default skip patterns
func NewDefaultsSource() *DefaultsSource {
	return &DefaultsSource{}
}

// Load returns the default excluded directory patterns.
// This source never fails - it always returns the built-in defaults.
//
// Returns:
//   - []string: Default skip patterns
//   - error: Always nil (included for interface compatibility)
func (d *DefaultsSource) Load() ([]string, error) {
	return DefaultSkippedDirs, nil
}

// Name returns a descriptive name for this pattern source.
func (d *DefaultsSource) Name() string {
	return "defaults"
}
