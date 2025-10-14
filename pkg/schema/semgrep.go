package schema

// SemgrepOutput represents the JSON output structure from Semgrep.
type SemgrepOutput struct {
	Results []SemgrepResult `json:"results"`
	Errors  []SemgrepError  `json:"errors"`
}

// SemgrepResult represents a single finding from Semgrep.
type SemgrepResult struct {
	CheckID  string          `json:"check_id"` // Rule ID
	Path     string          `json:"path"`     // File path
	Start    SemgrepLocation `json:"start"`    // Start location
	End      SemgrepLocation `json:"end"`      // End location
	Extra    SemgrepExtra    `json:"extra"`    // Additional metadata
	Message  string          `json:"message"`  // Rule message
	Severity string          `json:"severity"` // WARNING, ERROR, INFO
}

// SemgrepLocation represents a position in the source code.
type SemgrepLocation struct {
	Line   int `json:"line"`   // Line number (1-indexed)
	Col    int `json:"col"`    // Column number (1-indexed)
	Offset int `json:"offset"` // Byte offset
}

// SemgrepExtra contains additional metadata from Semgrep rules.
type SemgrepExtra struct {
	Message  string         `json:"message"`  // Human-readable message
	Metadata map[string]any `json:"metadata"` // Rule metadata
	Severity string         `json:"severity"` // Severity level
	Lines    string         `json:"lines"`    // Matched code snippet
}

// SemgrepError represents an error from Semgrep execution.
type SemgrepError struct {
	Type    string `json:"type"`    // Error type
	Level   string `json:"level"`   // Error level
	Message string `json:"message"` // Error message
	Path    string `json:"path"`    // File path (if applicable)
}
