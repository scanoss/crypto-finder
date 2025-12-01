package entities

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
	Message  string                 `json:"message"`  // Human-readable message
	Metadata SemgrepMetadata        `json:"metadata"` // Rule metadata
	Metavars map[string]MetavarInfo `json:"metavars"` // Metavariables
	Severity string                 `json:"severity"` // Severity level
	Lines    string                 `json:"lines"`    // Matched code snippet
}

// SemgrepMetadata contains metadata from Semgrep rules.
type SemgrepMetadata struct {
	Category       string         `json:"category,omitempty"`
	Subcategory    string         `json:"subcategory,omitempty"`
	Confidence     string         `json:"confidence,omitempty"`
	Likelihood     string         `json:"likelihood,omitempty"`
	Impact         string         `json:"impact,omitempty"`
	CWE            any            `json:"cwe,omitempty"`
	Crypto         map[string]any `json:"crypto,omitempty"`
	Owasp          []string       `json:"owasp,omitempty"`
	References     []string       `json:"references,omitempty"`
	Recommendation string         `json:"recommendation,omitempty"`
}

// MetavarInfo holds information about a captured metavariables.
type MetavarInfo struct {
	Start struct {
		Line   int `json:"line"`
		Col    int `json:"col"`
		Offset int `json:"offset"`
	} `json:"start"`
	End struct {
		Line   int `json:"line"`
		Col    int `json:"col"`
		Offset int `json:"offset"`
	} `json:"end"`
	AbstractContent string                  `json:"abstract_content"`
	PropagatedValue *MetavarPropagatedValue `json:"propagated_value"`
}

// MetavarPropagatedValue contains propagated values for metavariables.
type MetavarPropagatedValue struct {
	SvalueStart struct {
		Line   int `json:"line"`
		Col    int `json:"col"`
		Offset int `json:"offset"`
	} `json:"svalue_start"`
	SvalueEnd struct {
		Line   int `json:"line"`
		Col    int `json:"col"`
		Offset int `json:"offset"`
	} `json:"svalue_end"`
	SvalueAbstractContent string `json:"svalue_abstract_content"`
}

// SemgrepError represents an error from Semgrep execution.
type SemgrepError struct {
	Code    int                `json:"code,omitempty"`  // Error code
	Type    any                `json:"type"`            // Error type (string or [string, locations])
	Level   string             `json:"level"`           // Error level
	Message string             `json:"message"`         // Error message
	Path    string             `json:"path"`            // File path (if applicable)
	Spans   []SemgrepErrorSpan `json:"spans,omitempty"` // Error spans
}

// SemgrepErrorSpan represents a location span in a Semgrep error.
type SemgrepErrorSpan struct {
	File  string          `json:"file"`
	Start SemgrepLocation `json:"start"`
	End   SemgrepLocation `json:"end"`
}
