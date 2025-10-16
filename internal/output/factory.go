// Package output handles formatting and writing scan results to various output formats.
package output

import (
	"fmt"
	"sort"
)

// WriterFactory provides a registry of output format writers.
// It enables dynamic selection of output formats based on user input.
//
// Example usage:
//
//	factory := output.NewWriterFactory()
//	writer, err := factory.GetWriter("json")
//	if err != nil {
//	    return err
//	}
//	writer.Write(report, "/path/to/output.json")
type WriterFactory struct {
	writers map[string]Writer
}

// NewWriterFactory creates a factory with all supported output format writers registered.
//
// Currently supported formats:
//   - json: Standard JSON output (pretty-printed by default)
func NewWriterFactory() *WriterFactory {
	return &WriterFactory{
		writers: map[string]Writer{
			"json": NewJSONWriter(),
		},
	}
}

// GetWriter returns the writer implementation for the specified format.
//
// Parameters:
//   - format: The output format name (e.g., "json", "csv", "html")
//
// Returns:
//   - Writer implementation for the format
//   - Error if format is not supported
func (f *WriterFactory) GetWriter(format string) (Writer, error) {
	writer, ok := f.writers[format]
	if !ok {
		return nil, fmt.Errorf("unsupported output format '%s' (supported: %v)", format, f.SupportedFormats())
	}
	return writer, nil
}

// SupportedFormats returns a sorted list of all supported output format names.
func (f *WriterFactory) SupportedFormats() []string {
	formats := make([]string, 0, len(f.writers))
	for format := range f.writers {
		formats = append(formats, format)
	}
	sort.Strings(formats)
	return formats
}
