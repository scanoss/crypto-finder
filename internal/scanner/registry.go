package scanner

import (
	"fmt"
	"sort"
	"sync"
)

// Registry manages available scanners and provides a factory for retrieving
// scanner instances by name.
//
// The registry is thread-safe and allows dynamic registration of scanners.
// For MVP, we register the Semgrep adapter. Future versions will add
// OpenGrep and CBOM toolkit adapters.
type Registry struct {
	mu       sync.RWMutex
	scanners map[string]Scanner
}

// NewRegistry creates a new scanner registry.
func NewRegistry() *Registry {
	return &Registry{
		scanners: make(map[string]Scanner),
	}
}

// Register adds a scanner to the registry with the given name.
// If a scanner with the same name already exists, it will be replaced.
//
// Example:
//
//	registry := NewRegistry()
//	registry.Register("semgrep", semgrep.NewSemgrepScanner())
func (r *Registry) Register(name string, scanner Scanner) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scanners[name] = scanner
}

// Get retrieves a scanner by name.
// Returns an error if the scanner is not found.
//
// Example:
//
//	scanner, err := registry.Get("semgrep")
//	if err != nil {
//	    log.Fatal(err)
//	}
func (r *Registry) Get(name string) (Scanner, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	scanner, exists := r.scanners[name]
	if !exists {
		return nil, fmt.Errorf("scanner '%s' not found (available scanners: %v)", name, r.available())
	}

	return scanner, nil
}

// Available returns a sorted list of all registered scanner names.
//
// Example:
//
//	available := registry.Available()
//	// ["semgrep", "opengrep", "cbom-toolkit"]
func (r *Registry) Available() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.available()
}

// available is an internal helper that returns available scanner names.
// Caller must hold read lock.
func (r *Registry) available() []string {
	names := make([]string, 0, len(r.scanners))
	for name := range r.scanners {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Has checks if a scanner with the given name is registered.
func (r *Registry) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.scanners[name]
	return exists
}
