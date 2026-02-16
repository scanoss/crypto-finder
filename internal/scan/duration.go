package scan

import (
	"fmt"
	"strings"
	"time"
)

// ParseDuration parses a duration string supporting standard Go formats plus:
// - "d" for days (e.g., "30d" = 720 hours)
// - "w" for weeks (e.g., "2w" = 336 hours)
//
// Standard formats (ns, us, ms, s, m, h) are parsed by time.ParseDuration.
func ParseDuration(s string) (time.Duration, error) {
	// Try standard parsing first (supports: ns, us, ms, s, m, h)
	d, err := time.ParseDuration(s)
	if err == nil {
		return d, nil
	}

	// Check for "d" (days) suffix
	if strings.HasSuffix(s, "d") {
		days := strings.TrimSuffix(s, "d")
		var value float64
		n, parseErr := fmt.Sscanf(days, "%f", &value)
		if parseErr != nil || n != 1 {
			return 0, fmt.Errorf("invalid duration format: %s", s)
		}
		return time.Duration(value*24) * time.Hour, nil
	}

	// Check for "w" (weeks) suffix
	if strings.HasSuffix(s, "w") {
		weeks := strings.TrimSuffix(s, "w")
		var value float64
		n, parseErr := fmt.Sscanf(weeks, "%f", &value)
		if parseErr != nil || n != 1 {
			return 0, fmt.Errorf("invalid duration format: %s", s)
		}
		return time.Duration(value*24*7) * time.Hour, nil
	}

	// Return original error if no custom suffix matched
	return 0, fmt.Errorf("invalid duration format: %s", s)
}
