package cache

import (
	"testing"
	"time"
)

func TestHumanAge(t *testing.T) {
	for _, c := range []struct {
		in   time.Duration
		want string
	}{
		{20 * time.Minute, "0h"},
		{5*time.Hour + 20*time.Minute, "5h"},
		{50 * time.Hour, "2d 2h"},
		{30 * 24 * time.Hour, "30d 0h"},
	} {
		if got := humanAge(c.in); got != c.want {
			t.Fatalf("humanAge(%s) = %q, want %q", c.in, got, c.want)
		}
	}
}
