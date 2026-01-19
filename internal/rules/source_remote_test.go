package rules

import (
	"context"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/cache"
)

func TestNewRemoteRuleSource(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cacheManager, err := cache.NewManager(nil)
	if err != nil {
		t.Fatalf("Failed to create cache manager: %v", err)
	}

	source := NewRemoteRuleSource(ctx, "dca", "latest", cacheManager)

	if source == nil {
		t.Fatal("NewRemoteRuleSource() returned nil")
	}

	if source.rulesetName != "dca" {
		t.Errorf("Expected rulesetName 'dca', got '%s'", source.rulesetName)
	}

	if source.version != "latest" {
		t.Errorf("Expected version 'latest', got '%s'", source.version)
	}

	if source.cacheManager == nil {
		t.Error("cacheManager should not be nil")
	}
}

func TestRemoteRuleSource_Name(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		rulesetName  string
		version      string
		wantContains []string
	}{
		{
			name:         "dca latest",
			rulesetName:  "dca",
			version:      "latest",
			wantContains: []string{"remote", "dca", "latest"},
		},
		{
			name:         "custom ruleset with version",
			rulesetName:  "custom-rules",
			version:      "v1.2.3",
			wantContains: []string{"remote", "custom-rules", "v1.2.3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			cacheManager, err := cache.NewManager(nil)
			if err != nil {
				t.Fatalf("Failed to create cache manager: %v", err)
			}
			source := NewRemoteRuleSource(ctx, tt.rulesetName, tt.version, cacheManager)

			name := source.Name()

			if name == "" {
				t.Fatal("Name() should not return empty string")
			}

			for _, want := range tt.wantContains {
				if !strings.Contains(name, want) {
					t.Errorf("Name() = %q should contain %q", name, want)
				}
			}
		})
	}
}
