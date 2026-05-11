package cli

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/scanoss/crypto-finder/internal/failure"
)

func TestValidateErrorOutputFormat(t *testing.T) {
	tests := []struct {
		name   string
		format string
		wantOK bool
	}{
		{name: "default empty", format: "", wantOK: true},
		{name: "text", format: "text", wantOK: true},
		{name: "json uppercase", format: "JSON", wantOK: true},
		{name: "invalid", format: "xml", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateErrorOutputFormat(tt.format)
			if tt.wantOK && err != nil {
				t.Fatalf("validateErrorOutputFormat(%q) unexpected error: %v", tt.format, err)
			}
			if !tt.wantOK && err == nil {
				t.Fatalf("validateErrorOutputFormat(%q) expected error", tt.format)
			}
		})
	}
}

func TestRenderJSONError(t *testing.T) {
	var buffer bytes.Buffer

	renderJSONError(&buffer, failure.Prefix(
		failure.New(
			failure.CodeGradleJavaIncompatible,
			failure.StageDependency,
			"Gradle 6.9.2 cannot run on Java 21",
			failure.WithDetail("gradle_version", "6.9.2"),
		),
		"dependency scan failed",
	))

	var payload failure.Payload
	if err := json.Unmarshal(buffer.Bytes(), &payload); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if payload.Code != failure.CodeGradleJavaIncompatible {
		t.Fatalf("Code = %q, want %q", payload.Code, failure.CodeGradleJavaIncompatible)
	}
	if payload.Stage != failure.StageDependency {
		t.Fatalf("Stage = %q, want %q", payload.Stage, failure.StageDependency)
	}
	if payload.RawError == "" {
		t.Fatal("expected raw_error to be populated")
	}
}
