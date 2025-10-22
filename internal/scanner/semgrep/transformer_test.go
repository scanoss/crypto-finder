package semgrep

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestResolveMetavars(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		metavars map[string]entities.MetavarInfo
		want     string
	}{
		{
			name:  "Single metavar embedded in string",
			input: "SHA-$variant",
			metavars: map[string]entities.MetavarInfo{
				"$variant": {
					AbstractContent: "256",
				},
			},
			want: "SHA-256",
		},
		{
			name:  "Multiple metavars in string",
			input: "AES-$keySize-$mode",
			metavars: map[string]entities.MetavarInfo{
				"$keySize": {
					AbstractContent: "256",
				},
				"$mode": {
					AbstractContent: "GCM",
				},
			},
			want: "AES-256-GCM",
		},
		{
			name:  "Standalone metavar",
			input: "$ALGORITHM",
			metavars: map[string]entities.MetavarInfo{
				"$ALGORITHM": {
					AbstractContent: "\"AES\"",
				},
			},
			want: "AES",
		},
		{
			name:  "String without metavars",
			input: "RSA-2048",
			metavars: map[string]entities.MetavarInfo{
				"$OTHER": {
					AbstractContent: "value",
				},
			},
			want: "RSA-2048",
		},
		{
			name:  "Metavar not found - keep original",
			input: "SHA-$unknown",
			metavars: map[string]entities.MetavarInfo{
				"$variant": {
					AbstractContent: "256",
				},
			},
			want: "SHA-$unknown",
		},
		{
			name:  "Multiple metavars, some missing",
			input: "AES-$keySize-$mode-$unknown",
			metavars: map[string]entities.MetavarInfo{
				"$keySize": {
					AbstractContent: "128",
				},
				"$mode": {
					AbstractContent: "CBC",
				},
			},
			want: "AES-128-CBC-$unknown",
		},
		{
			name:  "Empty string",
			input: "",
			metavars: map[string]entities.MetavarInfo{
				"$variant": {
					AbstractContent: "256",
				},
			},
			want: "",
		},
		{
			name:  "Metavar with propagated value",
			input: "SHA-$variant",
			metavars: map[string]entities.MetavarInfo{
				"$variant": {
					AbstractContent: "128",
					PropagatedValue: &entities.MetavarPropagatedValue{
						SvalueAbstractContent: "256",
					},
				},
			},
			want: "SHA-256", // Should prefer propagated value
		},
		{
			name:  "Metavar with quotes in propagated value",
			input: "$ALGORITHM",
			metavars: map[string]entities.MetavarInfo{
				"$ALGORITHM": {
					PropagatedValue: &entities.MetavarPropagatedValue{
						SvalueAbstractContent: "\"SHA-512\"",
					},
				},
			},
			want: "SHA-512", // Should strip quotes
		},
		{
			name:     "Empty metavars map",
			input:    "SHA-$variant",
			metavars: map[string]entities.MetavarInfo{},
			want:     "SHA-$variant",
		},
		{
			name:     "Nil metavars map",
			input:    "SHA-$variant",
			metavars: nil,
			want:     "SHA-$variant",
		},
		{
			name:  "Complex pattern with multiple variations",
			input: "$algo-$size-$mode with $padding padding",
			metavars: map[string]entities.MetavarInfo{
				"$algo": {
					AbstractContent: "AES",
				},
				"$size": {
					AbstractContent: "256",
				},
				"$mode": {
					AbstractContent: "GCM",
				},
				"$padding": {
					AbstractContent: "PKCS7",
				},
			},
			want: "AES-256-GCM with PKCS7 padding",
		},
		{
			name:  "Metavar with underscore in name",
			input: "$algorithm_name-$key_size",
			metavars: map[string]entities.MetavarInfo{
				"$algorithm_name": {
					AbstractContent: "RSA",
				},
				"$key_size": {
					AbstractContent: "2048",
				},
			},
			want: "RSA-2048",
		},
		{
			name:  "Metavar with numbers in name",
			input: "$var1-$var2",
			metavars: map[string]entities.MetavarInfo{
				"$var1": {
					AbstractContent: "first",
				},
				"$var2": {
					AbstractContent: "second",
				},
			},
			want: "first-second",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveMetavars(tt.input, tt.metavars)
			if got != tt.want {
				t.Errorf("resolveMetavars(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestGetMetavarValue(t *testing.T) {
	tests := []struct {
		name     string
		metavars map[string]entities.MetavarInfo
		key      string
		want     string
	}{
		{
			name: "Metavar with AbstractContent",
			metavars: map[string]entities.MetavarInfo{
				"$ALGORITHM": {
					AbstractContent: "AES",
				},
			},
			key:  "$ALGORITHM",
			want: "AES",
		},
		{
			name: "Metavar with PropagatedValue",
			metavars: map[string]entities.MetavarInfo{
				"$ALGORITHM": {
					AbstractContent: "oldvalue",
					PropagatedValue: &entities.MetavarPropagatedValue{
						SvalueAbstractContent: "newvalue",
					},
				},
			},
			key:  "$ALGORITHM",
			want: "newvalue",
		},
		{
			name: "Metavar with quoted value",
			metavars: map[string]entities.MetavarInfo{
				"$MODE": {
					AbstractContent: "\"GCM\"",
				},
			},
			key:  "$MODE",
			want: "GCM",
		},
		{
			name: "Direct value without $ prefix",
			metavars: map[string]entities.MetavarInfo{
				"$ALGO": {
					AbstractContent: "value",
				},
			},
			key:  "literal-value",
			want: "literal-value",
		},
		{
			name: "Empty key",
			metavars: map[string]entities.MetavarInfo{
				"$ALGO": {
					AbstractContent: "value",
				},
			},
			key:  "",
			want: "",
		},
		{
			name: "Metavar not found",
			metavars: map[string]entities.MetavarInfo{
				"$ALGO": {
					AbstractContent: "value",
				},
			},
			key:  "$NOTFOUND",
			want: "",
		},
		{
			name: "Key without $ tries with and without prefix",
			metavars: map[string]entities.MetavarInfo{
				"variant": {
					AbstractContent: "256",
				},
			},
			key:  "$variant",
			want: "256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getMetavarValue(tt.metavars, tt.key)
			if got != tt.want {
				t.Errorf("getMetavarValue(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestExtractCryptoMetadata(t *testing.T) {
	tests := []struct {
		name           string
		cryptoMetadata map[string]any
		metavars       map[string]entities.MetavarInfo
		wantMetadata   map[string]string
	}{
		{
			name: "String with embedded metavar",
			cryptoMetadata: map[string]any{
				"algorithmName": "SHA-$variant",
				"primitive":     "hash",
			},
			metavars: map[string]entities.MetavarInfo{
				"$variant": {
					AbstractContent: "256",
				},
			},
			wantMetadata: map[string]string{
				"algorithmName": "SHA-256",
				"primitive":     "hash",
			},
		},
		{
			name: "Multiple metavars in values",
			cryptoMetadata: map[string]any{
				"algorithmName":          "AES-$keySize",
				"mode":                   "$mode",
				"parameterSetIdentifier": "$keySize",
			},
			metavars: map[string]entities.MetavarInfo{
				"$keySize": {
					AbstractContent: "256",
				},
				"$mode": {
					AbstractContent: "GCM",
				},
			},
			wantMetadata: map[string]string{
				"algorithmName":          "AES-256",
				"mode":                   "GCM",
				"parameterSetIdentifier": "256",
			},
		},
		{
			name: "Boolean value",
			cryptoMetadata: map[string]any{
				"algorithmName": "RSA",
				"certified":     true,
			},
			metavars: map[string]entities.MetavarInfo{},
			wantMetadata: map[string]string{
				"algorithmName": "RSA",
				"certified":     "true",
			},
		},
		{
			name: "Numeric value",
			cryptoMetadata: map[string]any{
				"algorithmName": "AES",
				"keySize":       float64(256),
			},
			metavars: map[string]entities.MetavarInfo{},
			wantMetadata: map[string]string{
				"algorithmName": "AES",
				"keySize":       "256",
			},
		},
		{
			name: "Mixed types",
			cryptoMetadata: map[string]any{
				"algorithmName": "AES-$keySize-$mode",
				"primitive":     "ae",
				"keySize":       float64(256),
				"certified":     true,
			},
			metavars: map[string]entities.MetavarInfo{
				"$keySize": {
					AbstractContent: "256",
				},
				"$mode": {
					AbstractContent: "GCM",
				},
			},
			wantMetadata: map[string]string{
				"algorithmName": "AES-256-GCM",
				"primitive":     "ae",
				"keySize":       "256",
				"certified":     "true",
			},
		},
		{
			name: "Literal string value",
			cryptoMetadata: map[string]any{
				"algorithmName": "SHA-256",
				"primitive":     "hash",
			},
			metavars: map[string]entities.MetavarInfo{},
			wantMetadata: map[string]string{
				"algorithmName": "SHA-256",
				"primitive":     "hash",
			},
		},
		{
			name:           "Empty metadata",
			cryptoMetadata: map[string]any{},
			metavars: map[string]entities.MetavarInfo{
				"$variant": {
					AbstractContent: "256",
				},
			},
			wantMetadata: map[string]string{},
		},
		{
			name: "Real example from Semgrep output",
			cryptoMetadata: map[string]any{
				"algorithmName":          "SHA-$variant",
				"api":                    "MessageDigest.getInstance",
				"assetType":              "algorithm",
				"library":                "JCA/JCE",
				"parameterSetIdentifier": "$variant",
				"primitive":              "hash",
			},
			metavars: map[string]entities.MetavarInfo{
				"$variant": {
					AbstractContent: "256",
				},
			},
			wantMetadata: map[string]string{
				"algorithmName":          "SHA-256",
				"api":                    "MessageDigest.getInstance",
				"assetType":              "algorithm",
				"library":                "JCA/JCE",
				"parameterSetIdentifier": "256",
				"primitive":              "hash",
			},
		},
		{
			name: "Metavar not found - keeps original",
			cryptoMetadata: map[string]any{
				"algorithmName": "SHA-$unknown",
			},
			metavars: map[string]entities.MetavarInfo{
				"$variant": {
					AbstractContent: "256",
				},
			},
			wantMetadata: map[string]string{
				"algorithmName": "SHA-$unknown",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := &entities.CryptographicAsset{
				Metadata: make(map[string]string),
			}

			extractCryptoMetadata(asset, tt.cryptoMetadata, tt.metavars)

			if len(asset.Metadata) != len(tt.wantMetadata) {
				t.Errorf("extractCryptoMetadata() got %d metadata entries, want %d",
					len(asset.Metadata), len(tt.wantMetadata))
			}

			for key, want := range tt.wantMetadata {
				got, ok := asset.Metadata[key]
				if !ok {
					t.Errorf("extractCryptoMetadata() missing key %q", key)
					continue
				}
				if got != want {
					t.Errorf("extractCryptoMetadata() metadata[%q] = %q, want %q", key, got, want)
				}
			}
		})
	}
}

func TestDetectLanguage(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     string
	}{
		{
			name:     "Java file",
			filePath: "/path/to/File.java",
			want:     "java",
		},
		{
			name:     "Python file",
			filePath: "/path/to/script.py",
			want:     "python",
		},
		{
			name:     "Go file",
			filePath: "/path/to/main.go",
			want:     "go",
		},
		{
			name:     "JavaScript file",
			filePath: "/path/to/app.js",
			want:     "javascript",
		},
		{
			name:     "TypeScript file",
			filePath: "/path/to/app.ts",
			want:     "typescript",
		},
		{
			name:     "Unknown extension",
			filePath: "/path/to/file.xyz",
			want:     "unknown",
		},
		{
			name:     "No extension",
			filePath: "/path/to/Makefile",
			want:     "makefile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectLanguage(tt.filePath)
			if got != tt.want {
				t.Errorf("detectLanguage(%q) = %q, want %q", tt.filePath, got, tt.want)
			}
		})
	}
}
