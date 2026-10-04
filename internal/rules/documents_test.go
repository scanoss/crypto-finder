// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package rules

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"go.yaml.in/yaml/v3"
)

type languagesView struct {
	Rules []struct {
		ID        string   `yaml:"id"`
		Languages []string `yaml:"languages"`
	} `yaml:"rules"`
}

type severityView struct {
	Rules []struct {
		Severity int `yaml:"severity"`
	} `yaml:"rules"`
}

// Every view decodes exactly what yaml.Unmarshal decodes from the same bytes,
// including its errors and partial results.
func TestDocumentsDecodeMatchesUnmarshal(t *testing.T) {
	t.Parallel()
	inputs := map[string]string{
		"valid":      "rules:\n  - id: a\n    languages: [go, c]\n    severity: 3\n",
		"type error": "rules:\n  - id: a\n    languages: [go]\n    severity: high\n",
		"syntax":     "rules:\n  - id: [unclosed\n",
		"empty":      "",
		"comment":    "# nothing here\n",
		"two docs":   "rules:\n  - id: first\n---\nrules:\n  - id: second\n",
		"anchors":    "base: &b [go]\nrules:\n  - id: a\n    languages: *b\n",
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			docs := NewDocuments(new(languagesView), new(severityView))
			for range 2 { // the second round reads the stored views
				var gotLang, wantLang languagesView
				gotErr, wantErr := docs.Decode("rules.yaml", []byte(input), &gotLang), yaml.Unmarshal([]byte(input), &wantLang)
				assertSameDecode(t, gotLang, wantLang, gotErr, wantErr)
				var gotSev, wantSev severityView
				gotErr, wantErr = docs.Decode("rules.yaml", []byte(input), &gotSev), yaml.Unmarshal([]byte(input), &wantSev)
				assertSameDecode(t, gotSev, wantSev, gotErr, wantErr)
			}
		})
	}
}

func assertSameDecode(t *testing.T, got, want any, gotErr, wantErr error) {
	t.Helper()
	if (gotErr == nil) != (wantErr == nil) || (gotErr != nil && gotErr.Error() != wantErr.Error()) {
		t.Fatalf("error = %v, want %v", gotErr, wantErr)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded %#v, want %#v", got, want)
	}
}

func TestDocumentsReuseParseUntilBytesChange(t *testing.T) {
	t.Parallel()
	docs := NewDocuments(new(languagesView))
	first := []byte("rules:\n  - id: a\n    languages: [go]\n")
	var a, b languagesView
	if err := docs.Decode("r.yaml", first, &a); err != nil {
		t.Fatal(err)
	}
	if err := docs.Decode("r.yaml", append([]byte(nil), first...), &b); err != nil {
		t.Fatal(err)
	}
	// Shared backing arrays prove the second Decode reused the first parse.
	if &a.Rules[0] != &b.Rules[0] {
		t.Fatal("identical bytes were parsed again")
	}
	var changed languagesView
	if err := docs.Decode("r.yaml", []byte("rules:\n  - id: b\n    languages: [c]\n"), &changed); err != nil {
		t.Fatal(err)
	}
	if changed.Rules[0].ID != "b" || changed.Rules[0].Languages[0] != "c" {
		t.Fatalf("changed bytes decoded stale view %#v", changed)
	}
	// A view that was not registered still decodes, with its own parse.
	var other severityView
	if err := docs.Decode("r.yaml", []byte("rules:\n  - severity: 2\n"), &other); err != nil || other.Rules[0].Severity != 2 {
		t.Fatalf("unregistered view: %#v, %v", other, err)
	}
	var unshared languagesView
	if err := (*Documents)(nil).Decode("r.yaml", first, &unshared); err != nil || unshared.Rules[0].ID != "a" {
		t.Fatalf("nil Documents: %#v, %v", unshared, err)
	}
}

func TestDocumentsConcurrentDecode(t *testing.T) {
	t.Parallel()
	docs := NewDocuments(new(languagesView))
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data := []byte("rules:\n  - id: a\n    languages: [go]\n")
			if i%2 == 1 {
				data = []byte("rules:\n  - id: b\n    languages: [c]\n")
			}
			var view languagesView
			if err := docs.Decode("r.yaml", data, &view); err != nil {
				t.Error(err)
				return
			}
			if want := map[bool]string{false: "a", true: "b"}[i%2 == 1]; view.Rules[0].ID != want {
				t.Errorf("decoded %q, want %q", view.Rules[0].ID, want)
			}
		}()
	}
	wg.Wait()
}

// The gate reports the same errors whether or not it shares a Documents.
func TestValidateDocumentsMatchesValidate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	files := map[string]string{
		"ok.yaml":     "rules:\n  - id: ok\n    metadata:\n      crypto:\n        parameterCondition: \"$x == 'AES'\"\n",
		"bad.yaml":    "rules:\n  - id: bad\n    metadata:\n      crypto:\n        parameterCondition: \"$x ==\"\n",
		"broken.yaml": "rules:\n  - id: [\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want := (&ParameterConditionValidator{}).Validate([]string{dir})
	if want == nil || !strings.Contains(want.Error(), `rule "bad"`) || !strings.Contains(want.Error(), "broken.yaml") {
		t.Fatalf("fixture should fail on both bad files, got %v", want)
	}
	docs := NewDocuments(new(languagesView), ParameterConditionView())
	for range 2 {
		got := (&ParameterConditionValidator{}).ValidateDocuments(docs, []string{dir})
		if got == nil || got.Error() != want.Error() {
			t.Fatalf("ValidateDocuments = %v, want %v", got, want)
		}
	}
}
