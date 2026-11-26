package cards

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/entities"
)

const testCipherRule = `rules:
- id: java.test.cipher-aes
  languages: [java]
  message: AES cipher
  severity: INFO
  pattern: javax.crypto.Cipher.getInstance("AES")
  metadata:
    crypto:
      assetType: algorithm
      algorithmName: AES
`

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A ruleset release holds semgrep-rules/ and cards/, each with a directory
// per language; a rules checkout's language directory is the rules itself.
func TestRulesetLayout(t *testing.T) {
	release := t.TempDir()
	writeFile(t, filepath.Join(release, "semgrep-rules", "java", "x", "rules.yaml"), testCipherRule)
	writeFile(t, filepath.Join(release, "cards", "x", "rules.yaml"), "cards: []\n")
	if java, cards := rulesetLayout(release, "java"); java != filepath.Join(release, "semgrep-rules", "java") || cards != filepath.Join(release, "cards") {
		t.Errorf("release layout = %q, %q", java, cards)
	}
	flat := t.TempDir()
	writeFile(t, filepath.Join(flat, "x", "rules.yaml"), testCipherRule)
	if java, cards := rulesetLayout(flat, "java"); java != flat || cards != "" {
		t.Errorf("flat layout = %q, %q", java, cards)
	}
	pythonOnly := t.TempDir()
	writeFile(t, filepath.Join(pythonOnly, "cards", "python", "x", "rules.cards"), "cards: []\n")
	if _, cards := rulesetLayout(pythonOnly, "java"); cards != "" {
		t.Errorf("java cards of a ruleset with python cards only = %q, want none", cards)
	}
	both := t.TempDir()
	for _, lang := range []string{"java", "python"} {
		writeFile(t, filepath.Join(both, "semgrep-rules", lang, "x", "rules.yaml"), "rules: []\n")
		writeFile(t, filepath.Join(both, "cards", lang, "x", "rules.cards"), "cards: []\n")
		if rules, cards := rulesetLayout(both, lang); rules != filepath.Join(both, "semgrep-rules", lang) || cards != filepath.Join(both, "cards", lang) {
			t.Errorf("%s layout = %q, %q", lang, rules, cards)
		}
	}
}

const testPythonRules = `rules:
- id: python.test.md5
  languages: [python]
  message: MD5
  severity: INFO
  pattern: hashlib.md5(...)
  metadata:
    crypto: {assetType: algorithm, algorithmName: MD5}
- id: python.test.sha1
  languages: [python]
  message: SHA-1
  severity: INFO
  pattern: hashlib.sha1(...)
  metadata:
    crypto: {assetType: algorithm, algorithmName: SHA-1}
`

func pythonFragment() graphfrag.GraphFragmentExport {
	fragment := graphfrag.GraphFragmentExport{
		Functions:   []graphfrag.GraphFragmentFunction{{Key: "app.main.run", Package: "app.main", FilePath: "app/main.py"}},
		SourceLines: map[string]map[int]string{"app/main.py": {3: "    a = h.md5(data)", 4: "    b = h.sha1(data)"}},
		Imports:     map[string][]graphfrag.GraphFragmentImport{"app/main.py": {{Line: 1, Module: "hashlib", Alias: "h"}}},
	}
	for i, fn := range []string{"md5", "sha1"} {
		fragment.ExternalCalls = append(fragment.ExternalCalls, graphfrag.GraphFragmentExternal{
			CallerKey: "app.main.run", TargetKey: "hashlib." + fn, Raw: "h." + fn, Line: 3 + i, StartCol: 9, EndCol: 17 + len(fn),
			Resolution: "exact", MethodName: fn, EntryCall: &graphfrag.GraphFragmentCallSite{
				Line:       3 + i,
				Parameters: []graphfrag.GraphFragmentParameter{{ParameterIndex: 0, ArgumentExpression: "data"}},
			},
		})
	}
	fragment.ScanMetadata.Ecosystem = "python"
	return fragment
}

// A Python scan (Language python) matches the index compiled from
// semgrep-rules/python and the cards of cards/python against a Python
// fragment: the carded rule is reported once (its card replaces its compiled
// entry), the other through its compiled entry. A Java scan of the same
// ruleset reads neither the Python rules nor the Python cards.
func TestScanPythonCards(t *testing.T) {
	release := t.TempDir()
	writeFile(t, filepath.Join(release, "semgrep-rules", "python", "x", "rules.yaml"), testPythonRules)
	writeFile(t, filepath.Join(release, "semgrep-rules", "java", "x", "rules.yaml"), testCipherRule)
	writeFile(t, filepath.Join(release, "cards", "python", "x", "rules.cards"), "cards:\n- rule: python.test.md5\n  match: {call: hashlib.md5}\n")
	catalogs := NewCatalogs() // shared: each language keeps its own catalog
	scan := func(language string, fragment graphfrag.GraphFragmentExport) ([]string, error) {
		report, err := NewScannerFactory(Options{
			Language: language,
			Catalogs: catalogs,
			Fragment: func(string) (graphfrag.GraphFragmentExport, error) { return fragment, nil },
			Ruleset:  func() ([]string, error) { return []string{release}, nil },
		})().Scan(t.Context(), t.TempDir(), []string{filepath.Join(release, "semgrep-rules", language)}, entities.ToolInfo{})
		if err != nil {
			return nil, err
		}
		var ids []string
		for _, finding := range report.Findings {
			for _, asset := range finding.CryptographicAssets {
				for _, rule := range asset.Rules {
					ids = append(ids, rule.ID)
				}
			}
		}
		return ids, nil
	}
	ids, err := scan("python", pythonFragment())
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(ids)
	if want := []string{"x.python.test.md5", "x.python.test.sha1"}; !reflect.DeepEqual(ids, want) {
		t.Errorf("python rule ids = %v, want %v", ids, want)
	}
	ids, err = scan("java", cipherFragment())
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "x.java.test.cipher-aes" {
		t.Errorf("java rule ids = %v, want x.java.test.cipher-aes", ids)
	}
}

// With no index or rules directory given, the scanner compiles the index from
// the ruleset directory the rules source loaded (a leased ruleset's run
// directory), not from the rule paths Scan gets, which are a copy filtered for
// OpenGrep without cards/. A finding takes the rule id OpenGrep would report,
// relative to those rule paths.
func TestScanCompilesTheRulesetItIsGiven(t *testing.T) {
	release := t.TempDir()
	writeFile(t, filepath.Join(release, "semgrep-rules", "java", "x", "rules.yaml"), testCipherRule)
	fragment := cipherFragment()
	ruleset := []string{release}
	scanner := NewScannerFactory(Options{
		Fragment: func(string) (graphfrag.GraphFragmentExport, error) { return fragment, nil },
		Ruleset:  func() ([]string, error) { return ruleset, nil },
	})()
	filtered := []string{filepath.Join(t.TempDir(), "filtered")}
	writeFile(t, filepath.Join(filtered[0], "x", "rules.yaml"), testCipherRule)
	report, err := scanner.Scan(t.Context(), t.TempDir(), filtered, entities.ToolInfo{Name: "cards", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, finding := range report.Findings {
		for _, asset := range finding.CryptographicAssets {
			for _, rule := range asset.Rules {
				ids = append(ids, rule.ID)
			}
		}
	}
	if len(ids) != 1 || ids[0] != "x.java.test.cipher-aes" {
		t.Errorf("rule ids = %v, want x.java.test.cipher-aes", ids)
	}
	ruleset = []string{release, release}
	if _, err := NewScannerFactory(Options{
		Fragment: func(string) (graphfrag.GraphFragmentExport, error) { return fragment, nil },
		Ruleset:  func() ([]string, error) { return ruleset, nil },
	})().Scan(t.Context(), t.TempDir(), filtered, entities.ToolInfo{}); err == nil {
		t.Error("two ruleset directories: want an error")
	}
}

// The filtered copy OpenGrep gets may merge rule files into one, with each
// rule's directory written into its id; the finding keeps that id.
func TestScanFindsRulesInAMergedCopy(t *testing.T) {
	release := t.TempDir()
	writeFile(t, filepath.Join(release, "semgrep-rules", "java", "x", "rules.yaml"), testCipherRule)
	filtered := t.TempDir()
	writeFile(t, filepath.Join(filtered, "merged-rules.yaml"),
		`{"rules":[{"id":"x.java.test.other","languages":["java"],"message":"o","severity":"INFO","pattern":"f()"},
{"id":"x.java.test.cipher-aes","languages":["java"],"message":"AES cipher","severity":"INFO","pattern":"g()"}]}`)
	scanner := NewScannerFactory(Options{
		Fragment: func(string) (graphfrag.GraphFragmentExport, error) { return cipherFragment(), nil },
		Ruleset:  func() ([]string, error) { return []string{release}, nil },
	})()
	report, err := scanner.Scan(t.Context(), t.TempDir(), []string{filtered}, entities.ToolInfo{Name: "cards", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].CryptographicAssets[0].Rules[0].ID != "x.java.test.cipher-aes" {
		t.Errorf("findings = %+v, want the cipher rule under its merged id", report.Findings)
	}
}

func cipherFragment() graphfrag.GraphFragmentExport {
	line, col, endCol := 5, 20, 52
	return graphfrag.GraphFragmentExport{
		Functions: []graphfrag.GraphFragmentFunction{{Key: "app.(X).run#0", Package: "app", FilePath: "app/X.java"}},
		ExternalCalls: []graphfrag.GraphFragmentExternal{{
			CallerKey: "app.(X).run#0", TargetKey: "javax.crypto.(Cipher).getInstance#1", Raw: "Cipher.getInstance",
			Line: line, StartCol: col, EndCol: endCol, Resolution: "exact", MethodName: "getInstance", Arity: 1,
			EntryCall: &graphfrag.GraphFragmentCallSite{Line: line, Parameters: []graphfrag.GraphFragmentParameter{
				{ParameterIndex: 0, ArgumentExpression: `"AES"`, ResolvedValue: `"AES"`},
			}},
		}},
		SourceLines: map[string]map[int]string{"app/X.java": {line: `        Cipher c = Cipher.getInstance("AES");`}},
	}
}

// A release's card files are rules.cards (YAML under a name crypto-finder
// releases without the cards scanner do not pass to OpenGrep); the scanner
// reads them, so a card for a rule the ruleset lacks is an error.
func TestScanReadsRulesCardsFiles(t *testing.T) {
	scan := func(cardsFile string) error {
		release := t.TempDir()
		writeFile(t, filepath.Join(release, "semgrep-rules", "java", "x", "rules.yaml"), testCipherRule)
		writeFile(t, filepath.Join(release, "cards", "java", "x", cardsFile), "cards:\n- rule: java.x.unknown\n  match: {method: foo}\n")
		fragment := cipherFragment()
		_, err := NewScannerFactory(Options{
			Fragment: func(string) (graphfrag.GraphFragmentExport, error) { return fragment, nil },
			Ruleset:  func() ([]string, error) { return []string{release}, nil },
		})().Scan(t.Context(), t.TempDir(), []string{filepath.Join(release, "semgrep-rules")}, entities.ToolInfo{})
		return err
	}
	if err := scan("rules.cards"); err == nil || !strings.Contains(err.Error(), "java.x.unknown") {
		t.Errorf("rules.cards with an unknown rule: err = %v, want the bad card", err)
	}
	if err := scan("rules.txt"); err != nil {
		t.Errorf("rules.txt is not a card file: err = %v", err)
	}
}

// The matcher gets a Python fragment's ecosystem, imports, attribute stores
// and keyword arguments.
func TestMatcherFragmentCarriesPythonData(t *testing.T) {
	fragment := pythonFragment()
	fragment.ExternalCalls[0].EntryCall.Parameters[0].Keyword = "data"
	fragment.AttributeStores = []graphfrag.GraphFragmentAttributeStore{{Line: 5, Receiver: "ctx", Attribute: "verify_mode", Operator: "="}}
	out := toMatcherFragment(&fragment)
	if out.ScanMetadata.Ecosystem != "python" || len(out.Imports["app/main.py"]) != 1 || len(out.AttributeStores) != 1 ||
		out.ExternalCalls[0].EntryCall.Parameters[0].Keyword != "data" {
		t.Errorf("matcher fragment = ecosystem %q, imports %v, stores %v, params %+v", out.ScanMetadata.Ecosystem, out.Imports,
			out.AttributeStores, out.ExternalCalls[0].EntryCall.Parameters)
	}
}

// A ruleset of v3 card files only: the hand card finds the call, and the
// finding takes its rule's message, severity and purl from the card file's
// rules entry, under the id the card file's directory below the rule paths
// gives it, as a rule YAML's directory does.
func TestScanV3CardsOnly(t *testing.T) {
	release := t.TempDir()
	writeFile(t, filepath.Join(release, "cards", "java", "x", "rules.cards"), `format: scanoss-cards/3
rules:
  java.test.cipher-aes:
    severity: "INFO"
    message: "AES cipher (v3)"
    purl: "pkg:maven/example/lib"
    crypto: {assetType: "algorithm", algorithmFamily: "AES"}
cards:
- rule: java.test.cipher-aes
  match: {call: javax.crypto.Cipher.getInstance}
`)
	scanner := NewScannerFactory(Options{
		Fragment: func(string) (graphfrag.GraphFragmentExport, error) { return cipherFragment(), nil },
		Ruleset:  func() ([]string, error) { return []string{release}, nil },
	})()
	report, err := scanner.Scan(t.Context(), t.TempDir(), []string{filepath.Join(release, "cards", "java")}, entities.ToolInfo{Name: "cards", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %+v", report.Findings)
	}
	asset := report.Findings[0].CryptographicAssets[0]
	if r := asset.Rules[0]; r.ID != "x.java.test.cipher-aes" || r.Message != "AES cipher (v3)" || r.Severity != "INFO" {
		t.Errorf("rule = %+v, want x.java.test.cipher-aes with the rules entry's message", r)
	}
	if n, diffs, err := VerifyRuleInfo(filepath.Join(release, "cards", "java"), filepath.Join(release, "cards", "java")); err != nil || n != 1 || len(diffs) != 0 {
		t.Errorf("VerifyRuleInfo = %d, %v, %v", n, diffs, err)
	}
}

// The matcher gets a Node fragment's object literals.
func TestMatcherFragmentCarriesNodeObjectLiterals(t *testing.T) {
	fragment := graphfrag.GraphFragmentExport{
		ObjectLiterals: map[string][]graphfrag.GraphFragmentObjectLiteral{"src/a.js": {{Line: 2, StartCol: 7, EndCol: 20, Text: "{ alg: 'x1' }"}}},
	}
	fragment.ScanMetadata.Ecosystem = "node"
	if out := toMatcherFragment(&fragment); !reflect.DeepEqual(out.ObjectLiterals, fragment.ObjectLiterals) {
		t.Errorf("matcher fragment object literals = %+v", out.ObjectLiterals)
	}
}

// A C++ scan also matches the C rules that name C++, as OpenGrep runs a
// [c, cpp] rule on C++ files: a C rule of languages [c] does not apply, and
// a rule both rule sets match at one place is reported once.
func TestScanCPPAlsoMatchesTheCRules(t *testing.T) {
	release := t.TempDir()
	rule := func(id, langs, pattern string) string {
		return "- id: " + id + "\n  languages: " + langs + "\n  message: m\n  severity: INFO\n  pattern: " + pattern +
			"\n  metadata: {crypto: {assetType: algorithm, algorithmName: X}}\n"
	}
	writeFile(t, filepath.Join(release, "semgrep-rules", "cpp", "acme", "rules.yaml"),
		"rules:\n"+rule("cpp.acme.seal", "[cpp]", "acme::seal(...)")+rule("acme.shared", "[c, cpp]", "acme_mix(...)"))
	writeFile(t, filepath.Join(release, "semgrep-rules", "c", "acme", "rules.yaml"),
		"rules:\n"+rule("c.acme.mix", "[c, cpp]", "acme_mix(...)")+rule("c.acme.only", "[c]", "acme_mix(...)")+
			rule("acme.shared", "[c, cpp]", "acme_mix(...)"))
	src := map[int]string{3: "    acme::seal(k);", 4: "    acme_mix(k);"}
	fragment := graphfrag.GraphFragmentExport{
		Functions: []graphfrag.GraphFragmentFunction{{Key: "main", FilePath: "src/a.cpp"}},
		ExternalCalls: []graphfrag.GraphFragmentExternal{
			{CallerKey: "main", Raw: "acme::seal", Line: 3, StartCol: 5, EndCol: 18, Resolution: "exact", MethodName: "seal"},
			{CallerKey: "main", Raw: "acme_mix", Line: 4, StartCol: 5, EndCol: 16, Resolution: "exact", MethodName: "acme_mix"},
		},
		SourceLines: map[string]map[int]string{"src/a.cpp": src},
	}
	fragment.ScanMetadata.Ecosystem = ecosystemCPP
	report, err := NewScannerFactory(Options{
		Language: ecosystemCPP,
		Fragment: func(string) (graphfrag.GraphFragmentExport, error) { return fragment, nil },
		Ruleset:  func() ([]string, error) { return []string{release}, nil },
	})().Scan(t.Context(), t.TempDir(), []string{filepath.Join(release, "semgrep-rules")}, entities.ToolInfo{})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, finding := range report.Findings {
		for _, asset := range finding.CryptographicAssets {
			for _, rule := range asset.Rules {
				ids = append(ids, rule.ID)
			}
		}
	}
	sort.Strings(ids)
	want := []string{"c.acme.acme.shared", "c.acme.c.acme.mix", "cpp.acme.cpp.acme.seal"}
	if !reflect.DeepEqual(ids, want) {
		t.Errorf("rule ids = %v, want %v", ids, want)
	}
}
