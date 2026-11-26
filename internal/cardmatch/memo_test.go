package cardmatch

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/scanoss/crypto-finder/internal/parsememo"
)

const memoDoc = `format: scanoss-cards/3
x-base: &base {kind: call, weight: 2}
rules:
  example.r: {severity: INFO, crypto: {keySize: 256, big: 123456789012345678901234567890, ratio: .5, inf: .inf, on: yes, none: ~}}
cards:
- rule: example.r
  match: {<<: *base, call: example.r, args: [1, "1", 0x10, [], {}]}
  1: integer key
  true: boolean key
`

func TestParseMemoServesTheNextProcess(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	parsememo.Enable()
	path := filepath.Join(home, "rules", "cards", "python", "example.cards")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(memoDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	newProcess := func() { parseMemos.byName = map[string]*parsememo.Memo{} }
	newProcess()
	defer newProcess()

	want, err := parseYAML([]byte(memoDoc))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadYAML(path); err != nil {
		t.Fatal(err)
	}
	if err := SaveMemo(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, ".scanoss", "crypto-finder", "cache", "cards-match-python.memo")); err != nil {
		t.Fatalf("the python cards memo: %v", err)
	}

	newProcess()
	stored, ok := parseMemoFor(path).Get(sha256Of(memoDoc))
	if !ok {
		t.Fatal("the next process finds no memo entry")
	}
	r := parsememo.NewReader(stored)
	if got := decodeYAMLValue(r); !r.Done() || !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded %s (done %v)\nparsed  %s", jsonValue(got), r.Done(), jsonValue(want))
	}
	served, err := loadYAML(path)
	if err != nil || !reflect.DeepEqual(served, want) {
		t.Fatalf("loadYAML = %s, %v", jsonValue(served), err)
	}
	if again, _ := loadYAML(path); again.(*OMap) == served.(*OMap) {
		t.Error("the memo served one value twice; a parse builds a new one each time")
	}
}

func sha256Of(s string) parsememo.Key { return sha256.Sum256([]byte(s)) }
