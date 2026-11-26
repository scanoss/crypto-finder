// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package parsememo

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	Enable()
	os.Exit(m.Run())
}

func TestMemoServesTheNextProcess(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	first, second := sha256.Sum256([]byte("first")), sha256.Sum256([]byte("second"))

	m := New("test")
	if _, ok := m.Get(first); ok {
		t.Fatal("a new memo has an entry")
	}
	m.Put(first, []byte("one"))
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}

	m = New("test")
	if got, ok := m.Get(first); !ok || string(got) != "one" {
		t.Fatalf("Get = %q, %v, want one", got, ok)
	}
	m.Put(second, []byte("two"))
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}

	m = New("test")
	for key, want := range map[Key]string{first: "one", second: "two"} {
		if got, ok := m.Get(key); !ok || string(got) != want {
			t.Errorf("Get = %q, %v, want %s", got, ok, want)
		}
	}
}

func TestMemoKeepsWhatOtherScansSaved(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	python, rust := sha256.Sum256([]byte("python cards")), sha256.Sum256([]byte("rust cards"))
	for key, value := range map[Key]string{python: "py", rust: "rs"} {
		m := New("test")
		m.Put(key, []byte(value))
		if err := m.Save(); err != nil {
			t.Fatal(err)
		}
	}
	m := New("test")
	for key, want := range map[Key]string{python: "py", rust: "rs"} {
		if got, ok := m.Get(key); !ok || string(got) != want {
			t.Errorf("Get = %q, %v, want %s", got, ok, want)
		}
	}
}

func TestMemoPastItsBoundKeepsOnlyWhatTheLastScanUsed(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	defer func(bound int) { maxBytes = bound }(maxBytes)
	maxBytes = 200
	old, current := sha256.Sum256([]byte("old ruleset")), sha256.Sum256([]byte("new ruleset"))
	m := New("test")
	m.Put(old, make([]byte, 150))
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	m = New("test")
	m.Put(current, []byte("new"))
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	m = New("test")
	if _, ok := m.Get(old); ok {
		t.Error("an entry of the old ruleset is still there")
	}
	if got, ok := m.Get(current); !ok || string(got) != "new" {
		t.Errorf("Get = %q, %v, want new", got, ok)
	}
}

func TestMemoIgnoresAnotherBuildOrACorruptFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	key := sha256.Sum256([]byte("content"))
	m := New("test")
	m.Put(key, []byte("value"))
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, ".scanoss", "crypto-finder", "cache", "test.memo")
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"another build": append([]byte(format+"another binary's identity sum..."), saved[len(m.header):]...),
		"truncated":     saved[:len(saved)-3],
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, ok := New("test").Get(key); ok {
			t.Errorf("%s: Get found the entry", name)
		}
	}
}

func TestReaderRejectsWhatNoWriterWrote(t *testing.T) {
	var w Writer
	w.String("abc")
	w.Strings(nil)
	w.Strings([]string{})
	w.Varint(-7)
	w.Float(0.25)
	r := NewReader(w.Bytes())
	if s, none, empty, i, f := r.String(), r.Strings(), r.Strings(), r.Varint(), r.Float(); s != "abc" || none != nil || empty == nil || len(empty) != 0 || i != -7 || f != 0.25 || !r.Done() {
		t.Fatalf("read %q %#v %#v %d %v, done %v", s, none, empty, i, f, r.Done())
	}
	r = NewReader(w.Bytes()[:2])
	if s := r.String(); r.Err() == nil {
		t.Errorf("a truncated string read as %q without error", s)
	}
}
