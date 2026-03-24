package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGoParser_SelectorCallsUseReceiverTypeNotVariableName(t *testing.T) {
	p := NewGoParser()
	dir := t.TempDir()

	src := `package mypkg

type S struct{}

func callParam(s *S) {
	s.internal()
}

func (s *S) callReceiver() {
	s.internal()
}

func (s *S) internal() {}
`
	if err := os.WriteFile(filepath.Join(dir, "crypto.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	analyses, err := p.ParseDirectory(dir, "example.com/project/mypkg")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis, got %d", len(analyses))
	}

	analysis := analyses[0]
	foundParamCall := false
	foundReceiverCall := false
	for _, fn := range analysis.Functions {
		if fn.ID.Name == "callParam" {
			for _, call := range fn.Calls {
				if call.Callee.Package == "example.com/project/mypkg" && call.Callee.Type == "*S" && call.Callee.Name == "internal" {
					if call.ReceiverVar != "s" {
						t.Fatalf("callParam ReceiverVar = %q, want s", call.ReceiverVar)
					}
					foundParamCall = true
				}
			}
		}
		if fn.ID.Type == "*S" && fn.ID.Name == "callReceiver" {
			for _, call := range fn.Calls {
				if call.Callee.Package == "example.com/project/mypkg" && call.Callee.Type == "*S" && call.Callee.Name == "internal" {
					if call.ReceiverVar != "s" {
						t.Fatalf("callReceiver ReceiverVar = %q, want s", call.ReceiverVar)
					}
					foundReceiverCall = true
				}
			}
		}
	}

	if !foundParamCall {
		t.Fatal("expected parameter-based selector call to use receiver type *S")
	}
	if !foundReceiverCall {
		t.Fatal("expected receiver-based selector call to use receiver type *S")
	}
}
