// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPythonParser_LocalArgumentSources(t *testing.T) {
	src := `from cryptography.hazmat.primitives.asymmetric import ec

def f(flag):
    bits = 2048
    curve = ec.SECP521R1()
    twice = 1024
    twice = 4096
    if flag:
        cond = 2048
    else:
        cond = 2048
    use(bits, curve, twice, cond, unknown)
`
	fns := parsePythonInline(t, src)
	call := findPythonCallByMethod(findPythonFuncByName(fns, "f"), "use")
	if call == nil || len(call.ArgumentSources) != 5 {
		t.Fatalf("use call = %+v", call)
	}
	bits := call.ArgumentSources[0]
	if len(bits) != 1 || bits[0].Type != "VARIABLE" || bits[0].Name != "bits" || len(bits[0].SourceNodes) != 1 || bits[0].SourceNodes[0].Value != "2048" {
		t.Errorf("bits = %+v, want VARIABLE bits wrapping VALUE 2048", bits)
	}
	curve := call.ArgumentSources[1]
	if len(curve) != 1 || curve[0].Type != "VARIABLE" || len(curve[0].SourceNodes) != 1 || curve[0].SourceNodes[0].Type != "CALL_RESULT" || curve[0].SourceNodes[0].CallTarget == nil {
		t.Fatalf("curve = %+v, want VARIABLE wrapping CALL_RESULT", curve)
	}
	if got := curve[0].SourceNodes[0].CallTarget; got.Name != "SECP521R1" {
		t.Errorf("curve call target = %+v, want SECP521R1", got)
	}
	if got := call.ArgumentSources[2]; got != nil {
		t.Errorf("twice = %+v, want nil: two different literals", got)
	}
	if got := call.ArgumentSources[3]; len(got) != 1 || got[0].SourceNodes[0].Value != "2048" {
		t.Errorf("cond = %+v, want VALUE 2048: both branches agree", got)
	}
	if got := call.ArgumentSources[4]; got != nil {
		t.Errorf("unknown = %+v, want nil", got)
	}
}

// TestPythonParser_LocalArgumentSourcesScaleLinearly pins that locals are
// indexed once per function. Resolving a name by rescanning the function body
// per argument grows with the square of its size.
func TestPythonParser_LocalArgumentSourcesScaleLinearly(t *testing.T) {
	build := func(n int) string {
		var b strings.Builder
		b.WriteString("def f(items):\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "    v%d = %d\n", i, i+1)
			if i%4 == 0 {
				fmt.Fprintf(&b, "    v%d = %d\n", i, i+2)
			}
		}
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "    gen(v%d)\n", i)
		}
		return b.String()
	}
	measure := func(n int) (visits int, resolved int, elapsed time.Duration) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "big.py"), []byte(build(n)), 0o644); err != nil {
			t.Fatal(err)
		}
		p := NewPythonParser()
		p.visits = &visits
		start := time.Now()
		analyses, err := p.ParseDirectory(dir, "pkg")
		if err != nil {
			t.Fatal(err)
		}
		elapsed = time.Since(start)
		for _, a := range analyses {
			for _, fn := range a.Functions {
				for _, call := range fn.Calls {
					if call.Callee.Name == "gen" && len(call.ArgumentSources) == 1 && len(call.ArgumentSources[0]) == 1 {
						resolved++
					}
				}
			}
		}
		return visits, resolved, elapsed
	}
	const small, large = 1000, 4000
	smallVisits, smallResolved, _ := measure(small)
	largeVisits, largeResolved, elapsed := measure(large)
	if want := small - (small+3)/4; smallResolved != want {
		t.Fatalf("resolved %d of %d unambiguous locals", smallResolved, want)
	}
	if want := large - (large+3)/4; largeResolved != want {
		t.Fatalf("resolved %d of %d unambiguous locals", largeResolved, want)
	}
	if ratio := float64(largeVisits) / float64(smallVisits); ratio > 5 {
		t.Fatalf("visits grew %.1fx for a 4x larger function, want about 4x", ratio)
	}
	if elapsed > 20*time.Second {
		t.Fatalf("parsing %d locals took %s, want near-linear time", large, elapsed)
	}
}
