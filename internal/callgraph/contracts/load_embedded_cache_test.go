package contracts

import (
	"sync"
	"testing"
)

// Every call graph build loads its ecosystem's KB. Re-parsing the embedded
// YAML on each build dominated scan and test time, so LoadEmbedded parses
// each ecosystem once and hands every caller the same KB.
func TestLoadEmbeddedParsesEachEcosystemOnce(t *testing.T) {
	t.Parallel()
	for _, eco := range []string{"java", "c", "cpp", "go", "node", "python", "rust", "unknown-ecosystem"} {
		t.Run(eco, func(t *testing.T) {
			t.Parallel()
			const callers = 16
			got := make([]*KnowledgeBase, callers)
			var wg sync.WaitGroup
			for i := range callers {
				wg.Go(func() {
					kb, err := LoadEmbedded(eco)
					if err != nil {
						t.Errorf("LoadEmbedded(%q): %v", eco, err)
					}
					got[i] = kb
				})
			}
			wg.Wait()
			for i, kb := range got {
				if kb == nil {
					t.Fatalf("caller %d got a nil KB", i)
				}
				if kb != got[0] {
					t.Fatalf("caller %d got a separately parsed KB; want one shared KB per ecosystem", i)
				}
			}
		})
	}
}
