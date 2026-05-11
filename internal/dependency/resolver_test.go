package dependency

import "testing"

func TestDependencyRefKey(t *testing.T) {
	t.Parallel()

	if got := (Ref{}).Key(); got != "" {
		t.Fatalf("Key() = %q, want empty", got)
	}
	if got := (Ref{Module: "org.example:lib"}).Key(); got != "org.example:lib" {
		t.Fatalf("Key() = %q, want org.example:lib", got)
	}
	if got := (Ref{Module: "org.example:lib", Version: "1.2.3"}).Key(); got != "org.example:lib@1.2.3" {
		t.Fatalf("Key() = %q, want org.example:lib@1.2.3", got)
	}
}
