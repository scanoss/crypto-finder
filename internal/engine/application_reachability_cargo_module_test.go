package engine

import (
	"testing"

	apiclient "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// A Cargo crate is reached in source by its library name (acme_sign) but
// named by its package name (acme-sign) everywhere a report names it: the
// purl and dependency_info.module must agree. The served answer carries the
// library name on the file and on each asset; the report must not.
func TestMergeApplicationReachability_CargoModuleIsThePackageName(t *testing.T) {
	closure := &ApplicationClosure{Ecosystem: "rust", Resolved: &dependency.ResolveResult{
		Dependencies: []dependency.Dependency{{Module: "acme-sign", ImportPath: "acme_sign", Version: "2.0.1"}},
	}}
	libInfo := func() *entities.DependencyInfo {
		return &entities.DependencyInfo{Module: "acme_sign", Version: "2.0.1", PURL: "pkg:cargo/acme-sign@2.0.1"}
	}
	answer := &apiclient.ApplicationReachability{InfoCode: "READY", Dependencies: []apiclient.ApplicationDependencyAnswer{{
		Purl: "pkg:cargo/acme-sign", Version: "2.0.1", InfoCode: "READY",
		Findings: []apiclient.ApplicationFinding{{
			FilePath: "acme_sign@2.0.1/src/lib.rs", Language: "rust", DependencyInfo: libInfo(),
			CryptographicAssets: []apiclient.ApplicationAsset{{
				Asset:        entities.CryptographicAsset{StartLine: 3, Rules: []entities.RuleInfo{{ID: "r"}}, DependencyInfo: libInfo()},
				Reachability: "unknown", ReachabilityReason: "unresolved_dispatch",
			}},
		}},
	}}}
	result, _ := MergeApplicationReachability(&entities.InterimReport{}, &DepScanResult{}, closure, answer)
	if len(result.Report.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Report.Findings))
	}
	f := result.Report.Findings[0]
	if f.FilePath != "src/lib.rs" {
		t.Errorf("file path = %q, want src/lib.rs", f.FilePath)
	}
	got := f.CryptographicAssets[0].DependencyInfo
	want := entities.DependencyInfo{Module: "acme-sign", Version: "2.0.1", PURL: "pkg:cargo/acme-sign@2.0.1"}
	if got == nil || got.Module != want.Module || got.Version != want.Version || got.PURL != want.PURL {
		t.Errorf("dependency_info = %+v, want %+v", got, want)
	}
}
