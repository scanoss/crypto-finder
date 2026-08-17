package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

func TestLiveReachability(t *testing.T) {
	fn := &callgraph.FunctionDecl{ID: callgraph.FunctionID{Package: "com.app", Type: "Main", Name: "run#0"}}
	user := map[string]bool{"com.app": true}
	cases := []struct {
		name              string
		containing        *callgraph.FunctionDecl
		userPackages      map[string]bool
		traced, truncated bool
		want              string
	}{
		{"no containing function", nil, user, false, false, graphfrag.ReachabilityNotApplicable},
		{"mine path without user universe", fn, nil, false, false, graphfrag.ReachabilityNotApplicable},
		{"traced chain", fn, user, true, false, graphfrag.ReachabilityReachable},
		{"traced chain trumps truncation", fn, user, true, true, graphfrag.ReachabilityReachable},
		{"untraced truncated is unknown", fn, user, false, true, graphfrag.ReachabilityUnknown},
		{"untraced complete is unreachable", fn, user, false, false, graphfrag.ReachabilityUnreachable},
	}
	for _, tc := range cases {
		if got := liveReachability(tc.containing, tc.userPackages, tc.traced, tc.truncated); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestLiveFindingAnalysis(t *testing.T) {
	chains := [][]callGraphChainNode{{
		{FunctionKey: "a", EntryCall: &callGraphEntryCall{Parameters: []callGraphParameter{{ResolvedValue: "AES"}}}},
		{FunctionKey: "b"},
	}}
	got := liveFindingAnalysis(chains, false)
	if got.CallChains != graphfrag.AnalysisComplete || got.Parameters != graphfrag.AnalysisComplete {
		t.Errorf("complete case: got %+v", got)
	}

	mixed := [][]callGraphChainNode{{
		{FunctionKey: "a", EntryCall: &callGraphEntryCall{Parameters: []callGraphParameter{{ResolvedValue: "AES"}, {}}}},
	}}
	got = liveFindingAnalysis(mixed, true)
	if got.CallChains != graphfrag.AnalysisPartial || got.Parameters != graphfrag.AnalysisPartial {
		t.Errorf("truncated/mixed case: got %+v", got)
	}

	if got = liveFindingAnalysis([][]callGraphChainNode{{{FunctionKey: "a"}}}, false); got.Parameters != graphfrag.AnalysisUnavailable {
		t.Errorf("unavailable case: got %+v", got)
	}
}
