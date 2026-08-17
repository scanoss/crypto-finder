package graphfrag

import "testing"

func genuineChain(rootKey string) []ExportChainNode {
	return []ExportChainNode{
		{FunctionKey: rootKey, FunctionName: "com.app.Main.run"},
		{FunctionKey: "com.lib.(Cipher).init#1", FunctionName: "com.lib.Cipher.init"},
	}
}

func selfChain() []ExportChainNode {
	return []ExportChainNode{{FunctionKey: "com.lib.(Cipher).init#1", FunctionName: "com.lib.Cipher.init"}}
}

func TestStitchedReachability(t *testing.T) {
	cases := []struct {
		name       string
		chains     [][]ExportChainNode
		suppressed bool
		want       string
	}{
		{"genuine chain is reachable", [][]ExportChainNode{genuineChain("com.app.(Main).run#0")}, false, ReachabilityReachable},
		{"genuine chain stays reachable under suppression", [][]ExportChainNode{genuineChain("com.app.(Main).run#0")}, true, ReachabilityReachable},
		{"self-chain with suppression is unknown", [][]ExportChainNode{selfChain()}, true, ReachabilityUnknown},
		{"self-chain without suppression is unreachable", [][]ExportChainNode{selfChain()}, false, ReachabilityUnreachable},
		{"no chains without suppression is unreachable", nil, false, ReachabilityUnreachable},
		{"no chains with suppression is unknown", nil, true, ReachabilityUnknown},
	}
	for _, tc := range cases {
		if got := stitchedReachability(tc.chains, tc.suppressed); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestStitchedFindingAnalysis(t *testing.T) {
	complete := &ExportFindingGraph{CallChains: [][]ExportChainNode{{
		{FunctionKey: "a", EntryCall: &ExportEntryCall{Parameters: []ExportParameter{{ResolvedValue: "AES"}}}},
		{FunctionKey: "b"},
	}}}
	got := stitchedFindingAnalysis(complete)
	if got.CallChains != AnalysisComplete || got.Parameters != AnalysisComplete {
		t.Errorf("complete case: got %+v", got)
	}

	partial := &ExportFindingGraph{
		CallChains: [][]ExportChainNode{{
			{FunctionKey: "a", EntryCall: &ExportEntryCall{Parameters: []ExportParameter{{ResolvedValue: "AES"}, {}}}},
		}},
		ForwardCalls: &ExportForwardClosure{Truncated: true},
	}
	got = stitchedFindingAnalysis(partial)
	if got.CallChains != AnalysisPartial || got.Parameters != AnalysisPartial {
		t.Errorf("partial case: got %+v", got)
	}

	unavailable := &ExportFindingGraph{CallChains: [][]ExportChainNode{{{FunctionKey: "a"}}}}
	if got = stitchedFindingAnalysis(unavailable); got.Parameters != AnalysisUnavailable {
		t.Errorf("unavailable case: got %+v", got)
	}
}
