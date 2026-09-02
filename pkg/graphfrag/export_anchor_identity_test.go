// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import "testing"

// TestBuildExportNodeFallsBackToFrameSignature pins that a frame whose
// Function never resolved in the fragment catalog (a package-level var/const
// initializer anchor) still ships an identity: the frame signature. The
// serving render rejects identity-less frames.
func TestBuildExportNodeFallsBackToFrameSignature(t *testing.T) {
	root := ComponentKey{Purl: "pkg:golang/example.com/lib", Version: "v1.0.0"}
	frame := CallFrame{
		Component: root,
		Signature: "example.com/lib.<varinit:consts>",
	}
	node := buildExportNode(&frame, root, "go")
	if node.FunctionName != "example.com/lib.<varinit:consts>" {
		t.Fatalf("FunctionName = %q, want the frame signature", node.FunctionName)
	}
	if node.FunctionKey != "example.com/lib.<varinit:consts>" {
		t.Fatalf("FunctionKey = %q, want the frame signature", node.FunctionKey)
	}
}

// TestBuildExportNodeKeepsResolvedIdentity pins that the fallback never
// clobbers a resolved Function identity.
func TestBuildExportNodeKeepsResolvedIdentity(t *testing.T) {
	root := ComponentKey{Purl: "pkg:golang/example.com/lib", Version: "v1.0.0"}
	frame := CallFrame{
		Component: root,
		Signature: "example.com/lib.Real",
		Function: Function{
			Signature:    "example.com/lib.Real",
			FunctionName: "example.com/lib.Real",
		},
	}
	node := buildExportNode(&frame, root, "go")
	if node.FunctionName != "example.com/lib.Real" {
		t.Fatalf("FunctionName = %q", node.FunctionName)
	}
}

// TestBuildExportChainSynthesizesPackageLevelIdentity pins that a single-frame
// chain whose op anchors at package scope (empty function signature end to
// end) ships a synthesized identity from the op location.
func TestBuildExportChainSynthesizesPackageLevelIdentity(t *testing.T) {
	root := ComponentKey{Purl: "pkg:golang/example.com/lib", Version: "v1.0.0"}
	fc := FindingChain{
		FindingID: "abcd1234",
		Frames:    []CallFrame{{Component: root}},
		CryptoOp:  &CryptoOperation{FilePath: "helper/consts.go", StartLine: 12, RuleID: "r"},
	}
	nodes, _ := buildExportChain(&fc, root, "go")
	if len(nodes) != 1 {
		t.Fatalf("nodes = %d, want 1", len(nodes))
	}
	if nodes[0].FunctionName != "<package-level:helper/consts.go:12>" {
		t.Fatalf("FunctionName = %q", nodes[0].FunctionName)
	}
	if nodes[0].FilePath == "" {
		t.Fatal("FilePath empty")
	}
}
