// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"fmt"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

const goECDHHeader = `package main

import (
	"crypto/ecdh"
	"crypto/rand"
)

`

// TestReceiverKeyLength_ExactBitsThroughSupportingCallIDs pins the size read
// from the curve an ecdh call is invoked on, joined the way consumers read it
// (finding graph supporting_call_ids to resolved_key_length), live and stitched.
// A zero wantBits asserts the size is absent: the receiver is not one call's
// unambiguous result.
func TestReceiverKeyLength_ExactBitsThroughSupportingCallIDs(t *testing.T) {
	const (
		generate = "crypto/ecdh.Curve.GenerateKey"
		newPriv  = "crypto/ecdh.Curve.NewPrivateKey"
	)
	type tc struct {
		name     string
		body     string
		match    string
		wantFunc string
		wantBits int
	}
	cases := make([]tc, 0, 24)
	for _, curve := range []struct {
		name string
		bits int
	}{{"P256", 256}, {"P384", 384}, {"P521", 521}, {"X25519", 0}} {
		match := fmt.Sprintf("ecdh.%s().GenerateKey(rand.Reader)", curve.name)
		cases = append(cases, tc{"chain " + curve.name, "func f() {\n\t" + match + "\n}\n", match, generate, curve.bits})
	}
	cases = append(cases,
		tc{"new private key chain", "func f(b []byte) {\n\tecdh.P384().NewPrivateKey(b)\n}\n", "ecdh.P384().NewPrivateKey(b)", newPriv, 384},
		tc{"local variable", "func f() {\n\tc := ecdh.P256()\n\tc.GenerateKey(rand.Reader)\n}\n", "c.GenerateKey(rand.Reader)", generate, 256},
		tc{"local variable of another curve is not read", "func f() {\n\tc := ecdh.P256()\n\td := ecdh.P521()\n\td.GenerateKey(rand.Reader)\n\t_ = c\n}\n", "d.GenerateKey(rand.Reader)", generate, 521},

		tc{"assigned twice to one curve", "func f(x bool) {\n\tc := ecdh.P384()\n\tif x {\n\t\tc = ecdh.P384()\n\t}\n\tc.GenerateKey(rand.Reader)\n}\n", "c.GenerateKey(rand.Reader)", generate, 0},
		tc{"package variable shadowed in a sibling block", "var c = ecdh.P384()\n\nfunc f(x bool) {\n\tif x {\n\t\tc := ecdh.P256()\n\t\t_ = c\n\t}\n\tc.GenerateKey(rand.Reader)\n}\n", "c.GenerateKey(rand.Reader)", generate, 0},
		tc{"package variable shadowed in a closure", "var c = ecdh.P384()\n\nfunc f() {\n\tfunc() {\n\t\tc := ecdh.P256()\n\t\t_ = c\n\t}()\n\tc.GenerateKey(rand.Reader)\n}\n", "c.GenerateKey(rand.Reader)", generate, 0},
		tc{"package variable", "var c = ecdh.P384()\n\nfunc f() {\n\tc.GenerateKey(rand.Reader)\n}\n", "c.GenerateKey(rand.Reader)", generate, 0},
		tc{"bound in an enclosing block", "func f(x bool) {\n\tc := ecdh.P256()\n\tif x {\n\t\tc.GenerateKey(rand.Reader)\n\t}\n}\n", "c.GenerateKey(rand.Reader)", generate, 256},
		tc{"curve parameter", "func f(c ecdh.Curve) {\n\tc.GenerateKey(rand.Reader)\n}\n", "c.GenerateKey(rand.Reader)", generate, 0},
		tc{"reassigned to another curve", "func f() {\n\tc := ecdh.P256()\n\tc = ecdh.P521()\n\tc.GenerateKey(rand.Reader)\n}\n", "c.GenerateKey(rand.Reader)", generate, 0},
		tc{"reassigned to a value that is not a call", "func f(o ecdh.Curve) {\n\tc := ecdh.P256()\n\tif o != nil {\n\t\tc = o\n\t}\n\tc.GenerateKey(rand.Reader)\n}\n", "c.GenerateKey(rand.Reader)", generate, 0},
		tc{"reassigned by a callee through its address", "func f() {\n\tc := ecdh.P256()\n\tset(&c)\n\tc.GenerateKey(rand.Reader)\n}\n\nfunc set(c *ecdh.Curve) { *c = ecdh.P521() }\n", "c.GenerateKey(rand.Reader)", generate, 0},
		tc{"declared then assigned", "func f() {\n\tvar c ecdh.Curve\n\tc = ecdh.P256()\n\tc.GenerateKey(rand.Reader)\n}\n", "c.GenerateKey(rand.Reader)", generate, 0},
		tc{"rebound in a closure", "func f() {\n\tc := ecdh.P256()\n\tfunc() {\n\t\tc := ecdh.P521()\n\t\t_ = c\n\t}()\n\tc.GenerateKey(rand.Reader)\n}\n", "c.GenerateKey(rand.Reader)", generate, 0},
		tc{"result of a helper", "func f() {\n\tc := pick()\n\tc.GenerateKey(rand.Reader)\n}\n\nfunc pick() ecdh.Curve { return ecdh.P256() }\n", "c.GenerateKey(rand.Reader)", generate, 0},
	)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			source := goECDHHeader + c.body
			line := 0
			for i, text := range strings.Split(source, "\n") {
				if strings.Contains(text, c.match) {
					line = i + 1
					break
				}
			}
			if line == 0 {
				t.Fatalf("fixture does not contain %q: an absent size would be vacuous", c.match)
			}
			exports := terminalExports(t, "go", "k.go", source, line, c.match, c.wantFunc, "")
			for name, got := range map[string]*graphfrag.ResolvedKeyLength{
				"live":     keyLengthViaSupportingCallIDs(t, exports.live.FindingGraphs, exports.live.SupportingCalls, exports.findingID, c.wantFunc),
				"stitched": keyLengthViaStitchedSupportingCallIDs(t, exports.stitched, exports.findingID, c.wantFunc),
			} {
				if c.wantBits == 0 {
					if got != nil && got.Bits != nil {
						t.Fatalf("%s: resolved_key_length bits = %d, want absent", name, *got.Bits)
					}
					continue
				}
				if got == nil || got.Bits == nil || *got.Bits != c.wantBits {
					t.Fatalf("%s: resolved_key_length = %#v, want %d bits", name, got, c.wantBits)
				}
				if got.Provenance != keyLengthProvenanceConstant {
					t.Fatalf("%s: provenance = %q, want constant", name, got.Provenance)
				}
			}
			for i := range exports.live.SupportingCalls {
				call := exports.live.SupportingCalls[i].SupportingCall
				if call == nil || call.ResolvedKeyLength == nil || call.ResolvedKeyLength.Bits == nil {
					continue
				}
				if *call.ResolvedKeyLength.Bits != c.wantBits {
					t.Fatalf("supporting call %s carries %d bits, want every carrier on the graph to agree on %d", call.FunctionName, *call.ResolvedKeyLength.Bits, c.wantBits)
				}
			}
		})
	}
}

func TestWithReceiverKeyLength_DisagreementPublishesNothing(t *testing.T) {
	bits := func(n int) *graphfrag.ResolvedKeyLength {
		return &graphfrag.ResolvedKeyLength{Bits: &n, Provenance: keyLengthProvenanceConstant}
	}
	unknown := &graphfrag.ResolvedKeyLength{Provenance: keyLengthProvenanceUnknown}
	if got := withReceiverKeyLength(bits(528), bits(521)); got != nil {
		t.Fatalf("disagreeing sizes = %#v, want none", got)
	}
	if got := withReceiverKeyLength(bits(256), bits(256)); got == nil || *got.Bits != 256 {
		t.Fatalf("agreeing sizes = %#v, want 256", got)
	}
	if got := withReceiverKeyLength(unknown, bits(384)); got == nil || *got.Bits != 384 {
		t.Fatalf("unresolved argument = %#v, want the receiver's 384", got)
	}
	if got := withReceiverKeyLength(bits(128), nil); got == nil || *got.Bits != 128 {
		t.Fatalf("no receiver = %#v, want the argument's 128", got)
	}
}

// TestReceiverKeyLength_ReceiverIsNotAnExportedParameterRole pins that the
// receiver contribution stays out of parameter_roles, whose entries are
// argument positions: a receiver exported there would read as parameter 0.
func TestReceiverKeyLength_ReceiverIsNotAnExportedParameterRole(t *testing.T) {
	for _, method := range []string{"crypto/ecdh.Curve.GenerateKey", "crypto/ecdh.Curve.NewPrivateKey"} {
		source := goECDHHeader + "func f(b []byte) {\n\tecdh.P256().GenerateKey(rand.Reader)\n\tecdh.P256().NewPrivateKey(b)\n}\n"
		match := "ecdh.P256().GenerateKey(rand.Reader)"
		line := 9
		if strings.HasSuffix(method, "NewPrivateKey") {
			match, line = "ecdh.P256().NewPrivateKey(b)", 10
		}
		exports := terminalExports(t, "go", "k.go", source, line, match, method, "")
		found := false
		for i := range exports.live.SupportingCalls {
			call := exports.live.SupportingCalls[i].SupportingCall
			if call == nil || call.FunctionName != method {
				continue
			}
			found = true
			for _, role := range call.ParameterRoles {
				if role.Contributes != nil && role.Contributes.Derivation == "argument_curve_bits" {
					t.Errorf("%s exports a receiver as parameter_roles entry %#v", method, role)
				}
			}
		}
		if !found {
			t.Errorf("%s: no supporting call exported", method)
		}
	}
}
