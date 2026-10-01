// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The cotp contracts key on the receiver type or namespace the C++ parser
// emits for a call ("Type.method"). This pins that agreement for every
// contracted method at the arity the parser counts, with its lifecycle role,
// and pins the negative half: the listed calls resolve to no contract.
func TestCOTPWrapperContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded(ecosystemCPP)
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}

	dir := t.TempDir()
	src := `#include "cotp.hpp"

bool flows(COTP::TOTP& totp, COTP::HOTP& hotp, COTP::OTP& otp, char* code, const char* chars) {
    totp.now(code);
    totp.at(59, 0, code);
    totp.verify(code, 59, 4);
    totp.valid_until(59, 4);
    totp.timecode(59);
    hotp.at(12, code);
    hotp.next(code);
    hotp.compare(code, 12);
    otp.generate(1, code);
    COTP::OTP::random_base32(32, code);
    COTP::OTP::random_base32(32, chars, code);
    return true;
}
`
	if err := os.WriteFile(filepath.Join(dir, "otp.cpp"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCPPParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"COTP::TOTP.now#1":          "operation",
		"COTP::TOTP.at#3":           "operation",
		"COTP::TOTP.verify#3":       "operation",
		"COTP::HOTP.at#2":           "operation",
		"COTP::HOTP.next#1":         "operation",
		"COTP::HOTP.compare#2":      "operation",
		"COTP::OTP.generate#2":      "operation",
		"COTP::OTP.random_base32#2": "operation",
		"COTP::OTP.random_base32#3": "operation",
	}
	negative := map[string]bool{}
	for _, key := range []string{"COTP::TOTP.valid_until#2", "COTP::TOTP.timecode#1"} {
		negative[key] = true
	}
	seen := map[string]bool{}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method := cppContractMethod(&callee)
				if method == "" {
					continue
				}
				arity := len(call.Arguments)
				key := method + "#" + strconv.Itoa(arity)
				got := kb.ContractsFor(method, arity)
				if negative[key] {
					if len(got) != 0 {
						t.Fatalf("%s resolved to %d contract(s), want none", key, len(got))
					}
					seen[key] = true
					continue
				}
				role, expected := want[key]
				if !expected {
					continue
				}
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one cotp contract", method, arity, len(got))
				}
				if got[0].Role != role || got[0].SourceLibrary != "cotp" {
					t.Fatalf("contract for %q = role %q library %q, want cotp %s", key, got[0].Role, got[0].SourceLibrary, role)
				}
				seen[key] = true
			}
		}
	}

	for key := range want {
		if !seen[key] {
			t.Fatalf("parsed calls did not cover %q", key)
		}
	}
	for key := range negative {
		if !seen[key] {
			t.Fatalf("parsed calls did not cover negative %q", key)
		}
	}
}
