// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedNodeOTPLib(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	type want struct {
		method string
		arity  int
		typ    string
		role   string
	}
	for _, w := range []want{
		// 6.x to 12.x instances, and the 6.x to 11.x subpath modules.
		{"otplib.authenticator.generate", 1, "string", "operation"},
		{"otplib.authenticator.check", 2, "boolean", "operation"},
		{"otplib.authenticator.generateSecret", 0, "string", "operation"},
		{"otplib.totp.verify", 1, "boolean", "operation"},
		{"otplib.hotp.generate", 2, "string", "operation"},
		{"otplib.hotp.check", 3, "boolean", "operation"},
		{"otplib/authenticator.generate", 1, "string", "operation"},
		{"otplib/totp.check", 2, "boolean", "operation"},
		{"otplib/hotp.generate", 2, "string", "operation"},
		// 13.x functions and classes.
		{"otplib.generate", 1, "string", "operation"},
		{"otplib.generateSync", 1, "string", "operation"},
		{"otplib.verify", 1, "VerifyResult", "operation"},
		{"otplib.generateSecret", 0, "string", "operation"},
		{"otplib.TOTP.<init>", 1, "otplib.TOTP", "factory"},
		{"otplib.HOTP.<init>", 0, "otplib.HOTP", "factory"},
		{"otplib.OTP.<init>", 1, "otplib.OTP", "factory"},
		{"otplib.TOTP.verify", 1, "VerifyResult", "operation"},
		// The counter comes first on the 13.x HOTP object.
		{"otplib.HOTP.generate", 1, "string", "operation"},
		{"otplib.OTP.verifySync", 1, "VerifyResult", "operation"},
	} {
		got := kb.ContractsFor(w.method, w.arity)
		if len(got) == 0 {
			t.Errorf("%s#%d resolved nothing", w.method, w.arity)
			continue
		}
		if got[0].Return.Type != w.typ || got[0].Role != w.role {
			t.Errorf("%s#%d = (%q, %q), want (%q, %q)", w.method, w.arity, got[0].Return.Type, got[0].Role, w.typ, w.role)
		}
	}

	// Provisioning-URI formatting and Base32 helpers compute no token.
	for _, unwanted := range []string{
		"otplib.authenticator.keyuri#3",
		"otplib.authenticator.encode#1",
		"otplib.authenticator.decode#1",
		"otplib.generateURI#1",
		"otplib.TOTP.toURI#0",
		"otplib.HOTP.toURI#1",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "otplib", "otplib")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "otplib") {
			n++
		}
	}
	if n != 54 {
		t.Errorf("otplib contributes %d keys, want 54", n)
	}
}

func TestLoadEmbeddedNodeOTPLibCore(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	type want struct {
		method string
		arity  int
		typ    string
		role   string
	}
	for _, w := range []want{
		{"@otplib/core.HOTP.<init>", 1, "@otplib/core.HOTP", "factory"},
		{"@otplib/core.TOTP.<init>", 0, "@otplib/core.TOTP", "factory"},
		{"@otplib/core.Authenticator.<init>", 1, "@otplib/core.Authenticator", "factory"},
		{"@otplib/core.HOTP.generate", 2, "string", "operation"},
		{"@otplib/core.TOTP.check", 2, "boolean", "operation"},
		{"@otplib/core.Authenticator.generateSecret", 0, "string", "operation"},
		{"@otplib/core.hotpToken", 3, "string", "operation"},
		{"@otplib/core.hotpCheck", 4, "boolean", "operation"},
		{"@otplib/core.totpToken", 2, "string", "operation"},
		{"@otplib/core.totpCheckWithWindow", 3, "number", "operation"},
		{"@otplib/core.authenticatorGenerateSecret", 2, "string", "operation"},
		// 13.x: one options object carrying the crypto plugin.
		{"@otplib/core.generateSecret", 1, "string", "operation"},
	} {
		got := kb.ContractsFor(w.method, w.arity)
		if len(got) == 0 {
			t.Errorf("%s#%d resolved nothing", w.method, w.arity)
			continue
		}
		if got[0].Return.Type != w.typ || got[0].Role != w.role {
			t.Errorf("%s#%d = (%q, %q), want (%q, %q)", w.method, w.arity, got[0].Return.Type, got[0].Role, w.typ, w.role)
		}
	}

	for _, unwanted := range []string{
		"@otplib/core.hotpKeyuri#5",
		"@otplib/core.totpKeyuri#4",
		"@otplib/core.hotpCounter#1",
		"@otplib/core.TOTP.timeRemaining#0",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "otplib-core", "@otplib/core.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "@otplib/core.") {
			n++
		}
	}
	if n != 28 {
		t.Errorf("otplib-core contributes %d keys, want 28", n)
	}
}
