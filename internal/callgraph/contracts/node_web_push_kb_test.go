// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedNodeWebPush(t *testing.T) {
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
		{"web-push.generateVAPIDKeys", 0, "web-push.VapidKeys", "operation"},
		{"web-push.setVapidDetails", 3, "void", "config"},
		// contentEncoding arrived in 3.4.0, so both shapes of the signature exist.
		{"web-push.getVapidHeaders", 4, "web-push.VapidHeaders", "operation"},
		{"web-push.getVapidHeaders", 5, "web-push.VapidHeaders", "operation"},
		{"web-push.getVapidHeaders", 6, "web-push.VapidHeaders", "operation"},
		{"web-push.encrypt", 3, "web-push.EncryptionResult", "operation"},
		{"web-push.encrypt", 4, "web-push.EncryptionResult", "operation"},
		{"web-push.generateRequestDetails", 1, "web-push.RequestDetails", "operation"},
		{"web-push.generateRequestDetails", 3, "web-push.RequestDetails", "operation"},
		{"web-push.sendNotification", 1, "web-push.SendResult", "operation"},
		{"web-push.sendNotification", 3, "web-push.SendResult", "operation"},
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

	// A stored legacy API key is not a cryptographic step.
	if _, ok := kb.Contracts["web-push.setGCMAPIKey#1"]; ok {
		t.Error("setGCMAPIKey stores a legacy key and must not be declared")
	}

	assertLibraryOwnsItsKeys(t, kb, "web-push", "web-push.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "web-push.") {
			n++
		}
	}
	if n != 13 {
		t.Errorf("web-push contributes %d keys, want 13", n)
	}
}
