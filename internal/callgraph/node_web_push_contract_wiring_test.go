// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// A module-function call has no receiver variable, so the contract's visible
// effect is the type a function returns through it. notify returns what
// sendNotification returns, and the push result reaches the export as the
// function's inferred return.
func TestNodeWebPushContractTypesFunctionsThatReturnItsResults(t *testing.T) {
	t.Parallel()

	graph := buildNodeGraph(t, `const webpush = require('web-push');
const { generateRequestDetails } = require('web-push');

function notify(subscription, payload) {
  return webpush.sendNotification(subscription, payload);
}

function details(subscription, payload) {
  return generateRequestDetails(subscription, payload, { TTL: 60 });
}

function keys() {
  return webpush.generateVAPIDKeys();
}

function other(subscription) {
  return webpush.setGCMAPIKey(subscription);
}
`)
	want := map[string]string{
		"notify":  "web-push.SendResult",
		"details": "web-push.RequestDetails",
		"keys":    "web-push.VapidKeys",
		"other":   "",
	}
	for name, typ := range want {
		var got *InferredReturn
		found := false
		for _, fn := range graph.Functions {
			if fn.ID.Name == name {
				got, found = fn.InferredReturn, true
			}
		}
		if !found {
			t.Fatalf("function %s not found", name)
		}
		switch {
		case typ == "" && got != nil:
			t.Errorf("%s: inferred return %q, want none (setGCMAPIKey is not contracted)", name, got.Type)
		case typ != "" && (got == nil || got.Type != typ || got.Origin != "kb-direct"):
			t.Errorf("%s: inferred return = %+v, want %s from the knowledge base", name, got, typ)
		}
	}
}
