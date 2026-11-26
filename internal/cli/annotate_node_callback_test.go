//go:build !windows

// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import "testing"

// A random draw whose callback starts on the draw's own line: the draw
// belongs to makeSalt, which encloses it, not to the callback that starts
// after it on that line.
const annotateNodeCallback = `const crypto = require("crypto");

function makeSalt(cb) {
    crypto.randomBytes(16, function(err, buf) {
        keep(buf, cb);
    });
}

function keep(buf, cb) {
    cb(buf);
}

module.exports = { makeSalt };
`

// annotate of a stored Node graph attributes a crypto call that takes a
// callback to the function that makes it, as the scan that stored the graph
// did: the stored functions keep their columns.
func TestAnnotateNodeCallbackWritesTheScanFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	annotateNodeRoundTrip(t, map[string]string{"package.json": `{"name": "acme", "version": "1.0.0"}`, "salt.js": annotateNodeCallback}, "acme-random")
}
