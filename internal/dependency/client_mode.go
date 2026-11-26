// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import "os"

// ClientMode reports whether the scan runs as the client of the client-server
// split (prototype knob CRYPTO_FINDER_CLIENT_MODE=1): dependencies are resolved
// to their pinned versions and compiled artifacts only. Their sources are not
// fetched, scanned or parsed; the server answers for them from mined graphs.
func ClientMode() bool {
	return os.Getenv("CRYPTO_FINDER_CLIENT_MODE") == "1"
}
