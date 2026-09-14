// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"os"
	"path/filepath"
)

// embeddedPythonContract reads one python contract YAML from the source tree.
// The package's own embed.FS is unexported, and the file this reads is the
// exact one `//go:embed python/*.yaml` compiles in, so a drift between the two
// is not possible without editing the same bytes.
func embeddedPythonContract(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join("python", name))
}
