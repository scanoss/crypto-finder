// Package cryptokb is crypto-finder's knowledge base of cryptographic library
// APIs: the contract YAML files, one directory per ecosystem, that the
// callgraph engine loads through internal/callgraph/contracts.
//
// Importing this package installs the KB as the engine's contracts source
// (contracts.SetSource) and its language-level hints (contracts.SetHints),
// the way an image format package registers its
// decoder. Every crypto-finder entry point that builds a call graph imports
// it; the engine itself stays free of crypto knowledge.
package cryptokb

import (
	"embed"

	"github.com/scanoss/reach/callgraph/contracts"
)

//go:embed c/*.yaml cpp/*.yaml go/*.yaml java/*.yaml node/*.yaml python/*.yaml rust/*.yaml
var files embed.FS

func init() {
	contracts.SetSource(files)
	contracts.SetHints(hints)
}

// Load returns the merged crypto KB of one ecosystem. It is
// contracts.ForEcosystem over the installed crypto KB.
func Load(ecosystem string) (*contracts.KnowledgeBase, error) {
	return contracts.ForEcosystem(ecosystem)
}
