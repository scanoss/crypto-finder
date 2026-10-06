package callgraph

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// goSourceMaxBytes bounds one sibling file read for the package index.
const goSourceMaxBytes = 2 << 20

var errSourceTooLarge = errors.New("go source file too large")

const (
	goNodePackageClause = "package_clause"
	goNodeTypeAlias     = "type_alias"
)

var (
	goKnownOS = toSet("aix", "android", "darwin", "dragonfly", "freebsd", "hurd", "illumos", "ios",
		"js", "linux", "nacl", "netbsd", "openbsd", "plan9", "solaris", "wasip1", "windows", "zos")
	goKnownArch = toSet("386", "amd64", "amd64p32", "arm", "armbe", "arm64", "arm64be", "loong64",
		"mips", "mipsle", "mips64", "mips64le", "mips64p32", "mips64p32le", "ppc", "ppc64", "ppc64le",
		"riscv", "riscv64", "s390", "s390x", "sparc", "sparc64", "wasm")
	goUniverseValues = toSet("nil", "true", "false", "iota")
)

func toSet(items ...string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, item := range items {
		set[item] = true
	}
	return set
}

// goPackageEntry is one package-level declaration of a name in one file.
type goPackageEntry struct {
	file        string
	test        bool
	conditional bool
	kind        goDeclKind
	value       string
}

// goPackageIndex lists, per package clause, every package-level name the .go
// files of one directory declare. It is built at most once per directory, the
// first time an identifier argument resolves to nothing in its own file, so a
// directory that never needs it is never read twice.
type goPackageIndex struct {
	dir   string
	built bool
	// unknown is set when a sibling could not be read in full: it may declare
	// any name, so nothing resolves against the package.
	unknown   bool
	byPackage map[string]map[string][]goPackageEntry
}

func newGoPackageIndex(dir string) *goPackageIndex {
	return &goPackageIndex{dir: filepath.Clean(dir)}
}

// lookup resolves name, used in file (declared in package pkg), to a literal
// declared by another file of the package. It answers only when exactly one
// file in the package declares the name at package level, that declaration is
// a literal const, and that file is built under every configuration: a name
// declared twice (a const per build tag, or a var, func or type beside a const)
// or declared in a conditionally built file is unknown. A _test.go file's
// declarations are visible only from a _test.go file.
func (x *goPackageIndex) lookup(parser *sitter.Parser, file, pkg string, test bool, name string) (string, bool) {
	if !x.built {
		x.build(parser)
	}
	if x.unknown {
		return "", false
	}
	var found *goPackageEntry
	entries := x.byPackage[pkg][name]
	for i := range entries {
		e := &entries[i]
		if e.file == file || (e.test && !test) {
			continue
		}
		if found != nil {
			return "", false
		}
		found = e
	}
	if found == nil || found.conditional || found.kind != goDeclLiteral {
		return "", false
	}
	return found.value, true
}

func (x *goPackageIndex) build(parser *sitter.Parser) {
	x.built = true
	x.byPackage = make(map[string]map[string][]goPackageEntry)
	entries, err := os.ReadDir(x.dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		path := filepath.Join(x.dir, name)
		src, err := readBounded(path)
		if err != nil {
			x.unknown = true
			return
		}
		tree, err := parser.ParseCtx(context.TODO(), nil, src)
		if err != nil {
			x.unknown = true
			return
		}
		x.addFile(path, name, tree.RootNode(), src)
		tree.Close()
	}
}

// readBounded reads a source file no larger than goSourceMaxBytes.
func readBounded(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > goSourceMaxBytes {
		return nil, errSourceTooLarge
	}
	return os.ReadFile(path)
}

func (x *goPackageIndex) addFile(path, name string, root *sitter.Node, src []byte) {
	pkg := ""
	conditional := goFileNameConstrained(name)
	idx := make(map[string][]goDecl)
	for i := 0; i < int(root.NamedChildCount()); i++ {
		n := root.NamedChild(i)
		switch n.Type() {
		case goNodePackageClause:
			pkg = goPackageClauseName(n, src)
		case goNodeComment:
			conditional = conditional || (pkg == "" && goBuildConstraintComment(n.Content(src)))
		default:
			goCollectPackageNames(n, src, idx)
		}
	}
	if pkg == "" {
		return
	}
	names := x.byPackage[pkg]
	if names == nil {
		names = make(map[string][]goPackageEntry)
		x.byPackage[pkg] = names
	}
	test := strings.HasSuffix(name, "_test.go")
	for ident, decls := range idx {
		if ident == "_" {
			continue
		}
		for _, d := range decls {
			names[ident] = append(names[ident], goPackageEntry{
				file: path, test: test, conditional: conditional, kind: d.kind, value: d.value,
			})
		}
	}
}

func goPackageClauseName(clause *sitter.Node, src []byte) string {
	for j := 0; j < int(clause.NamedChildCount()); j++ {
		if c := clause.NamedChild(j); c.Type() == goNodePackageIdentifier {
			return c.Content(src)
		}
	}
	return ""
}

// goCollectPackageNames records the package-level names a top-level node
// declares: consts and vars as in a function scope, plus funcs and types.
func goCollectPackageNames(n *sitter.Node, src []byte, idx map[string][]goDecl) {
	opaque := func(id *sitter.Node) {
		if id != nil {
			idx[id.Content(src)] = append(idx[id.Content(src)], goDecl{kind: goDeclOpaque})
		}
	}
	switch n.Type() {
	case goNodeFunctionDecl:
		opaque(n.ChildByFieldName("name"))
	case goNodeTypeDeclaration:
		for j := 0; j < int(n.NamedChildCount()); j++ {
			if spec := n.NamedChild(j); spec.Type() == goNodeTypeSpec || spec.Type() == goNodeTypeAlias {
				opaque(spec.ChildByFieldName("name"))
			}
		}
	default:
		goCollectDecls(n, src, idx)
	}
}

// goBuildConstraintComment reports whether a comment above the package clause
// is a //go:build or legacy // +build line.
func goBuildConstraintComment(text string) bool {
	text = strings.TrimSpace(text)
	return strings.HasPrefix(text, "//go:build") || strings.HasPrefix(text, "// +build")
}

// goFileNameConstrained mirrors the go tool's implicit constraint from a
// _GOOS, _GOARCH or _GOOS_GOARCH file-name suffix.
func goFileNameConstrained(name string) bool {
	name = strings.TrimSuffix(strings.TrimSuffix(name, ".go"), "_test")
	i := strings.Index(name, "_")
	if i < 0 {
		return false
	}
	parts := strings.Split(name[i:], "_")
	n := len(parts)
	if n >= 2 && goKnownOS[parts[n-2]] && goKnownArch[parts[n-1]] {
		return true
	}
	return n >= 1 && (goKnownOS[parts[n-1]] || goKnownArch[parts[n-1]])
}

// bindCrossFile points the const resolver at the package index so a name no
// scope of the file declares can resolve to a const of a sibling file.
func (p *GoParser) bindCrossFile(filePath, pkg string) {
	dir := filepath.Dir(filePath)
	index := p.pkgIndex
	if index == nil || index.dir != dir {
		index = newGoPackageIndex(dir)
	}
	file := filepath.Join(dir, filepath.Base(filePath))
	test := strings.HasSuffix(filePath, "_test.go")
	p.consts.crossFile = func(name string) (string, bool) {
		if pkg == "" || goUniverseValues[name] || goPredeclaredIdentifiers[name] {
			return "", false
		}
		return index.lookup(p.parser, file, pkg, test, name)
	}
}
