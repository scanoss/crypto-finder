package callgraph

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// cHeaderMaxBytes keeps one huge generated header from being parsed. A header
// over it counts as an unresolved include. A variable so tests can lower it.
var cHeaderMaxBytes int64 = 2 << 20

const (
	// cIncludeDepth bounds how deep a chain of local includes is followed. A
	// chain that runs past it leaves every header define unresolved.
	cIncludeDepth = 8
	// cHeaderCacheMax bounds the parsed-header cache of one parser.
	cHeaderCacheMax = 4096

	cNodePreprocInclude = "preproc_include"
	cNodeStringLiteral  = "string_literal"
)

// cLocalInclude is a quoted #include that resolved to a file on disk.
type cLocalInclude struct {
	path        string
	line        int
	conditional bool
}

// cHeader is what one parsed header contributes: its define scan and the local
// headers it includes in turn.
type cHeader struct {
	scan       cDefineScan
	includes   []cLocalInclude
	unresolved cUnresolved
}

// cUnresolved lists the lines of the quoted includes that name no readable
// file in the repo (an absolute path, a generated header not on disk). Such a
// header may redefine or #undef anything, so a define cannot be trusted past one.
type cUnresolved []int

// kills reports whether an unresolved include sits strictly between a define
// and a use.
func (u cUnresolved) kills(defineLine, useLine int) bool {
	for _, line := range u {
		if defineLine < line && line < useLine {
			return true
		}
	}
	return false
}

// cHeaderCache parses each header at most once per parser, however many files
// include it.
type cHeaderCache struct {
	byPath map[string]*cHeader
}

func (c *cHeaderCache) load(parser *sitter.Parser, path string) *cHeader {
	if h, ok := c.byPath[path]; ok {
		return h
	}
	if c.byPath == nil || len(c.byPath) >= cHeaderCacheMax {
		c.byPath = make(map[string]*cHeader)
	}
	c.byPath[path] = nil
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > cHeaderMaxBytes {
		return nil
	}
	src, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	tree, err := parser.ParseCtx(context.TODO(), nil, src)
	if err != nil {
		return nil
	}
	defer tree.Close()
	root := tree.RootNode()
	includes, unresolved := cLocalIncludes(root, src, path)
	h := &cHeader{scan: collectCDefines(root, src), includes: includes, unresolved: unresolved}
	c.byPath[path] = h
	return h
}

// cLocalIncludes lists the quoted includes of a file that resolve, relative to
// the including file's directory, to a regular file, and the lines of the
// quoted includes that resolve to none. Angle-bracket includes name system
// headers and are out of scope.
func cLocalIncludes(root *sitter.Node, src []byte, file string) ([]cLocalInclude, cUnresolved) {
	guard := cIncludeGuard(root, src)
	var includes []cLocalInclude
	var unresolved cUnresolved
	walkCNodes(root, func(n *sitter.Node) {
		line := int(n.StartPoint().Row) + 1
		if cOpaqueIncludeDirective(n, src) {
			unresolved = append(unresolved, line)
			return
		}
		if n.Type() != cNodePreprocInclude {
			return
		}
		path := n.ChildByFieldName("path")
		if path == nil {
			unresolved = append(unresolved, line)
			return
		}
		switch path.Type() {
		case cNodeStringLiteral:
		case "system_lib_string":
			return
		default:
			// #include MACRO and other computed includes name a file the
			// scan cannot know.
			unresolved = append(unresolved, line)
			return
		}
		rel := strings.Trim(strings.TrimSpace(path.Content(src)), `"`)
		target := filepath.Join(filepath.Dir(file), rel)
		if rel == "" || strings.ContainsAny(rel, `\`) || filepath.IsAbs(rel) || strings.HasPrefix(rel, "/") {
			unresolved = append(unresolved, line)
			return
		}
		if info, err := os.Stat(target); err != nil || !info.Mode().IsRegular() {
			unresolved = append(unresolved, line)
			return
		}
		includes = append(includes, cLocalInclude{
			path:        target,
			line:        line,
			conditional: cConditional(n, guard),
		})
	})
	return includes, unresolved
}

// cOpaqueIncludeDirective reports whether n is an #include_next or #import,
// which the grammar parses as a generic directive: the file they name is not
// followed, so whatever it defines is unknown.
func cOpaqueIncludeDirective(n *sitter.Node, src []byte) bool {
	if n.Type() != cNodePreprocCall {
		return false
	}
	directive := n.ChildByFieldName("directive")
	if directive == nil {
		return false
	}
	switch strings.TrimSpace(directive.Content(src)) {
	case "#include_next", "#import":
		return true
	}
	return false
}

// cIncludedFile is one header reached from the including file. line is the
// earliest line of the including file from which its defines are visible, and
// unconditional is false when every path to it sits under a conditional.
type cIncludedFile struct {
	header        *cHeader
	line          int
	unconditional bool
	// active is set while the file's includes are being followed, so a cycle
	// back to it counts as unknown.
	active bool
	// unreadable is set when the file exists but was too large, unreadable or
	// unparsable: it counts as an unresolved include at the line that names it.
	unreadable bool
	// dirtyLines are the lines of the header at which an include it makes, or
	// anything reachable through one, names no file: a define of the header
	// at or before such a line may have been undone.
	dirtyLines []int
}

// cIncludeScope is the transitive closure of the local headers a file
// includes, built once per file.
type cIncludeScope struct {
	files     map[string]*cIncludedFile
	truncated bool
	// dirtyTop are the lines of the including file whose include leads to an
	// unresolved include anywhere beneath it.
	dirtyTop cUnresolved
}

func newCIncludeScope(parser *sitter.Parser, cache *cHeaderCache, includes []cLocalInclude) *cIncludeScope {
	if len(includes) == 0 {
		return nil
	}
	scope := &cIncludeScope{files: make(map[string]*cIncludedFile)}
	for _, inc := range includes {
		if scope.visit(parser, cache, inc.path, inc.line, !inc.conditional, 1) {
			scope.dirtyTop = append(scope.dirtyTop, inc.line)
		}
	}
	return scope
}

// visit follows one include and reports whether an unresolved include sits
// anywhere beneath it.
func (s *cIncludeScope) visit(parser *sitter.Parser, cache *cHeaderCache, path string, line int, unconditional bool, depth int) bool {
	if depth > cIncludeDepth {
		s.truncated = true
		return true
	}
	file, seen := s.files[path]
	if !seen {
		file = &cIncludedFile{header: cache.load(parser, path), line: line, unconditional: unconditional}
		s.files[path] = file
	} else {
		if file.active {
			return true
		}
		improved := false
		if unconditional && (!file.unconditional || line < file.line) {
			file.unconditional, file.line, improved = true, line, true
		}
		if !improved {
			return file.unreadable || len(file.dirtyLines) > 0
		}
	}
	if file.header == nil {
		// The file exists but could not be read in full: whatever it defines
		// or undefines is unknown.
		file.unreadable = true
		return true
	}
	file.active = true
	file.dirtyLines = append([]int(nil), file.header.unresolved...)
	for _, inc := range file.header.includes {
		if s.visit(parser, cache, inc.path, file.line, file.unconditional && !inc.conditional, depth+1) {
			file.dirtyLines = append(file.dirtyLines, inc.line)
		}
	}
	file.active = false
	return len(file.dirtyLines) > 0
}

// touches counts the distinct included files that define, redefine or #undef
// name in any way.
func (s *cIncludeScope) touches(name string) int {
	count := 0
	for _, file := range s.files {
		if file.header == nil {
			continue
		}
		if _, ok := file.header.scan.touched[name]; ok {
			count++
		}
	}
	return count
}

// literal returns the header define for name when exactly one included file
// touches it, that file always reaches the including file, defines it as an
// unconditional literal, and the including file does not define it before the
// header could. ownTouch is the including file's own first define or #undef of
// name, 0 when it has none.
func (s *cIncludeScope) literal(name string, ownTouch int) (cDefine, bool) {
	if s.truncated || s.touches(name) != 1 {
		return cDefine{}, false
	}
	for _, file := range s.files {
		if file.header == nil || !file.unconditional {
			continue
		}
		define, ok := file.header.scan.literals[name]
		if !ok || file.undoneAfter(define.line) {
			continue
		}
		if ownTouch != 0 && ownTouch < file.line {
			return cDefine{}, false
		}
		return cDefine{value: define.value, line: file.line, until: ownTouch}, true
	}
	return cDefine{}, false
}

// undoneAfter reports whether an unresolved include may run at or after line.
func (f *cIncludedFile) undoneAfter(line int) bool {
	for _, dirty := range f.dirtyLines {
		if dirty >= line {
			return true
		}
	}
	return false
}
