// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package skip

import (
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
)

// builtOutputDirs are the DefaultSkippedDirs that hold compiler output rather
// than a third party's code. They are the only names eligible to be rescued by
// BuiltOutputOnlySource: `node_modules` and `vendor` hold other packages, and
// `docs` holds prose, so none of those is ever the artifact under scan.
var builtOutputDirs = []string{"dist", "build"}

// sourceExtensions are the file kinds that make a directory "source". The set is
// deliberately about CODE, not about files: a package that ships package.json,
// a README and a LICENSE beside dist/ has shipped no source outside dist, and
// treating those three as source would defeat the whole check.
var sourceExtensions = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".jsx": true,
	".ts": true, ".tsx": true, ".mts": true, ".cts": true,
	".go": true, ".py": true, ".rs": true, ".rb": true,
	".java": true, ".kt": true, ".scala": true, ".cs": true,
	".c": true, ".cc": true, ".cpp": true, ".cxx": true,
	".h": true, ".hh": true, ".hpp": true,
	".m": true, ".mm": true, ".swift": true, ".php": true,
}

// declarationSuffixes are TypeScript declaration files. They carry types and no
// executable code, so a package shipping `dist/` plus a root `index.d.ts` --
// an ordinary published layout -- has shipped no source outside dist. Counting
// one as source would leave the scan reading a declaration file and reporting
// the same ambiguous zero this check exists to remove.
var declarationSuffixes = []string{".d.ts", ".d.mts", ".d.cts"}

// extraRescueIgnoredDirs are directory names the pre-pass ignores on top of
// DefaultSkippedDirs. Source under these cannot be the reason to keep an
// exclusion, because the scan that follows will not read it either:
// DefaultSkippedTestPatterns removes them.
var extraRescueIgnoredDirs = []string{"test", "tests", "__tests__"}

// maxBuiltOutputWalk bounds the pre-pass. The question it answers is "is there
// ANY source outside the built-output directories", which the first hit
// settles, so the walk stops early in the common case and this cap only ever
// binds on a pathological tree.
const maxBuiltOutputWalk = 50000

// BuiltOutputOnlySource reports which built-output directory names hold the
// only source in targetDir, and so must NOT be excluded from the scan.
//
// A PUBLISHED PACKAGE IS NOT A CHECKOUT. `dist` and `build` are generated noise
// beside sources in a repository, which is why they are in DefaultSkippedDirs.
// In a published npm tarball they are frequently everything there is -- the
// modern default for a TypeScript package -- and excluding them makes the
// scanner read nothing and report no cryptography.
//
// Measured on @azure/cosmos 4.10.1, which ships only dist/: the same scan with
// the same rules reported 0 findings by default and 6 with the exclusion
// lifted. The danger is not the missing six. It is that a zero meaning "nobody
// read this tree" is indistinguishable from one meaning "no cryptography here",
// and the second is what reaches a coverage tracker.
//
// The check is deliberately conservative in both directions. It only fires when
// the exclusion would otherwise leave NOTHING: one source file anywhere the
// scan would actually read keeps the defaults exactly as they were. And it
// abstains -- returning nil, the defaults -- whenever the walk could not answer
// the question: an unreadable directory or a tree past the entry cap leaves a
// PARTIAL picture, and acting on a partial picture is how a plain checkout ends
// up with its generated output scanned.
func BuiltOutputOnlySource(targetDir string) []string {
	return builtOutputOnlySource(targetDir, maxBuiltOutputWalk)
}

// builtOutputOnlySource is BuiltOutputOnlySource with the entry cap as an
// argument, so a test can bind the cap without a shared variable.
func builtOutputOnlySource(targetDir string, maxEntries int) []string {
	root := filepath.Clean(targetDir)
	scan := builtOutputScan{
		root:       root,
		present:    map[string]bool{},
		maxEntries: maxEntries,
	}
	// A target named AT a built-output directory is that directory. Excluding
	// it would leave the scan nothing to read, and the operator pointed the
	// scanner there on purpose. `scan pkg/dist` and `scan pkg/dist/index.js`
	// (which the CLI maps to its parent) both arrive here.
	if base := filepath.Base(root); slices.Contains(builtOutputDirs, base) {
		scan.rootIsBuiltOutput = base
	}

	// WalkDir surfaces nothing but what visit returns, and visit returns only
	// fs.SkipAll or fs.SkipDir, so this is a guard rather than the error path:
	// an unreadable directory is recorded on the scan by visit itself.
	if err := filepath.WalkDir(root, scan.visit); err != nil {
		return nil
	}
	if scan.abandoned || scan.sourceOutside || len(scan.present) == 0 {
		return nil
	}
	out := make([]string, 0, len(scan.present))
	for name := range scan.present {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// builtOutputScan carries the state of one BuiltOutputOnlySource walk: which
// built-output directories hold source, whether any source was found outside
// them -- the single fact that settles the question -- and whether the walk
// was cut short before it could answer.
type builtOutputScan struct {
	root              string
	rootIsBuiltOutput string
	maxEntries        int
	present           map[string]bool
	sourceOutside     bool
	abandoned         bool
	seen              int
}

// visit is the WalkDir callback. It stops the walk as soon as the answer is
// known, which for a checkout is the first source file it meets.
func (c *builtOutputScan) visit(path string, d fs.DirEntry, err error) error {
	if err != nil {
		// An unreadable directory hides whatever source it holds, so the walk
		// cannot show that the built output is the only source. Note it: on
		// its own, fs.SkipAll makes WalkDir return nil and a partial answer
		// would read as a complete one.
		c.abandoned = true
		return fs.SkipAll
	}
	if c.sourceOutside {
		return fs.SkipAll
	}
	c.seen++
	if c.seen > c.maxEntries {
		c.abandoned = true
		return fs.SkipAll
	}
	rel, relErr := filepath.Rel(c.root, path)
	if relErr != nil {
		c.abandoned = true
		return fs.SkipAll
	}
	if d.IsDir() {
		return c.visitDir(rel, d.Name())
	}
	if !isSourceFile(path) {
		return nil
	}
	if c.rootIsBuiltOutput != "" {
		c.present[c.rootIsBuiltOutput] = true
		return fs.SkipAll
	}
	// Only a TOP-LEVEL built-output directory can be the artifact. A `dist`
	// nested under real source -- packages/x/dist beside packages/x/src -- is
	// generated noise exactly as it is in a checkout.
	if top, nested := topSegment(rel); nested && slices.Contains(builtOutputDirs, top) {
		c.present[top] = true
		return nil
	}
	c.sourceOutside = true
	return fs.SkipAll
}

// visitDir decides whether to descend. It skips what the scan that follows
// would skip anyway, so source the scanner will never read cannot be the
// reason an exclusion stays in place.
func (c *builtOutputScan) visitDir(rel, name string) error {
	if rel == "." {
		return nil
	}
	// Hidden directories: the callgraph builder skips these, and no published
	// package ships its sources under one.
	if strings.HasPrefix(name, ".") {
		return fs.SkipDir
	}
	if slices.Contains(builtOutputDirs, name) {
		return nil
	}
	// node_modules holds other packages, test directories are excluded by
	// DefaultSkippedTestPatterns, and the rest are the defaults themselves.
	// Installing dependencies before a scan must not cancel the rescue.
	if slices.Contains(DefaultSkippedDirs, name) || slices.Contains(extraRescueIgnoredDirs, name) {
		return fs.SkipDir
	}
	return nil
}

// isSourceFile reports whether path is code, as opposed to metadata, prose, or
// a type declaration.
func isSourceFile(path string) bool {
	lower := strings.ToLower(filepath.Base(path))
	for _, suffix := range declarationSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return false
		}
	}
	return sourceExtensions[filepath.Ext(lower)]
}

// topSegment returns the first path segment of a walk-relative path, and
// whether the path is nested below that segment rather than being it.
func topSegment(rel string) (string, bool) {
	segments := strings.Split(filepath.ToSlash(rel), "/")
	if len(segments) < 2 {
		return "", false
	}
	return segments[0], true
}

// DefaultPatternsForTarget returns DefaultPatterns with any built-output
// directory that holds the only source removed, so the scan reads the artifact
// instead of skipping it. For a checkout it returns DefaultPatterns unchanged.
func DefaultPatternsForTarget(targetDir string) []string {
	return withoutPatterns(DefaultPatterns(), BuiltOutputOnlySource(targetDir))
}

// withoutPatterns returns patterns with every name in drop removed. Returns
// patterns untouched when drop is empty, which is the common case.
func withoutPatterns(patterns, drop []string) []string {
	if len(drop) == 0 {
		return patterns
	}
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		if !slices.Contains(drop, p) {
			out = append(out, p)
		}
	}
	return out
}
