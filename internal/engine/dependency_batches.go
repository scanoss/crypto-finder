package engine

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

// maxBatchRoots caps the roots one scanner process scans. It bounds the wait
// before a failed process falls back to single scans and the rescans that
// fallback costs; sixteen roots already share one rule load.
const maxBatchRoots = 16

// depWork is a scannable dependency waiting for its scan. The cache lookup
// fills opts, cacheKey, scanner and scope, then the scan fills weight.
type depWork struct {
	index    int
	key      string
	dep      dependency.Dependency
	opts     ScanOptions
	cacheKey string
	scanner  scanner.Scanner
	weight   int64
	// scope limits the scan to the files of the dependency's imported
	// packages; nil scans the whole dependency.
	scope *scanner.DetectionScope
}

// scanBatch is one scanner process over several dependency roots.
type scanBatch struct {
	items  []depWork
	weight int64
}

// shapeBatches groups work into the processes that scan it. Roots that nest
// cannot share a process, because the outer root's exclusions hide the inner
// one, unless they are disjoint siblings of one directory, so each nesting
// level is split on its own into
// max(ceil(n / maxBatchRoots), min(workers, n)) batches: the heaviest work
// goes first, each item into the lightest batch, so the workers finish
// together and a very large dependency keeps a process to itself. The
// batches come heaviest first.
func shapeBatches(work []depWork, workers int) []scanBatch {
	roots := make([]scanner.Root, len(work))
	for i := range work {
		roots[i] = scanner.Root{Dir: filepath.Clean(work[i].dep.Dir), Scope: work[i].scope}
	}
	levels := nestingLevels(roots)
	byLevel := make(map[int][]depWork)
	for i := range work {
		byLevel[levels[i]] = append(byLevel[levels[i]], work[i])
	}
	batches := make([]scanBatch, 0, len(work))
	for level := 0; level < len(byLevel); level++ {
		batches = append(batches, balance(byLevel[level], workers)...)
	}
	sort.SliceStable(batches, func(i, j int) bool { return batches[i].weight > batches[j].weight })
	return batches
}

// balance spreads items over batches, heaviest first, each into the batch
// with the least weight, then the fewest items, that still has room.
func balance(items []depWork, workers int) []scanBatch {
	if len(items) == 0 {
		return nil
	}
	ordered := slices.Clone(items)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].weight > ordered[j].weight })
	count := max((len(items)+maxBatchRoots-1)/maxBatchRoots, min(workers, len(items)))
	batches := make([]scanBatch, count)
	for i := range ordered {
		target := -1
		for b := range batches {
			if len(batches[b].items) >= maxBatchRoots {
				continue
			}
			if target < 0 || batches[b].weight < batches[target].weight ||
				(batches[b].weight == batches[target].weight && len(batches[b].items) < len(batches[target].items)) {
				target = b
			}
		}
		batches[target].items = append(batches[target].items, ordered[i])
		batches[target].weight += ordered[i].weight
	}
	return batches
}

// nestingLevels gives each root its depth among roots: 0 when no other root
// holds it, otherwise one more than the level of the nearest root that does.
// A root holds every path below its Dir at a separator and an equal Dir, an
// earlier root holding a later one, unless the two are disjoint siblings.
func nestingLevels(roots []scanner.Root) []int {
	dirs := make([]string, len(roots))
	for i := range roots {
		dirs[i] = filepath.Clean(roots[i].Dir)
	}
	parent := make([]int, len(dirs))
	for i, dir := range dirs {
		parent[i] = -1
		for j, other := range dirs {
			if j == i || !holdsDir(other, dir) || (other == dir && (j > i || scanner.DisjointSiblings(roots[i], roots[j]))) {
				continue
			}
			if parent[i] < 0 || len(other) > len(dirs[parent[i]]) || (len(other) == len(dirs[parent[i]]) && j > parent[i]) {
				parent[i] = j
			}
		}
	}
	levels := make([]int, len(dirs))
	for i := range dirs {
		for j := parent[i]; j >= 0; j = parent[j] {
			levels[i]++
		}
	}
	return levels
}

func holdsDir(root, path string) bool {
	return strings.HasPrefix(path, root) && (len(path) == len(root) || os.IsPathSeparator(path[len(root)]))
}

// batchScanOptions returns the options of one process over members: the
// first member's, with every member's skip patterns (each dependency's own
// exclusions among them) and the process timeout scaled for the batch.
func batchScanOptions(members []ScanOptions) ScanOptions {
	opts := members[0]
	patterns := make([]string, 0, len(opts.ScannerConfig.SkipPatterns)+len(members))
	seen := make(map[string]bool)
	for i := range members {
		for _, pattern := range members[i].ScannerConfig.SkipPatterns {
			if !seen[pattern] {
				seen[pattern] = true
				patterns = append(patterns, pattern)
			}
		}
	}
	opts.ScannerConfig.SkipPatterns = patterns
	opts.ScannerConfig.Timeout = batchTimeout(opts.ScannerConfig.Timeout, len(members), effectiveJobs(opts.ScannerConfig))
	return opts
}

// batchTimeout gives a process over roots the single-scan timeout once per
// ceil(roots / jobs): the scanner analyzes jobs files at a time, so the roots
// consume about that many single-scan budgets of wall time.
func batchTimeout(single time.Duration, roots, jobs int) time.Duration {
	return single * time.Duration((roots+jobs-1)/jobs)
}

// effectiveJobs is the parallelism the scanner process will run with: a
// --jobs in ExtraArgs wins over Jobs, as it does on the command line, and
// zero is the scanner's default of one job per core.
func effectiveJobs(config scanner.Config) int {
	jobs := int(config.Jobs)
	for i, arg := range config.ExtraArgs {
		value := ""
		switch {
		case (arg == "--jobs" || arg == "-j") && i+1 < len(config.ExtraArgs):
			value = config.ExtraArgs[i+1]
		case strings.HasPrefix(arg, "--jobs="):
			value = strings.TrimPrefix(arg, "--jobs=")
		case strings.HasPrefix(arg, "-j") && len(arg) > 2:
			value = arg[2:]
		default:
			continue
		}
		if n, err := strconv.Atoi(value); err == nil {
			jobs = n
		}
	}
	if jobs <= 0 {
		return runtime.NumCPU()
	}
	return jobs
}

// sourceExtensions name the files that count toward a dependency's weight,
// per language hint. The weight only shapes batches, so it needs no more
// precision than this.
var sourceExtensions = map[string][]string{
	"go":         {".go"},
	"python":     {".py"},
	"java":       {".java"},
	"rust":       {".rs"},
	"c":          {".c", ".h"},
	"javascript": {".js", ".jsx", ".mjs", ".cjs"},
	"typescript": {".ts", ".tsx", ".mts", ".cts"},
}

// sourceWeight sums the bytes of the source files in languages that a scan of
// dir limited to scope reads: the scope's files, or with no scope every file
// below dir, not descending into nested node_modules, which other
// dependencies own. The root may be a symlink (pnpm installs are). What
// cannot be read weighs nothing.
func sourceWeight(dir string, scope *scanner.DetectionScope, languages []string) int64 {
	counted := make(map[string]bool)
	for _, language := range languages {
		for _, ext := range sourceExtensions[language] {
			counted[ext] = true
		}
	}
	if scope != nil {
		return scopedSourceWeight(dir, scope, counted)
	}
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	var total int64
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return skipUnreadable(entry, err)
		}
		if entry.IsDir() {
			if path != dir && entry.Name() == "node_modules" {
				return fs.SkipDir
			}
			return nil
		}
		if !counted[filepath.Ext(entry.Name())] {
			return nil
		}
		if info, infoErr := entry.Info(); infoErr == nil {
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		return 0
	}
	return total
}

func scopedSourceWeight(dir string, scope *scanner.DetectionScope, counted map[string]bool) int64 {
	var total int64
	for _, rel := range scope.Paths {
		if !counted[filepath.Ext(rel)] {
			continue
		}
		if info, err := os.Stat(filepath.Join(dir, rel)); err == nil {
			total += info.Size()
		}
	}
	return total
}

// skipUnreadable stops a walk at an unreadable root, steps over an unreadable
// directory and ignores an unreadable file.
func skipUnreadable(entry fs.DirEntry, err error) error {
	if entry == nil {
		return err
	}
	if entry.IsDir() {
		return fs.SkipDir
	}
	return nil
}
