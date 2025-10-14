package skip

// SkipMatcher is an interface that defines a matcher for skipping files and directories.
type SkipMatcher interface {
	// ShouldSkip returns true if the given path should be skipped.
	ShouldSkip(path string, isDir bool) bool
}
