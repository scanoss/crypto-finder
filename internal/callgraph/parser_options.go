package callgraph

type parserConfig struct {
	includeTests bool
}

// ParserOption customizes parser behavior for call graph construction.
type ParserOption func(*parserConfig)

func newParserConfig(opts []ParserOption) parserConfig {
	cfg := parserConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}

// WithIncludeTests controls whether parser implementations include test files and directories.
func WithIncludeTests(include bool) ParserOption {
	return func(cfg *parserConfig) {
		cfg.includeTests = include
	}
}
