// Package contracts provides the JCA/JCE knowledge base (KB) loader and types
// for the callgraph inference engine. It defines YAML-based contract definitions
// that map method signatures to their inferred return types.
package contracts

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

//go:embed java/*.yaml
var javaFS embed.FS

//go:embed python/*.yaml
var pythonFS embed.FS

//go:embed rust/*.yaml
var rustFS embed.FS

//go:embed go/*.yaml
var goFS embed.FS

//go:embed c/*.yaml
var cFS embed.FS

const (
	// ecosystemC is the ecosystem identifier for the C contract KB.
	ecosystemC = "c"
	// ecosystemGo is the ecosystem identifier for the Go contract KB.
	ecosystemGo = "go"
	// ecosystemPython is the ecosystem identifier for the Python contract KB.
	ecosystemPython = "python"
	// ecosystemRust is the ecosystem identifier for the Rust contract KB.
	ecosystemRust = "rust"
)

// Library holds the metadata for a single library KB source.
// Populated by Load() from the v2 YAML library: block.
// Nil on a KnowledgeBase produced by Merge() over multiple distinct libraries.
type Library struct {
	Name         string
	Coordinates  []string
	VersionRange string
	Description  string
}

// KnowledgeBase is the loaded, indexed JCA/JCE contract set.
type KnowledgeBase struct {
	SchemaVersion string
	Ecosystem     string
	// Library holds the library metadata from the v2 YAML library: block.
	// Nil when this KB is the result of Merge() over >= 2 distinct libraries.
	Library *Library
	// Contracts is indexed by qualified-method-arity key:
	// "<package>.<Type>.<method>#<arity>" e.g. "javax.crypto.Cipher.unwrap#3".
	// For constructors: "<package>.<Type>.<init>#<arity>".
	// Multiple contracts can share a key when argument-conditional.
	Contracts map[string][]Contract
	// Hierarchy maps a child FQN to its direct parent FQNs. Used for LUB.
	Hierarchy map[string][]string
}

// Contract describes a single KB entry mapping a method call to an inferred return type.
type Contract struct {
	Method        string
	Arity         int
	When          *Condition // nil = unconditional contract
	Return        ContractReturn
	SourceLibrary string // populated by Load() from the v2 YAML library.name field
	// Role classifies a method's part in a crypto object's lifecycle (e.g.
	// "factory", "config", "output", "operation") so exported supporting
	// calls can carry semantic categories without duplicating crypto rule
	// metadata. Validated at load time against the Role whitelist; empty is
	// the valid "untagged" value.
	Role string
	// Parameters declares per-parameter roles for operation-determining or
	// metadata-contributing arguments, index/name-aligned with the callee's
	// declared parameter list. Nil when the contract carries no parameter
	// role annotations (the common case).
	Parameters []ParameterContract
}

// Role classifies a contract method's part in a crypto object's lifecycle.
// Declared as a distinct type for documentation; Contract.Role itself stays
// a plain string (validated against the Role whitelist at load time) so
// existing call sites that compare/assign strings need no changes.
type Role string

// Derivation classifies how a downstream consumer should compute the value a
// parameter contributes (see ParameterContract.Contributes).
type Derivation string

// Role whitelist values. See validRole.
const (
	RoleFactory   Role = "factory"
	RoleConfig    Role = "config"
	RoleOutput    Role = "output"
	RoleOperation Role = "operation"
)

// Derivation whitelist values. See validDerivation.
const (
	DerivationArgumentValue     Derivation = "argument_value"
	DerivationArgumentBitLength Derivation = "argument_bit_length"
	DerivationArgumentType      Derivation = "argument_type"
)

// ParameterContract describes a single parameter's role in a contract
// method, used to derive downstream export parameter_roles. Either Index or
// Name identifies the parameter; Index is preferred (position-based,
// matching parameter_types export ordering).
type ParameterContract struct {
	// Index is the 0-based parameter position; nil when identified by Name.
	Index *int
	Name  string
	// Role is one of "operation-determining", "metadata-contributing", "none".
	Role string
	// Contributes describes the property this parameter contributes and the
	// derivation strategy a downstream consumer should apply. Present only
	// when Role != "none".
	Contributes *Contribution
}

// Contribution names the property a parameter contributes to and the
// derivation strategy (see Derivation) a downstream consumer applies to
// compute it from the call-site argument.
type Contribution struct {
	Property   string
	Derivation string
}

// Condition constrains when this contract applies based on an argument value.
type Condition struct {
	ArgIndex   int
	ArgValueIn []string // matches if resolved literal is one of these
}

// ContractReturn holds the inferred return type and confidence for a contract.
type ContractReturn struct {
	Type       string
	Confidence string // "high" | "medium" | "low"
}

// ContractsFor returns all contracts for the given method FQN and arity.
// Performs an exact-arity match. For Python's arity-tolerant variant, see
// ContractsForTolerant.
func (kb *KnowledgeBase) ContractsFor(method string, arity int) []Contract {
	key := fmt.Sprintf("%s#%d", method, arity)
	return kb.Contracts[key]
}

// ContractsForTolerant returns contracts for the given method FQN and arity with
// ecosystem-aware matching:
//   - For Python KBs (kb.Ecosystem == "python"): first tries an exact-arity
//     match; if no contracts are found, falls back to any arity (name-only
//     match). When multiple candidates with different arities exist in the
//     fallback, the lowest-arity candidate is returned (deterministic tiebreak).
//   - For all other ecosystems: identical to ContractsFor (exact-arity only).
//
// Rationale: Python kwargs and default arguments mean the same crypto function
// may be called with varying arities at different sites (e.g. AES.new(key, mode)
// vs AES.new(key, mode, iv=...)). Exact-arity matching silently misses real-world
// calls in such cases. Java's strict overload discipline does not have this
// ambiguity, so Java keeps exact-arity semantics unchanged.
func (kb *KnowledgeBase) ContractsForTolerant(method string, arity int) []Contract {
	// Always try exact match first (preferred regardless of ecosystem).
	if exact := kb.ContractsFor(method, arity); len(exact) > 0 {
		return exact
	}
	// Non-Python: no fallback — return nil immediately.
	if kb.Ecosystem != ecosystemPython {
		return nil
	}

	// Python name-only fallback: scan for any key with "method#<anyArity>" prefix.
	prefix := method + "#"
	type candidate struct {
		arity    int
		contract []Contract
	}
	var candidates []candidate
	for key, ctrs := range kb.Contracts {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		suffix := key[len(prefix):]
		n := 0
		valid := suffix != ""
		for _, ch := range suffix {
			if ch < '0' || ch > '9' {
				valid = false
				break
			}
			n = n*10 + int(ch-'0')
		}
		if !valid {
			continue
		}
		candidates = append(candidates, candidate{arity: n, contract: ctrs})
	}
	if len(candidates) == 0 {
		return nil
	}
	// Deterministic tiebreak: return the candidate with the lowest arity.
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].arity < candidates[j].arity
	})
	return candidates[0].contract
}

// ContractsForCFunction matches a C callable with linkage-aware fallback.
// Exact qualification always wins. Bare-symbol lookup is allowed only when the
// caller has established external linkage and absence of a local declaration.
func (kb *KnowledgeBase) ContractsForCFunction(method string, arity int, externalGlobal bool) []Contract {
	if exact := kb.ContractsFor(method, arity); len(exact) > 0 {
		return exact
	}
	if kb.Ecosystem != ecosystemC || !externalGlobal {
		return nil
	}
	if idx := strings.LastIndex(method, "."); idx >= 0 {
		return kb.ContractsFor(method[idx+1:], arity)
	}
	return nil
}

// yamlKB is the YAML-level representation used for unmarshalling.
type yamlKB struct {
	SchemaVersion string              `yaml:"schema_version"`
	Ecosystem     string              `yaml:"ecosystem"`
	Library       *yamlLibrary        `yaml:"library"`
	Contracts     []yamlContract      `yaml:"contracts"`
	Hierarchy     map[string][]string `yaml:"hierarchy"`
}

type yamlLibrary struct {
	Name         string   `yaml:"name"`
	Coordinates  []string `yaml:"coordinates,omitempty"`
	VersionRange string   `yaml:"version_range,omitempty"`
	Description  string   `yaml:"description,omitempty"`
}

type yamlContract struct {
	Method string     `yaml:"method"`
	Arity  int        `yaml:"arity"`
	When   *yamlWhen  `yaml:"when"`
	Return yamlReturn `yaml:"return"`
	// Role classifies the method's lifecycle part; see Contract.Role.
	Role string `yaml:"role,omitempty"`
	// Parameters declares per-parameter roles; see Contract.Parameters.
	Parameters []yamlParameterRole `yaml:"parameters,omitempty"`
}

type yamlParameterRole struct {
	Index       *int              `yaml:"index,omitempty"`
	Name        string            `yaml:"name,omitempty"`
	Role        string            `yaml:"role"`
	Contributes *yamlContribution `yaml:"contributes,omitempty"`
}

type yamlContribution struct {
	Property   string `yaml:"property"`
	Derivation string `yaml:"derivation"`
}

type yamlWhen struct {
	ArgIndex   int      `yaml:"arg_index"`
	ArgValueIn []string `yaml:"arg_value_in"`
}

type yamlReturn struct {
	Type       string `yaml:"type"`
	Confidence string `yaml:"confidence"`
}

var validConfidence = map[string]struct{}{
	"high":   {},
	"medium": {},
	"low":    {},
}

// validRole is the whitelist for Contract.Role / yamlContract.Role.
var validRole = map[string]struct{}{
	string(RoleFactory):   {},
	string(RoleConfig):    {},
	string(RoleOutput):    {},
	string(RoleOperation): {},
}

// validParameterRole is the whitelist for ParameterContract.Role.
var validParameterRole = map[string]struct{}{
	"operation-determining": {},
	"metadata-contributing": {},
	"none":                  {},
}

// validDerivation is the whitelist for Contribution.Derivation.
var validDerivation = map[string]struct{}{
	string(DerivationArgumentValue):     {},
	string(DerivationArgumentBitLength): {},
	string(DerivationArgumentType):      {},
}

// Load parses and validates a YAML knowledge base payload.
// Returns a validated, indexed KnowledgeBase or an error.
func Load(data []byte) (*KnowledgeBase, error) {
	var raw yamlKB
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("contracts: YAML parse error: %w", err)
	}
	if err := validateHeader(&raw); err != nil {
		return nil, err
	}
	kb := &KnowledgeBase{
		SchemaVersion: raw.SchemaVersion,
		Ecosystem:     raw.Ecosystem,
		Library: &Library{
			Name:         raw.Library.Name,
			Coordinates:  raw.Library.Coordinates,
			VersionRange: raw.Library.VersionRange,
			Description:  raw.Library.Description,
		},
		Contracts: make(map[string][]Contract),
		Hierarchy: make(map[string][]string),
	}
	if err := indexContracts(&raw, kb); err != nil {
		return nil, err
	}
	if err := indexHierarchy(&raw, kb); err != nil {
		return nil, err
	}
	return kb, nil
}

// validateHeader checks that the top-level schema_version, ecosystem, and library fields are present and valid.
func validateHeader(raw *yamlKB) error {
	if raw.SchemaVersion == "" {
		return fmt.Errorf("contracts: missing required field schema_version")
	}
	if raw.SchemaVersion != "2" {
		return fmt.Errorf("contracts: unsupported schema_version %q (only \"2\" is accepted)", raw.SchemaVersion)
	}
	if raw.Ecosystem == "" {
		return fmt.Errorf("contracts: missing required field ecosystem")
	}
	if raw.Library == nil {
		return fmt.Errorf("contracts: missing required field library")
	}
	if raw.Library.Name == "" {
		return fmt.Errorf("contracts: library.name is required")
	}
	return nil
}

// validateContract checks that a single YAML contract entry is well-formed.
func validateContract(i int, c yamlContract) (*Condition, error) {
	if c.Method == "" {
		return nil, fmt.Errorf("contracts: contract[%d]: method is required", i)
	}
	if c.Arity < 0 {
		return nil, fmt.Errorf("contracts: contract[%d] (%s): arity must be >= 0, got %d", i, c.Method, c.Arity)
	}
	if c.Return.Type == "" {
		return nil, fmt.Errorf("contracts: contract[%d] (%s): return.type is required", i, c.Method)
	}
	if _, ok := validConfidence[c.Return.Confidence]; !ok {
		return nil, fmt.Errorf("contracts: contract[%d] (%s): return.confidence %q must be one of {high, medium, low}", i, c.Method, c.Return.Confidence)
	}
	if c.Role != "" {
		if _, ok := validRole[c.Role]; !ok {
			return nil, fmt.Errorf("contracts: contract[%d] (%s): role %q not in {factory, config, output, operation}", i, c.Method, c.Role)
		}
	}
	if c.When == nil {
		return nil, nil //nolint:nilnil // nil Condition is the valid "unconditional" signal
	}
	if c.When.ArgIndex < 0 {
		return nil, fmt.Errorf("contracts: contract[%d] (%s): when.arg_index must be >= 0", i, c.Method)
	}
	if len(c.When.ArgValueIn) == 0 {
		return nil, fmt.Errorf("contracts: contract[%d] (%s): when.arg_value_in must not be empty", i, c.Method)
	}
	return &Condition{
		ArgIndex:   c.When.ArgIndex,
		ArgValueIn: c.When.ArgValueIn,
	}, nil
}

// validateParameters checks that the Parameters sub-schema entries of a
// single YAML contract are well-formed, naming the method and field on
// failure. Returns the parsed ParameterContract slice (nil when the contract
// declares no parameters block).
func validateParameters(i int, c yamlContract) ([]ParameterContract, error) {
	if len(c.Parameters) == 0 {
		return nil, nil
	}
	out := make([]ParameterContract, 0, len(c.Parameters))
	for j, p := range c.Parameters {
		if _, ok := validParameterRole[p.Role]; !ok {
			return nil, fmt.Errorf(
				"contracts: contract[%d] (%s): parameters[%d].role %q not in {operation-determining, metadata-contributing, none}",
				i, c.Method, j, p.Role,
			)
		}
		pc := ParameterContract{Index: p.Index, Name: p.Name, Role: p.Role}
		if p.Contributes != nil {
			if p.Contributes.Property == "" {
				return nil, fmt.Errorf(
					"contracts: contract[%d] (%s): parameters[%d].contributes.property is required",
					i, c.Method, j,
				)
			}
			if _, ok := validDerivation[p.Contributes.Derivation]; !ok {
				return nil, fmt.Errorf(
					"contracts: contract[%d] (%s): parameters[%d].contributes.derivation %q not in {argument_value, argument_bit_length, argument_type}",
					i, c.Method, j, p.Contributes.Derivation,
				)
			}
			pc.Contributes = &Contribution{Property: p.Contributes.Property, Derivation: p.Contributes.Derivation}
		}
		out = append(out, pc)
	}
	return out, nil
}

// indexContracts validates and indexes all contract entries into the KnowledgeBase.
func indexContracts(raw *yamlKB, kb *KnowledgeBase) error {
	unconditionalSeen := make(map[string]struct{})
	for i, c := range raw.Contracts {
		when, err := validateContract(i, c)
		if err != nil {
			return err
		}
		params, err := validateParameters(i, c)
		if err != nil {
			return err
		}
		key := fmt.Sprintf("%s#%d", c.Method, c.Arity)
		// Reject duplicate unconditional contracts for the same key.
		if when == nil {
			if _, dup := unconditionalSeen[key]; dup {
				return fmt.Errorf("contracts: duplicate unconditional contract for key %q", key)
			}
			unconditionalSeen[key] = struct{}{}
		}
		kb.Contracts[key] = append(kb.Contracts[key], Contract{
			Method:        c.Method,
			Arity:         c.Arity,
			When:          when,
			Return:        ContractReturn{Type: c.Return.Type, Confidence: c.Return.Confidence},
			SourceLibrary: raw.Library.Name,
			Role:          c.Role,
			Parameters:    params,
		})
	}
	return nil
}

// indexHierarchy validates and indexes all hierarchy edges into the KnowledgeBase.
func indexHierarchy(raw *yamlKB, kb *KnowledgeBase) error {
	for child, parents := range raw.Hierarchy {
		if child == "" {
			return fmt.Errorf("contracts: hierarchy: empty child FQN")
		}
		for j, p := range parents {
			if p == "" {
				return fmt.Errorf("contracts: hierarchy: child %q has empty parent at index %d", child, j)
			}
		}
		kb.Hierarchy[child] = parents
	}
	return nil
}

// embedFSFor returns the embedded filesystem and directory name for the given ecosystem.
// Returns nil, "" if the ecosystem is not known.
func embedFSFor(ecosystem string) (fs.FS, string) {
	switch ecosystem {
	case "java":
		return &javaFS, "java"
	case ecosystemC:
		return &cFS, ecosystemC
	case ecosystemGo:
		return &goFS, ecosystemGo
	case ecosystemPython:
		return &pythonFS, ecosystemPython
	case ecosystemRust:
		return &rustFS, ecosystemRust
	default:
		return nil, ""
	}
}

// emptyKB returns a valid empty KnowledgeBase with schema version "2".
func emptyKB() *KnowledgeBase {
	return &KnowledgeBase{
		SchemaVersion: "2",
		Contracts:     map[string][]Contract{},
		Hierarchy:     map[string][]string{},
	}
}

// LoadEmbedded discovers and loads all *.yaml files in the given ecosystem
// directory under the embedded contracts FS, validates each, and returns the
// merged KnowledgeBase. Duplicate library.name values across files are detected
// here because LoadEmbedded has access to file paths for the diagnostic.
//
// Returns an empty *KnowledgeBase (nil error) if the ecosystem is unknown or
// the directory has no YAML files. Returns an error if any file cannot be read,
// fails validation, or if two files declare the same library.name.
func LoadEmbedded(ecosystem string) (*KnowledgeBase, error) {
	fsys, dir := embedFSFor(ecosystem)
	if fsys == nil {
		return emptyKB(), nil
	}

	entries, err := fs.ReadDir(fsys, dir)
	if err != nil || len(entries) == 0 {
		// Intentional per spec scenario B2: an unknown or empty ecosystem
		// directory is not an error — return an empty KB and let the engine
		// proceed without any contracts for this ecosystem. For an embed.FS
		// the only ReadDir error is "directory does not exist," which is the
		// empty-ecosystem case.
		return emptyKB(), nil //nolint:nilerr // see spec/design: empty-ecosystem returns empty KB
	}

	seenLibNames := make(map[string]string) // libName -> filePath
	kbs := make([]*KnowledgeBase, 0, len(entries))

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		path := dir + "/" + entry.Name()
		data, readErr := fs.ReadFile(fsys, path)
		if readErr != nil {
			return nil, fmt.Errorf("contracts: read %s: %w", path, readErr)
		}
		kb, loadErr := Load(data)
		if loadErr != nil {
			return nil, fmt.Errorf("contracts: %s: %w", path, loadErr)
		}
		if kb.Library != nil {
			if existing, dup := seenLibNames[kb.Library.Name]; dup {
				return nil, fmt.Errorf("contracts: duplicate library name %q in files %s and %s",
					kb.Library.Name, existing, path)
			}
			seenLibNames[kb.Library.Name] = path
		}
		kbs = append(kbs, kb)
	}

	if len(kbs) == 0 {
		return emptyKB(), nil
	}
	if len(kbs) == 1 {
		return kbs[0], nil
	}
	return Merge(kbs...)
}

// ── Merge ─────────────────────────────────────────────────────────────────────

// Merge combines multiple per-library KnowledgeBases into a single merged KB,
// applying conflict detection rules. Returns an error if any conflict rule
// is violated. The result KB has Library = nil (it represents a merger of
// N libraries; no single library identifies it).
//
// Conflict rules:
//  1. Same key + identical contract → idempotent (keep one, no error).
//  2. Same key + same condition + DIFFERENT return → HARD ERROR (names both libs).
//  3. Hierarchy child→[A] in both → idempotent.
//  4. Hierarchy child→[A] vs child→[B] → HARD ERROR.
//  5. Hierarchy child→[A] vs child→[A,B] → UNION (output is the larger set).
func Merge(kbs ...*KnowledgeBase) (*KnowledgeBase, error) {
	if len(kbs) == 0 {
		return emptyKB(), nil
	}
	if len(kbs) == 1 {
		return cloneKB(kbs[0]), nil
	}
	if err := validateLibraryUniqueness(kbs); err != nil {
		return nil, err
	}
	eco, err := commonEcosystem(kbs)
	if err != nil {
		return nil, err
	}
	mergedContracts, err := mergeContracts(kbs)
	if err != nil {
		return nil, err
	}
	mergedHierarchy, err := mergeHierarchy(kbs)
	if err != nil {
		return nil, err
	}
	return &KnowledgeBase{
		SchemaVersion: "2",
		Ecosystem:     eco,
		Library:       nil, // merger of N libraries: no single Library identifies it
		Contracts:     mergedContracts,
		Hierarchy:     mergedHierarchy,
	}, nil
}

// cloneKB returns a deep clone of a KnowledgeBase so callers cannot mutate the
// original via the returned value. Used by Merge when len(kbs) == 1.
func cloneKB(kb *KnowledgeBase) *KnowledgeBase {
	clone := &KnowledgeBase{
		SchemaVersion: kb.SchemaVersion,
		Ecosystem:     kb.Ecosystem,
		Contracts:     make(map[string][]Contract, len(kb.Contracts)),
		Hierarchy:     make(map[string][]string, len(kb.Hierarchy)),
	}
	if kb.Library != nil {
		lib := *kb.Library
		clone.Library = &lib
	}
	for k, v := range kb.Contracts {
		dst := make([]Contract, len(v))
		copy(dst, v)
		clone.Contracts[k] = dst
	}
	for k, v := range kb.Hierarchy {
		dst := make([]string, len(v))
		copy(dst, v)
		clone.Hierarchy[k] = dst
	}
	return clone
}

// validateLibraryUniqueness returns an error if two KBs share the same
// non-empty Library.Name. Merge() enforces uniqueness for in-memory KBs where
// file paths are not available (LoadEmbedded uses path-aware detection instead).
func validateLibraryUniqueness(kbs []*KnowledgeBase) error {
	seen := make(map[string]struct{}, len(kbs))
	for _, kb := range kbs {
		if kb.Library == nil || kb.Library.Name == "" {
			continue
		}
		if _, dup := seen[kb.Library.Name]; dup {
			return fmt.Errorf("contracts: duplicate library name %q", kb.Library.Name)
		}
		seen[kb.Library.Name] = struct{}{}
	}
	return nil
}

// commonEcosystem verifies that all KBs share the same ecosystem string and
// returns it. Returns an error if any two KBs disagree.
func commonEcosystem(kbs []*KnowledgeBase) (string, error) {
	eco := kbs[0].Ecosystem
	for _, kb := range kbs[1:] {
		if kb.Ecosystem != eco {
			return "", fmt.Errorf("contracts: ecosystem mismatch: %q vs %q", eco, kb.Ecosystem)
		}
	}
	return eco, nil
}

// conditionKey produces a canonical, set-based key for a Condition.
// nil Condition → "nil-condition". Non-nil → "argIndex|sorted-arg_value_in".
// Sorting makes the key order-insensitive: ["A","B"] == ["B","A"].
func conditionKey(c *Condition) string {
	if c == nil {
		return "nil-condition"
	}
	sorted := make([]string, len(c.ArgValueIn))
	copy(sorted, c.ArgValueIn)
	sort.Strings(sorted)
	return fmt.Sprintf("%d|%s", c.ArgIndex, strings.Join(sorted, ","))
}

// mergeContracts applies contract conflict rules 1 and 2 across all KBs.
// Rule 1: same key + identical (Return.Type, Return.Confidence, condition) → idempotent.
// Rule 2: same key + same condition + different return → HARD ERROR naming both libs.
func mergeContracts(kbs []*KnowledgeBase) (map[string][]Contract, error) {
	totalContracts := 0
	for _, kb := range kbs {
		totalContracts += len(kb.Contracts)
	}
	// index: methodArityKey → condKey → Contract (de-duplicated)
	index := make(map[string]map[string]Contract, totalContracts)

	for _, kb := range kbs {
		for key, cs := range kb.Contracts {
			if index[key] == nil {
				index[key] = make(map[string]Contract, len(cs))
			}
			if err := mergeContractGroup(index[key], cs, key); err != nil {
				return nil, err
			}
		}
	}

	// Flatten index back to map[string][]Contract
	result := make(map[string][]Contract, len(index))
	for key, byCondition := range index {
		cs := make([]Contract, 0, len(byCondition))
		for _, c := range byCondition {
			cs = append(cs, c)
		}
		result[key] = cs
	}
	return result, nil
}

// mergeContractGroup inserts a slice of contracts into the per-condition index for
// one methodArityKey, applying rules 1 (idempotent) and 2 (conflict HARD ERROR).
// Rule 1/2 equality now also covers Role and Parameters (see
// contractsEquivalent): identical role/parameter_roles merge idempotently,
// divergent values HARD-ERROR naming both libraries, mirroring the
// pre-existing return-type conflict discipline.
func mergeContractGroup(index map[string]Contract, cs []Contract, key string) error {
	for _, c := range cs {
		ck := conditionKey(c.When)
		existing, exists := index[ck]
		if !exists {
			index[ck] = c
			continue
		}
		// Rule 1: identical return+role+parameters → idempotent
		if contractsEquivalent(existing, c) {
			continue
		}
		// Rule 2: same condition + divergent return/role/parameters → HARD ERROR
		return fmt.Errorf(
			"contracts: contract conflict for %s: library %q has return %q (%s) role %q; library %q has return %q (%s) role %q",
			key,
			existing.SourceLibrary, existing.Return.Type, existing.Return.Confidence, existing.Role,
			c.SourceLibrary, c.Return.Type, c.Return.Confidence, c.Role,
		)
	}
	return nil
}

// contractsEquivalent reports whether two contracts sharing the same
// method+arity+condition key are semantically identical: same return type,
// confidence, role, and canonical parameter-role key.
func contractsEquivalent(a, b Contract) bool {
	return a.Return.Type == b.Return.Type &&
		a.Return.Confidence == b.Return.Confidence &&
		a.Role == b.Role &&
		parametersKey(a.Parameters) == parametersKey(b.Parameters)
}

// parametersKey produces a canonical, order-insensitive key for a
// ParameterContract slice, used by contractsEquivalent to detect divergence
// across libraries during Merge.
func parametersKey(params []ParameterContract) string {
	if len(params) == 0 {
		return ""
	}
	parts := make([]string, len(params))
	for i, p := range params {
		idx := "-"
		if p.Index != nil {
			idx = strconv.Itoa(*p.Index)
		}
		contrib := ""
		if p.Contributes != nil {
			contrib = p.Contributes.Property + ":" + p.Contributes.Derivation
		}
		parts[i] = idx + "|" + p.Name + "|" + p.Role + "|" + contrib
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

// mergeHierarchy applies hierarchy conflict rules 3, 4, and 5 across all KBs.
// Rule 3: identical parent sets → idempotent.
// Rule 4: non-comparable sets → HARD ERROR naming both source libraries.
// Rule 5: one set is a strict subset of the other → emit the union (larger set).
func mergeHierarchy(kbs []*KnowledgeBase) (map[string][]string, error) {
	totalHierarchy := 0
	for _, kb := range kbs {
		totalHierarchy += len(kb.Hierarchy)
	}
	merged := make(map[string][]string, totalHierarchy)

	// Track which KB owns each child for diagnostics
	type ownerEntry struct {
		parents []string
		libName string
	}
	owners := make(map[string]ownerEntry, totalHierarchy)

	for _, kb := range kbs {
		libName := ""
		if kb.Library != nil {
			libName = kb.Library.Name
		}
		for child, parents := range kb.Hierarchy {
			existing, exists := owners[child]
			if !exists {
				owners[child] = ownerEntry{parents: parents, libName: libName}
				merged[child] = parents
				continue
			}
			result, err := resolveParentSets(child, existing.parents, existing.libName, parents, libName)
			if err != nil {
				return nil, err
			}
			owners[child] = ownerEntry{parents: result, libName: existing.libName}
			merged[child] = result
		}
	}
	return merged, nil
}

// resolveParentSets applies rules 3-5 for a single hierarchy child.
// Returns the winning parent set or an error on non-comparable conflict.
func resolveParentSets(child string, setA []string, libA string, setB []string, libB string) ([]string, error) {
	// Rule 3: identical sets → idempotent
	if setsEqual(setA, setB) {
		return setA, nil
	}
	// Rule 5a: setA ⊆ setB → use setB (the larger)
	if isSubset(setA, setB) {
		return setB, nil
	}
	// Rule 5b: setB ⊆ setA → use setA (the larger)
	if isSubset(setB, setA) {
		return setA, nil
	}
	// Rule 4: non-comparable → HARD ERROR
	return nil, fmt.Errorf(
		"contracts: hierarchy conflict for %s: library %q has [%s]; library %q has [%s]",
		child, libA, strings.Join(setA, ", "), libB, strings.Join(setB, ", "),
	)
}

// setsEqual returns true if two string slices contain the same elements
// (order-insensitive).
func setsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, s := range a {
		counts[s]++
	}
	for _, s := range b {
		counts[s]--
		if counts[s] < 0 {
			return false
		}
	}
	return true
}

// isSubset returns true if every element of sub is in super.
func isSubset(sub, super []string) bool {
	superSet := make(map[string]struct{}, len(super))
	for _, s := range super {
		superSet[s] = struct{}{}
	}
	for _, s := range sub {
		if _, ok := superSet[s]; !ok {
			return false
		}
	}
	return true
}
