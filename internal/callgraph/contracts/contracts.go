// Package contracts provides the JCA/JCE knowledge base (KB) loader and types
// for the callgraph inference engine. It defines YAML-based contract definitions
// that map method signatures to their inferred return types.
package contracts

import (
	"embed"
	"fmt"

	"go.yaml.in/yaml/v3"
)

//go:embed java/jdk-crypto.yaml
var embeddedFS embed.FS

// KnowledgeBase is the loaded, indexed JCA/JCE contract set.
type KnowledgeBase struct {
	SchemaVersion string
	Ecosystem     string
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
	Method string
	Arity  int
	When   *Condition // nil = unconditional contract
	Return ContractReturn
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
func (kb *KnowledgeBase) ContractsFor(method string, arity int) []Contract {
	key := fmt.Sprintf("%s#%d", method, arity)
	return kb.Contracts[key]
}

// yamlKB is the YAML-level representation used for unmarshalling.
type yamlKB struct {
	SchemaVersion string              `yaml:"schema_version"`
	Ecosystem     string              `yaml:"ecosystem"`
	Contracts     []yamlContract      `yaml:"contracts"`
	Hierarchy     map[string][]string `yaml:"hierarchy"`
}

type yamlContract struct {
	Method string     `yaml:"method"`
	Arity  int        `yaml:"arity"`
	When   *yamlWhen  `yaml:"when"`
	Return yamlReturn `yaml:"return"`
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
		Contracts:     make(map[string][]Contract),
		Hierarchy:     make(map[string][]string),
	}
	if err := indexContracts(&raw, kb); err != nil {
		return nil, err
	}
	if err := indexHierarchy(&raw, kb); err != nil {
		return nil, err
	}
	return kb, nil
}

// validateHeader checks that the top-level schema_version and ecosystem fields are present and valid.
func validateHeader(raw *yamlKB) error {
	if raw.SchemaVersion == "" {
		return fmt.Errorf("contracts: missing required field schema_version")
	}
	if raw.SchemaVersion != "1" {
		return fmt.Errorf("contracts: unsupported schema_version %q (only \"1\" is accepted)", raw.SchemaVersion)
	}
	if raw.Ecosystem == "" {
		return fmt.Errorf("contracts: missing required field ecosystem")
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

// indexContracts validates and indexes all contract entries into the KnowledgeBase.
func indexContracts(raw *yamlKB, kb *KnowledgeBase) error {
	unconditionalSeen := make(map[string]struct{})
	for i, c := range raw.Contracts {
		when, err := validateContract(i, c)
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
			Method: c.Method,
			Arity:  c.Arity,
			When:   when,
			Return: ContractReturn{
				Type:       c.Return.Type,
				Confidence: c.Return.Confidence,
			},
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

// LoadEmbeddedJava loads the embedded JCA/JCE knowledge base from jdk-crypto.yaml.
func LoadEmbeddedJava() (*KnowledgeBase, error) {
	data, err := embeddedFS.ReadFile("java/jdk-crypto.yaml")
	if err != nil {
		return nil, fmt.Errorf("contracts: failed to read embedded java KB: %w", err)
	}
	return Load(data)
}
