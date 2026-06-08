package rules

import (
	"os"
	"path/filepath"
	"testing"

	"go.yaml.in/yaml/v3"
)

type fixtureRuleFile struct {
	Rules []fixtureRule `yaml:"rules"`
}

type fixtureRule struct {
	ID       string              `yaml:"id"`
	Metadata fixtureRuleMetadata `yaml:"metadata"`
}

type fixtureRuleMetadata struct {
	Crypto map[string]string `yaml:"crypto"`
}

func TestJavaRulesFixturesClassifyPassword4JAndBouncyCastleSignals(t *testing.T) {
	t.Parallel()

	fixturePath := filepath.Join("..", "..", "testdata", "rules", "java-crypto-reachability.yaml")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture rules: %v", err)
	}

	var parsed fixtureRuleFile
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("parse fixture rules: %v", err)
	}

	passwordTerminal := findFixtureRule(parsed.Rules, "java.password4j.terminal.hash")
	if passwordTerminal == nil {
		t.Fatal("missing java.password4j.terminal.hash rule")
	}
	if passwordTerminal.Metadata.Crypto["assetType"] != "algorithm" || passwordTerminal.Metadata.Crypto["operation"] != "digest" {
		t.Fatalf("password terminal metadata = %#v, want algorithm digest", passwordTerminal.Metadata.Crypto)
	}

	bouncyKeygen := findFixtureRule(parsed.Rules, "java.bouncycastle.keygen.ec")
	if bouncyKeygen == nil {
		t.Fatal("missing java.bouncycastle.keygen.ec rule")
	}
	if bouncyKeygen.Metadata.Crypto["algorithmPrimitive"] != "key-agree" || bouncyKeygen.Metadata.Crypto["operation"] != "keygen" {
		t.Fatalf("bouncycastle keygen metadata = %#v, want key-agree keygen", bouncyKeygen.Metadata.Crypto)
	}
}

func findFixtureRule(rules []fixtureRule, id string) *fixtureRule {
	for i := range rules {
		if rules[i].ID == id {
			return &rules[i]
		}
	}
	return nil
}
