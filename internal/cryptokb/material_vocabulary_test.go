package cryptokb_test

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/scanoss/reach/callgraph/contracts"
)

// TestRelatedCryptoMaterialTypes_AreCycloneDXValues keeps the role whitelist
// inside the CycloneDX 1.7 relatedCryptoMaterialType enum the converter
// validates against, so a role the loader accepts never becomes "other" in a
// CBOM.
func TestRelatedCryptoMaterialTypes_AreCycloneDXValues(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("../converter/schema/bom-1.7.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Definitions struct {
			CryptoProperties struct {
				Properties struct {
					RelatedCryptoMaterialProperties struct {
						Properties struct {
							Type struct {
								Enum []string `json:"enum"`
							} `json:"type"`
						} `json:"properties"`
					} `json:"relatedCryptoMaterialProperties"`
				} `json:"properties"`
			} `json:"cryptoProperties"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	enum := schema.Definitions.CryptoProperties.Properties.RelatedCryptoMaterialProperties.Properties.Type.Enum
	if len(enum) == 0 {
		t.Fatal("schema relatedCryptoMaterialType enum not found")
	}
	for _, material := range contracts.RelatedCryptoMaterialTypes {
		if !slices.Contains(enum, material) {
			t.Errorf("material %q is not in the CycloneDX enum %v", material, enum)
		}
	}
}
