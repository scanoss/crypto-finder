package oid

import (
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestResolver_ExactOnly(t *testing.T) {
	resolver := NewDefaultResolver()
	tests := []struct {
		name    string
		asset   entities.CryptographicAsset
		want    string
		outcome Outcome
	}{
		{"AES needs key size", asset("AES", "", "CBC", "", "block-cipher"), "", NoExactSelection},
		{"AES exact mode and key size", asset("AES", "", "CBC", "128", "block-cipher"), "2.16.840.1.101.3.4.1.2", Exact},
		{"HMAC SHA 256 alias", asset("HMAC", "HMAC-SHA-256", "", "", "mac"), "1.2.840.113549.2.9", Exact},
		{"known family is not a branch fallback", asset("AES", "AES-999-CBC", "CBC", "999", "block-cipher"), "", NoExactSelection},
		{"ECDSA requires digest", asset("ECDSA", "ECDSA", "", "", "signature"), "", NoExactSelection},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolver.ResolveAsset(&tt.asset)
			if result.OID != tt.want || result.Outcome != tt.outcome {
				t.Fatalf("ResolveAsset() = (%q, %v), want (%q, %v)", result.OID, result.Outcome, tt.want, tt.outcome)
			}
		})
	}
}

func TestResolver_ClaimAndEvidencePrecedence(t *testing.T) {
	resolver := NewDefaultResolver()
	tests := []struct {
		name  string
		asset entities.CryptographicAsset
		want  Outcome
	}{
		{"dual conflicting claims", assetWithClaims("1.2.3", "1.2.840.113549.2.9"), RejectedClaim},
		{"rule claim is admitted", assetWithClaims("", "1.2.840.113549.2.9"), Exact},
		{"invalid primitive wins before lookup", entities.CryptographicAsset{Metadata: map[string]string{"assetType": "algorithm", "algorithmPrimitive": "other", "algorithmName": "HMAC-SHA256"}}, InvalidEvidence},
		{"unlisted asset type is invalid", entities.CryptographicAsset{Metadata: map[string]string{"assetType": "protocol", "algorithmPrimitive": "mac", "algorithmName": "HMAC-SHA256"}}, InvalidEvidence},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolver.ResolveAsset(&tt.asset); got.Outcome != tt.want {
				t.Fatalf("ResolveAsset() outcome = %v, want %v", got.Outcome, tt.want)
			}
		})
	}
}

func TestPreparedReport_ClonesAndSummaryIsImmutableValue(t *testing.T) {
	report := &entities.InterimReport{Findings: []entities.Finding{{CryptographicAssets: []entities.CryptographicAsset{asset("HMAC", "HMAC-SHA-256", "", "", "mac")}}}}
	report.Findings[0].CryptographicAssets[0].TerminalStartCol = 12
	report.Findings[0].CryptographicAssets[0].TerminalEndCol = 25
	prepared, err := NewDefaultResolver().PrepareReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if report.Findings[0].CryptographicAssets[0].OID != "" {
		t.Fatal("PrepareReport mutated the input report")
	}
	first := prepared.ReportClone()
	first.Findings[0].CryptographicAssets[0].OID = "changed"
	if second := prepared.ReportClone(); second.Findings[0].CryptographicAssets[0].OID != "1.2.840.113549.2.9" {
		t.Fatalf("ReportClone leaked mutation: %q", second.Findings[0].CryptographicAssets[0].OID)
	}
	if got := prepared.ReportClone().Findings[0].CryptographicAssets[0].TerminalEndCol; got != 25 {
		t.Fatalf("ReportClone lost internal terminal anchor: %d", got)
	}
	mutatedSummary := prepared.Summary()
	mutatedSummary.Exact = 99
	if got := prepared.Summary().Exact; got == mutatedSummary.Exact {
		t.Fatalf("Summary leaked mutation: %d", got)
	}
}

func TestNewResolver_RejectsInvalidCatalog(t *testing.T) {
	base := Record{Name: "valid", OID: "1.2.3", Authority: "IETF", PrimarySource: "https://example.invalid/registry", Class: Digest}
	for _, records := range [][]Record{
		{{Name: "missing", OID: "1.2.3", Class: Digest}},
		{{Name: "bad", OID: "3.1.1", Authority: "IETF", PrimarySource: "https://example.invalid/registry", Class: Digest}},
		{{Name: "branch", OID: "2.16.840.1.101.3.4.1", Authority: "NIST", PrimarySource: "https://example.invalid/registry", Class: Cipher}},
		{base, {Name: "valid", OID: "1.2.4", Authority: "IETF", PrimarySource: "https://example.invalid/registry", Class: Digest}},
	} {
		if _, err := NewResolver(records); err == nil {
			t.Fatal("NewResolver() accepted invalid catalog")
		}
	}
}

//go:embed testdata/report-record-inventory.json
var reportRecordInventory []byte

// reportInventory is intentionally a distinct evidence schema, not Record's JSON
// shape. Its source IDs and nested registration fields keep the test oracle
// independent of production catalog decoding.
type reportInventory struct {
	Schema  string                  `json:"inventory_schema"`
	Records []reportInventoryRecord `json:"records"`
}

type reportInventoryRecord struct {
	SourceID         string `json:"source_id"`
	ObjectIdentifier string `json:"object_identifier"`
	Registered       struct {
		Name       string `json:"name"`
		Identifier string `json:"identifier"`
	} `json:"registered"`
	Classification    ObjectClass       `json:"classification"`
	RegistrationState RegistrationState `json:"registration_state"`
	Selection         struct {
		Aliases    []string    `json:"aliases"`
		Family     string      `json:"family"`
		Mode       string      `json:"mode"`
		KeySize    string      `json:"key_size"`
		Dimensions []Dimension `json:"dimensions"`
	} `json:"selection"`
	RegistrationAuthority string `json:"registration_authority"`
	PrimaryReference      string `json:"primary_reference"`
}

func decodeReportInventory(data []byte) ([]reportInventoryRecord, error) {
	var inventory reportInventory
	if err := json.Unmarshal(data, &inventory); err != nil {
		return nil, err
	}
	if inventory.Schema != "report-record-inventory/v1" {
		return nil, fmt.Errorf("unsupported inventory schema %q", inventory.Schema)
	}
	return inventory.Records, nil
}

func (row reportInventoryRecord) translatedRecord() Record {
	aliases := row.Selection.Aliases
	if len(aliases) == 0 {
		aliases = nil
	}
	return Record{
		Name: row.SourceID, OID: row.ObjectIdentifier,
		RegisteredName: row.Registered.Name, RegisteredIdentifier: row.Registered.Identifier,
		Class: row.Classification, State: row.RegistrationState,
		Aliases: aliases, Family: row.Selection.Family, Mode: row.Selection.Mode,
		KeySize: row.Selection.KeySize, Required: row.Selection.Dimensions,
		Authority: row.RegistrationAuthority, PrimarySource: row.PrimaryReference,
	}
}

func compareCatalogToReportInventory(got []Record, want []reportInventoryRecord) error {
	if len(got) != len(want) {
		return fmt.Errorf("record count = %d, want %d", len(got), len(want))
	}
	for i := range want {
		expected := want[i].translatedRecord()
		if actual := got[i]; !reflect.DeepEqual(actual, expected) {
			return fmt.Errorf("row %d (%q) differs: got %#v, want %#v", i, actual.Name, actual, expected)
		}
	}
	return nil
}

func TestDefaultCatalog_MatchesIndependentRecordInventory(t *testing.T) {
	want, err := decodeReportInventory(reportRecordInventory)
	if err != nil {
		t.Fatalf("decode independent record inventory: %v", err)
	}
	if err := compareCatalogToReportInventory(defaultRecords(), want); err != nil {
		t.Fatalf("production catalog differs from independent record inventory: %v", err)
	}
}

func TestIndependentRecordInventory_DetectsMutationOmissionAdditionStateAndSource(t *testing.T) {
	want, err := decodeReportInventory(reportRecordInventory)
	if err != nil {
		t.Fatal(err)
	}
	base := defaultRecords()
	cases := []struct {
		name string
		got  []Record
	}{
		{"mutation", func() []Record { got := append([]Record(nil), base...); got[0].OID = "1.2.999"; return got }()},
		{"omission", base[:len(base)-1]},
		{"addition", append(append([]Record(nil), base...), base[0])},
		{"state", func() []Record { got := append([]Record(nil), base...); got[0].State = Deprecated; return got }()},
		{"source", func() []Record {
			got := append([]Record(nil), base...)
			got[0].PrimarySource = "https://example.invalid/changed"
			return got
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := compareCatalogToReportInventory(tc.got, want); err == nil {
				t.Fatal("independent inventory accepted changed catalog")
			}
		})
	}
}

func TestDefaultCatalog_HasDeterministicReportInventory(t *testing.T) {
	// This is the explicit inventory gate for the report's mapping tables. A
	// source-verified row must add a record (or update this reviewed count), not
	// silently disappear behind aggregate coverage totals.
	const reportRecordCount = 274
	if got := len(defaultRecords()); got != reportRecordCount {
		t.Fatalf("defaultRecords() = %d source-verified records, want %d", got, reportRecordCount)
	}
}

func TestDefaultCatalog_IsPinnedIndependentAuthorityEvidence(t *testing.T) {
	// This digest pins every authority-evidence row (not an implementation
	// generated projection). Adding, omitting, or editing a production record
	// therefore requires an explicit review of the committed evidence artifact.
	const expected = "a195f817c71b97e5a5762266258bb19bd33427f1674adc319b857442c0e5f0bb"
	actual := fmt.Sprintf("%x", sha256.Sum256(defaultCatalog))
	if actual != expected {
		t.Fatalf("authority catalog digest = %s, want %s; review every record change", actual, expected)
	}
	for _, record := range defaultRecords() {
		if record.RegisteredName == "" || record.RegisteredIdentifier == "" || record.Authority == "" || record.PrimarySource == "" || len(record.Required) == 0 {
			t.Fatalf("incomplete independent authority evidence for %q", record.Name)
		}
		if !validAuthoritySource(record.PrimarySource) {
			t.Fatalf("catalog record %q has non-authoritative source %q", record.Name, record.PrimarySource)
		}
	}
}

func TestDefaultCatalog_UsesCuratedRegistrationStates(t *testing.T) {
	states := map[string]RegistrationState{}
	for _, record := range defaultRecords() {
		states[record.Name] = record.State
	}
	if states["SHA-1"] != Legacy {
		t.Fatalf("SHA-1 state = %v, want Legacy", states["SHA-1"])
	}
	if states["RC4"] != Deprecated {
		t.Fatalf("RC4 state = %v, want Deprecated", states["RC4"])
	}
	for name, state := range states {
		if !emittingState(state) {
			t.Fatalf("positive authority catalog contains non-emitting %q state %v", name, state)
		}
	}
}

func TestResolver_NonEmittingReportDispositions(t *testing.T) {
	resolver := NewDefaultResolver()
	for _, tt := range []struct {
		name string
		want Outcome
	}{{"Argon2", NoStandard}, {"HMAC-MD5", Unresolved}} {
		t.Run(tt.name, func(t *testing.T) {
			got := resolver.ResolveAsset(&entities.CryptographicAsset{Metadata: map[string]string{"assetType": "algorithm", "algorithmPrimitive": "kdf", "algorithmName": tt.name}})
			if got.Outcome != tt.want || got.OID != "" {
				t.Fatalf("ResolveAsset() = %#v, want %v without OID", got, tt.want)
			}
		})
	}
}

func TestResolver_RejectsUnsafeClaims(t *testing.T) {
	resolver := NewDefaultResolver()
	tests := []struct {
		name, claim string
		want        Outcome
	}{
		{"matching claim", "1.2.840.113549.2.9", Exact},
		{"branch claim", "1.2.840.113549.2", RejectedClaim},
		{"malformed claim", "1.2.x", RejectedClaim},
		{"private claim", "1.3.6.1.4.1.99999.1", RejectedClaim},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := asset("HMAC", "HMAC-SHA-256", "", "", "mac")
			a.OID = tt.claim
			got := resolver.ResolveAsset(&a)
			if got.Outcome != tt.want {
				t.Fatalf("outcome = %v, want %v", got.Outcome, tt.want)
			}
			if tt.want == RejectedClaim && got.OID != "" {
				t.Fatalf("unsafe claim retained: %q", got.OID)
			}
		})
	}
}

func asset(family, name, mode, keySize, primitive string) entities.CryptographicAsset {
	return entities.CryptographicAsset{Metadata: map[string]string{
		"assetType": "algorithm", "algorithmFamily": family, "algorithmName": name,
		"algorithmMode": mode, "algorithmParameterSetIdentifier": keySize, "algorithmPrimitive": primitive,
	}}
}

func assetWithClaims(topLevel, ruleClaim string) entities.CryptographicAsset {
	a := asset("HMAC", "HMAC-SHA-256", "", "", "mac")
	a.OID = topLevel
	if ruleClaim != "" {
		a.Metadata["oid"] = ruleClaim
	}
	return a
}

func TestDefaultCatalog_EveryExactRecordResolvesFromItsRequiredEvidence(t *testing.T) {
	resolver := NewDefaultResolver()
	for _, record := range defaultRecords() {
		record := record
		t.Run(record.Name, func(t *testing.T) {
			if record.Class == Curve {
				got := resolver.ResolveCurve(record.Name)
				if got.Outcome != Exact || got.OID != record.OID {
					t.Fatalf("ResolveCurve(%q) = %#v, want %q", record.Name, got, record.OID)
				}
				return
			}
			got := resolver.ResolveAsset(&entities.CryptographicAsset{Metadata: map[string]string{
				"assetType":                       "algorithm",
				"algorithmName":                   record.Name,
				"algorithmFamily":                 record.Family,
				"algorithmMode":                   record.Mode,
				"algorithmParameterSetIdentifier": record.KeySize,
				"algorithmPrimitive":              primitiveForClass(record.Class),
			}})
			if got.Outcome != Exact || got.OID != record.OID {
				t.Fatalf("ResolveAsset(%q) = %#v, want exact %q", record.Name, got, record.OID)
			}
		})
	}
}

func TestNewResolver_RejectsDuplicateSelector(t *testing.T) {
	records := []Record{
		{Name: "same", OID: "1.2.3", Authority: "IETF", PrimarySource: "https://example.invalid/registry", Class: Digest, RegisteredName: "same", RegisteredIdentifier: "1.2.3", Required: []Dimension{DimensionName}},
		{Name: "same", OID: "1.2.4", Authority: "IETF", PrimarySource: "https://example.invalid/registry", Class: Digest, RegisteredName: "same", RegisteredIdentifier: "1.2.4", Required: []Dimension{DimensionName}},
	}
	_, err := NewResolver(records)
	if err == nil || !strings.Contains(err.Error(), `duplicate selector "same"`) {
		t.Fatalf("NewResolver() error = %v, want duplicate selector for canonical name", err)
	}
}

func TestNewResolver_RejectsAliasCollision(t *testing.T) {
	records := []Record{
		{Name: "first", OID: "1.2.3", Authority: "IETF", PrimarySource: "https://example.invalid/registry", Class: Digest, Aliases: []string{"shared"}, RegisteredName: "first", RegisteredIdentifier: "1.2.3", Required: []Dimension{DimensionName}},
		{Name: "shared", OID: "1.2.4", Authority: "IETF", PrimarySource: "https://example.invalid/registry", Class: Digest, RegisteredName: "shared", RegisteredIdentifier: "1.2.4", Required: []Dimension{DimensionName}},
	}
	_, err := NewResolver(records)
	if err == nil || !strings.Contains(err.Error(), `duplicate selector "shared"`) {
		t.Fatalf("NewResolver() error = %v, want duplicate selector for alias", err)
	}
}

func primitiveForClass(class ObjectClass) string {
	switch class {
	case Digest:
		return "hash"
	case XOF:
		return "xof"
	case MAC:
		return "mac"
	case Cipher:
		return "block-cipher"
	case Signature:
		return "signature"
	case PKE:
		return "pke"
	case KEM:
		return "kem"
	case KDF:
		return "kdf"
	case Key:
		return "key"
	case KeyAgreement:
		return "key-agree"
	case KeyWrap:
		return "key-wrap"
	case DRBG:
		return "drbg"
	case Combiner:
		return "combiner"
	case Curve:
		return "curve"
	default:
		return "other"
	}
}

func TestNewResolver_RejectsLocalAuthorityEvidence(t *testing.T) {
	record := Record{
		Name:                 "verified",
		OID:                  "1.2.3",
		Authority:            "IETF",
		PrimarySource:        "docs/research/oid-mapping/report-source.md",
		Class:                Digest,
		RegisteredName:       "verified",
		RegisteredIdentifier: "1.2.3",
		Required:             []Dimension{DimensionName},
	}
	if _, err := NewResolver([]Record{record}); err == nil {
		t.Fatal("NewResolver() accepted a local path as authority evidence")
	}
}
