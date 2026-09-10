// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package oid resolves only exact, registered cryptographic object identifiers.
package oid

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// Outcome is the exclusive terminal disposition of an OID resolution.
type Outcome uint8

// Resolution dispositions.
const (
	Exact Outcome = iota
	RejectedClaim
	InvalidEvidence
	NoExactSelection
	AmbiguousSelection
	NoStandard
	Unresolved
)

// ObjectClass identifies the semantic object type an OID identifies.
type ObjectClass uint8

// Supported cryptographic object classes.
const (
	Digest ObjectClass = iota
	XOF
	MAC
	Cipher
	Signature
	PKE
	KEM
	KDF
	Key
	KeyAgreement
	KeyWrap
	DRBG
	Combiner
	Curve
)

// RegistrationState says whether a registry entry can be emitted as an exact
// identity. Draft and expired registrations stay in separate non-emitting
// dispositions and are never accepted by the positive catalog.
type RegistrationState uint8

// Registry states used by the exact object catalog.
const (
	Standardized RegistrationState = iota
	Registered
	Legacy
	Deprecated
	Draft
	Expired
)

// Dimension identifies a discriminator which must be present to select a record.
type Dimension string

// Dimension values used by catalog selection.
const (
	DimensionName         Dimension = "algorithmName"
	DimensionFamily       Dimension = "algorithmFamily"
	DimensionMode         Dimension = "algorithmMode"
	DimensionParameterSet Dimension = "algorithmParameterSetIdentifier"
)

// Record is a source-verified exact OID registration. Name is the selector
// spelling; RegisteredName and RegisteredIdentifier retain the authoritative
// registration facts rather than treating a convenient selector as evidence.
type Record struct {
	Name, OID, Authority, PrimarySource  string
	Class                                ObjectClass
	Aliases                              []string
	Family, Mode, KeySize                string
	State                                RegistrationState
	RegisteredName, RegisteredIdentifier string
	Required                             []Dimension
}

// Result is the selected exact identity or deliberate omission disposition.
type Result struct {
	OID     string
	Outcome Outcome
	Record  string
}

// Summary counts mutually exclusive resolution dispositions.
type Summary struct{ Total, Exact, RejectedClaim, InvalidEvidence, NoExactSelection, AmbiguousSelection, NoStandard, Unresolved int }

// ResolvedReport is intentionally distinct from an input InterimReport.
type ResolvedReport entities.InterimReport

// PreparedReport owns an immutable resolved clone and its private provenance.
type PreparedReport struct {
	report  *ResolvedReport
	results []Result
	summary Summary
}

// Resolver resolves exact OIDs from a construction-validated catalog.
type Resolver struct {
	records []Record
	index   map[string][]Record
}

const kemOperation = "KEM"

var (
	oidPattern = regexp.MustCompile(`^([012])(\.\d+)+$`)

	// genericOperationSelectors names the report's generic Chinese algorithms
	// only after the rule gives their exact operation. The registered OID is an
	// operation object, never a generic SM2 or SM9 family identity.
	genericOperationSelectors = map[string]map[string]string{
		"SM2": {
			"SIGN": "SM2-SIGNATURE", "KEY-EXCHANGE": "SM2-KEY-EXCHANGE", "ENCRYPT": "SM2-PKE",
		},
		"SM9": {
			"SIGN": "SM9-SIGNATURE", "KEY-EXCHANGE": "SM9-KEY-EXCHANGE", "ENCRYPT": "SM9-PKE", kemOperation: "SM9-KEM",
		},
	}
)

// NewResolver validates and indexes a source-verified catalog.
func NewResolver(records []Record) (*Resolver, error) {
	r := &Resolver{records: append([]Record(nil), records...), index: make(map[string][]Record)}
	// A selector signature (canonical name or alias) must identify exactly one
	// object. Silently appending duplicate values made ambiguity an accidental
	// runtime outcome and allowed aliases to shadow canonical registered names.
	seen := make(map[string]string)
	for i := range r.records {
		record := r.records[i]
		if strings.TrimSpace(record.Name) == "" || strings.TrimSpace(record.Authority) == "" || strings.TrimSpace(record.PrimarySource) == "" ||
			strings.TrimSpace(record.RegisteredName) == "" || strings.TrimSpace(record.RegisteredIdentifier) == "" || len(record.Required) == 0 || !validAuthoritySource(record.PrimarySource) {
			return nil, fmt.Errorf("oid: catalog record has missing registered evidence")
		}
		if !validOID(record.OID) || record.RegisteredIdentifier != record.OID || blockedClaim(record.OID) {
			return nil, fmt.Errorf("oid: invalid or forbidden OID %q", record.OID)
		}
		if !emittingState(record.State) {
			return nil, fmt.Errorf("oid: non-emitting registration state for %q", record.Name)
		}
		keys := append([]string{record.Name}, record.Aliases...)
		for _, raw := range keys {
			key := aliasKey(raw, record.Class)
			if prior, exists := seen[key]; exists {
				return nil, fmt.Errorf("oid: duplicate selector %q between %q and %q", raw, prior, record.Name)
			}
			seen[key] = record.Name
			r.index[key] = []Record{record}
		}
	}
	return r, nil
}

// validAuthoritySource rejects local documentation and selector-derived placeholders.
// Production catalog evidence must point at an independently authoritative HTTPS record.
func validAuthoritySource(source string) bool {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(source))
	return err == nil && parsed.Scheme == "https" && parsed.Host != ""
}

// NewDefaultResolver returns the built-in report-backed resolver.
func NewDefaultResolver() *Resolver {
	r, err := NewResolver(defaultRecords())
	if err != nil {
		panic(err)
	}
	return r
}

// ResolveAsset resolves one asset without ever selecting a family or branch arc.
//
//nolint:gocyclo,gocognit // Terminal precedence is deliberately visible and closed.
func (r *Resolver) ResolveAsset(asset *entities.CryptographicAsset) Result {
	if asset == nil || asset.Metadata == nil {
		return Result{Outcome: NoExactSelection}
	}
	if assetType := strings.TrimSpace(asset.Metadata["assetType"]); assetType != "" && assetType != "algorithm" {
		return Result{Outcome: InvalidEvidence}
	}
	topLevelClaim := strings.TrimSpace(asset.OID)
	ruleClaim := strings.TrimSpace(asset.Metadata["oid"])
	if (topLevelClaim != "" && (!validOID(topLevelClaim) || blockedClaim(topLevelClaim))) ||
		(ruleClaim != "" && (!validOID(ruleClaim) || blockedClaim(ruleClaim))) ||
		(topLevelClaim != "" && ruleClaim != "" && topLevelClaim != ruleClaim) {
		return Result{Outcome: RejectedClaim}
	}
	class, ok := classFor(asset.Metadata["algorithmPrimitive"])
	if !ok {
		return Result{Outcome: InvalidEvidence}
	}
	if !functionAllowsClass(asset.Metadata["cryptoFunction"], class) {
		return Result{Outcome: InvalidEvidence}
	}
	if selected, disposition, handled := r.genericOperationCandidate(asset, class); handled {
		if disposition != Exact {
			return Result{Outcome: disposition}
		}
		return selectedResult(selected, topLevelClaim, ruleClaim)
	}
	candidates := r.candidates(asset, class)
	if len(candidates) == 0 {
		if noStandardSelector(asset) {
			return Result{Outcome: NoStandard}
		}
		if unresolvedSelector(asset) {
			return Result{Outcome: Unresolved}
		}
		return Result{Outcome: NoExactSelection}
	}
	if len(candidates) > 1 {
		return Result{Outcome: AmbiguousSelection}
	}
	selected := candidates[0]
	return selectedResult(selected, topLevelClaim, ruleClaim)
}

func selectedResult(selected Record, topLevelClaim, ruleClaim string) Result {
	if (topLevelClaim != "" && topLevelClaim != selected.OID) || (ruleClaim != "" && ruleClaim != selected.OID) {
		return Result{Outcome: RejectedClaim}
	}
	return Result{OID: selected.OID, Outcome: Exact, Record: selected.Name}
}

func noStandardSelector(asset *entities.CryptographicAsset) bool {
	values := []string{normalize(asset.Metadata["algorithmName"]), normalize(asset.Metadata["algorithmFamily"])}
	known := map[string]bool{"ARGON2": true, "BCRYPT": true, "YESCRYPT": true, "PBKDF1": true, "SP800-108": true, "SP800-56C": true, "ANSI-KDF": true, "TLS-PRF": true, "DRBG": true, "BLS12-381": true, "ASCON": true, "BLAKE3": true, "ECIES": true, "SALSA20": true}
	familyDisposition := map[string]bool{"ASCON": true, "BLAKE3": true, "ECIES": true, "SALSA20": true}
	return known[values[0]] || familyDisposition[values[1]]
}

func emittingState(state RegistrationState) bool {
	return state == Standardized || state == Registered || state == Legacy || state == Deprecated
}

func blockedClaim(value string) bool {
	// These are primary-registry namespace/family arcs named by the research
	// report. They identify a branch, not a construction, and must not survive
	// merely because the finding is otherwise missing a discriminator.
	return map[string]bool{
		"2.16.840.1.101.3.4.1": true, // NIST AES namespace
		"2.16.840.1.101.3.4.2": true, // NIST digest/XOF namespace
		"2.16.840.1.101.3.4.3": true, // NIST signature namespace
		"2.16.840.1.101.3.4.4": true, // NIST KEM namespace
		"1.2.156.10197.1.301":  true, // SM2 operation namespace
		"1.2.156.10197.1.302":  true, // SM9 operation namespace
	}[value]
}

func functionAllowsClass(value string, class ObjectClass) bool {
	function := normalize(value)
	if function == "" {
		return true
	}
	allowed := map[string]map[ObjectClass]bool{
		"GENERATE":      {DRBG: true},
		"KEYGEN":        {Key: true},
		"KEYGENERATION": {Key: true},
		"ENCRYPT":       {Cipher: true, PKE: true, KeyWrap: true},
		"DECRYPT":       {Cipher: true, PKE: true, KeyWrap: true},
		"DIGEST":        {Digest: true, XOF: true},
		"HASH":          {Digest: true, XOF: true},
		"TAG":           {MAC: true, Cipher: true},
		"KEYDERIVE":     {KDF: true, KeyAgreement: true},
		"DERIVE":        {KDF: true, KeyAgreement: true},
		"DERIVEKEY":     {KDF: true, KeyAgreement: true},
		"KEYDERIVATION": {KDF: true, KeyAgreement: true},
		"KEYEXCHANGE":   {KeyAgreement: true},
		"KEY-EXCHANGE":  {KeyAgreement: true},
		"SIGN":          {Signature: true},
		"SIGNATURE":     {Signature: true},
		"VERIFY":        {Signature: true},
		"VERIFICATION":  {Signature: true},
		"KEYVER":        {Signature: true},
		"ENCAPSULATE":   {KEM: true},
		"DECAPSULATE":   {KEM: true},
		"KEM":           {KEM: true},
	}
	classes, known := allowed[function]
	return known && classes[class]
}

func unresolvedSelector(asset *entities.CryptographicAsset) bool {
	values := []string{normalize(asset.Metadata["algorithmName"]), normalize(asset.Metadata["algorithmFamily"])}
	known := map[string]bool{"HMAC-MD5": true, "KYBER": true, "DILITHIUM": true, "SPHINCS+": true, "CURVE25519": true, "BLOWFISH": true, "TWOFISH": true, "SERPENT": true, "ZUC": true}
	return known[values[0]] || known[values[1]]
}

// ResolveCurve projects a named curve identity independently of an algorithm
// identity. Callers must never use this result to overwrite an asset algorithm
// OID: a curve, ECDSA operation, and EC public key are different ASN.1 objects.
func (r *Resolver) ResolveCurve(name string) Result {
	normalized := normalize(name)
	for i := range r.records {
		record := &r.records[i]
		if record.Class == Curve && (normalize(record.Name) == normalized || containsAlias(*record, normalized)) {
			return Result{OID: record.OID, Outcome: Exact, Record: record.Name}
		}
	}
	switch normalized {
	case "BLS12-381":
		return Result{Outcome: NoStandard}
	case "CURVE25519":
		return Result{Outcome: Unresolved}
	default:
		return Result{Outcome: NoExactSelection}
	}
}

func (r *Resolver) genericOperationCandidate(asset *entities.CryptographicAsset, class ObjectClass) (Record, Outcome, bool) {
	name := normalize(asset.Metadata["algorithmName"])
	operations, isGenericFamily := genericOperationSelectors[name]
	if !isGenericFamily {
		return Record{}, 0, false
	}
	operation := normalize(asset.Metadata["cryptoFunction"])
	if operation == "" {
		operation = normalize(asset.Metadata["operation"])
	}
	if operation == "" {
		return Record{}, NoExactSelection, true
	}
	operation = canonicalOperation(operation)
	if operation == "" {
		return Record{}, InvalidEvidence, true
	}
	recordName, knownOperation := operations[operation]
	if !knownOperation {
		return Record{}, InvalidEvidence, true
	}
	for i := range r.records {
		record := &r.records[i]
		if record.Name == recordName {
			if record.Class != class {
				return Record{}, InvalidEvidence, true
			}
			return *record, Exact, true
		}
	}
	return Record{}, InvalidEvidence, true
}

func canonicalOperation(value string) string {
	switch normalize(value) {
	case "SIGN", "SIGNATURE", "SIGNING", "VERIFY", "VERIFICATION":
		return "SIGN"
	case "KEY-EXCHANGE", "KEYEXCHANGE", "AGREE", "KEY-AGREE":
		return "KEY-EXCHANGE"
	case "ENCRYPT", "ENCRYPTION", "DECRYPT", "DECRYPTION":
		return "ENCRYPT"
	case kemOperation, "ENCAPSULATE", "DECAPSULATE":
		return kemOperation
	default:
		return ""
	}
}

// PrepareReport deep-clones and resolves a final materialized report once.
func (r *Resolver) PrepareReport(unprepared *entities.InterimReport) (*PreparedReport, error) {
	if unprepared == nil {
		return nil, fmt.Errorf("oid: nil interim report")
	}
	raw, err := json.Marshal(unprepared)
	if err != nil {
		return nil, fmt.Errorf("oid: clone report: %w", err)
	}
	var clone entities.InterimReport
	if err := json.Unmarshal(raw, &clone); err != nil {
		return nil, fmt.Errorf("oid: clone report: %w", err)
	}
	// The interim wire schema intentionally excludes structural terminal columns,
	// but callgraph projections consume them after preparation. Preserve that
	// internal state while still deep-cloning all public maps and slices.
	restoreInternalAssetState(unprepared.Findings, clone.Findings)
	p := &PreparedReport{report: (*ResolvedReport)(&clone)}
	for i := range clone.Findings {
		for j := range clone.Findings[i].CryptographicAssets {
			a := &clone.Findings[i].CryptographicAssets[j]
			result := r.ResolveAsset(a)
			p.results = append(p.results, result)
			add(&p.summary, result.Outcome)
			a.OID = result.OID
		}
	}
	return p, nil
}

func restoreInternalAssetState(source, clone []entities.Finding) {
	for findingIndex := range clone {
		if findingIndex >= len(source) {
			break
		}
		for assetIndex := range clone[findingIndex].CryptographicAssets {
			if assetIndex >= len(source[findingIndex].CryptographicAssets) {
				break
			}
			sourceAsset := source[findingIndex].CryptographicAssets[assetIndex]
			cloneAsset := &clone[findingIndex].CryptographicAssets[assetIndex]
			cloneAsset.TerminalStartCol = sourceAsset.TerminalStartCol
			cloneAsset.TerminalEndCol = sourceAsset.TerminalEndCol
		}
	}
}

// ReportClone returns an independently mutable clone of the prepared report.
//
//nolint:errcheck // JSON round-trip only fails for impossible in-memory schema values.
func (p *PreparedReport) ReportClone() *ResolvedReport {
	if p == nil || p.report == nil {
		return nil
	}
	raw, _ := json.Marshal(p.report)
	var clone ResolvedReport
	_ = json.Unmarshal(raw, &clone)
	restoreInternalAssetState(p.report.Findings, clone.Findings)
	return &clone
}

// Summary returns a value copy of the preparation summary.
func (p *PreparedReport) Summary() Summary {
	if p == nil {
		return Summary{}
	}
	return p.summary
}

//nolint:gocyclo // Matching exact evidence is intentionally explicit.
func (r *Resolver) candidates(a *entities.CryptographicAsset, class ObjectClass) []Record {
	name := normalize(a.Metadata["algorithmName"])
	family := normalize(a.Metadata["algorithmFamily"])
	mode := normalize(a.Metadata["algorithmMode"])
	keySize := normalize(a.Metadata["algorithmParameterSetIdentifier"])
	var matches []Record
	for i := range r.records {
		rec := r.records[i]
		if rec.Class != class {
			continue
		}
		if name != "" && normalize(rec.Name) != name && !containsAlias(rec, name) {
			continue
		}
		if name == "" && family != normalize(rec.Family) {
			continue
		}
		if rec.Mode != "" && mode != normalize(rec.Mode) {
			continue
		}
		if rec.KeySize != "" && keySize != normalize(rec.KeySize) {
			continue
		}
		if name != "" && rec.Family != "" && family != "" && !sameFamily(family, normalize(rec.Family)) {
			continue
		}
		matches = append(matches, rec)
	}
	return matches
}

func add(s *Summary, o Outcome) {
	s.Total++
	switch o {
	case Exact:
		s.Exact++
	case RejectedClaim:
		s.RejectedClaim++
	case InvalidEvidence:
		s.InvalidEvidence++
	case NoExactSelection:
		s.NoExactSelection++
	case AmbiguousSelection:
		s.AmbiguousSelection++
	case NoStandard:
		s.NoStandard++
	case Unresolved:
		s.Unresolved++
	}
}

func validOID(value string) bool {
	if !oidPattern.MatchString(value) {
		return false
	}
	parts := strings.Split(value, ".")
	return len(parts) > 1 && (parts[0] == "2" || parts[1] < "40")
}

func normalize(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	value = strings.NewReplacer("_", "-", " ", "-", "/", "-").Replace(value)
	for strings.Contains(value, "--") {
		value = strings.ReplaceAll(value, "--", "-")
	}
	return strings.Trim(value, "-")
}

func classFor(p string) (ObjectClass, bool) {
	switch normalize(p) {
	case "HASH":
		return Digest, true
	case "XOF":
		return XOF, true
	case "MAC":
		return MAC, true
	case "AE", "BLOCK-CIPHER", "STREAM-CIPHER":
		return Cipher, true
	case "SIGNATURE":
		return Signature, true
	case "PKE":
		return PKE, true
	case "KEM":
		return KEM, true
	case "KDF":
		return KDF, true
	case "KEY":
		return Key, true
	case "KEY-AGREE":
		return KeyAgreement, true
	case "KEY-WRAP":
		return KeyWrap, true
	case "DRBG":
		return DRBG, true
	case "COMBINER":
		return Combiner, true
	}
	return 0, false
}

func aliasKey(name string, class ObjectClass) string {
	return fmt.Sprintf("%d:%s", class, normalize(name))
}

func sameFamily(a, b string) bool {
	return a == b || (a == "SHA" && b == "SHA-2") || (a == "SHA-2" && b == "SHA")
}

func containsAlias(r Record, n string) bool {
	for _, a := range r.Aliases {
		if normalize(a) == n {
			return true
		}
	}
	return false
}

//go:embed catalog.json
var defaultCatalog []byte

// defaultRecords loads the committed, independently curated authority catalog.
// It deliberately does not synthesize registered names, identifiers, required
// dimensions, registration state, or source references from selector data.
func defaultRecords() []Record {
	var records []Record
	if err := json.Unmarshal(defaultCatalog, &records); err != nil {
		panic(fmt.Sprintf("oid: decode embedded authority catalog: %v", err))
	}
	return records
}
