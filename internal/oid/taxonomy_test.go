package oid

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// These assignments make the raw-to-prepared seam a compile-time contract: only
// InterimReport can be prepared and projections can only receive ResolvedReport.
var (
	_ func(*Resolver, *entities.InterimReport) (*PreparedReport, error) = (*Resolver).PrepareReport
	_ func(*PreparedReport) *ResolvedReport                             = (*PreparedReport).ReportClone
)

func TestResolver_OperationDiscriminatedSM2AndSM9(t *testing.T) {
	resolver := NewDefaultResolver()
	tests := []struct {
		name, primitive, operation, want string
	}{
		{"SM2 signature", "signature", "sign", "1.2.156.10197.1.301.1"},
		{"SM2 key exchange", "key-agree", "key-exchange", "1.2.156.10197.1.301.2"},
		{"SM2 encryption", "pke", "encrypt", "1.2.156.10197.1.301.3"},
		{"SM9 signature", "signature", "sign", "1.2.156.10197.1.302.1"},
		{"SM9 key exchange", "key-agree", "key-exchange", "1.2.156.10197.1.302.2"},
		{"SM9 encryption", "pke", "encrypt", "1.2.156.10197.1.302.3"},
		{"SM9 KEM", "kem", "kem", "1.2.156.10197.1.302.4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := &entities.CryptographicAsset{Metadata: map[string]string{
				"assetType": "algorithm", "algorithmName": tt.name[:3], "algorithmPrimitive": tt.primitive, "cryptoFunction": tt.operation,
			}}
			got := resolver.ResolveAsset(asset)
			if got.Outcome != Exact || got.OID != tt.want {
				t.Fatalf("ResolveAsset() = %#v, want exact %q", got, tt.want)
			}
		})
	}
}

func TestResolver_GenericChineseFamilyRequiresKnownOperation(t *testing.T) {
	resolver := NewDefaultResolver()
	for _, tt := range []struct {
		name, operation string
		want            Outcome
	}{
		{"missing operation", "", NoExactSelection},
		{"unsupported operation", "derive", InvalidEvidence},
		{"incompatible operation primitive", "sign", InvalidEvidence},
	} {
		t.Run(tt.name, func(t *testing.T) {
			primitive := "signature"
			if tt.name == "incompatible operation primitive" {
				primitive = "pke"
			}
			got := resolver.ResolveAsset(&entities.CryptographicAsset{Metadata: map[string]string{
				"assetType": "algorithm", "algorithmName": "SM2", "algorithmPrimitive": primitive, "cryptoFunction": tt.operation,
			}})
			if got.Outcome != tt.want || got.OID != "" {
				t.Fatalf("ResolveAsset() = %#v, want %v without OID", got, tt.want)
			}
		})
	}
}

func TestResolver_CurveProjectionIsSeparateFromAlgorithmOID(t *testing.T) {
	resolver := NewDefaultResolver()
	curve := resolver.ResolveCurve("secp256k1")
	if curve.Outcome != Exact || curve.OID != "1.3.132.0.10" || curve.Record != "secp256k1" {
		t.Fatalf("ResolveCurve(secp256k1) = %#v", curve)
	}
	for _, tt := range []struct {
		name string
		want Outcome
	}{{"BLS12-381", NoStandard}, {"Curve25519", Unresolved}} {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolver.ResolveCurve(tt.name); got.Outcome != tt.want || got.OID != "" {
				t.Fatalf("ResolveCurve(%q) = %#v, want %v without OID", tt.name, got, tt.want)
			}
		})
	}

	p256 := resolver.ResolveCurve("P-256")
	if p256.Outcome != Exact || p256.OID != "1.2.840.10045.3.1.7" {
		t.Fatalf("ResolveCurve(P-256) = %#v", p256)
	}
	asset := asset("ECDSA", "ECDSA-SHA256", "", "", "signature")
	asset.Metadata["ellipticCurve"] = "secp256k1"
	if got := resolver.ResolveAsset(&asset); got.OID != "1.2.840.10045.4.3.2" {
		t.Fatalf("algorithm OID was replaced by curve OID: %#v", got)
	}
}

func TestResolver_KeyAndKeyAgreementRemainSeparateClasses(t *testing.T) {
	resolver := NewDefaultResolver()
	key := resolver.ResolveAsset(&entities.CryptographicAsset{Metadata: map[string]string{
		"assetType": "algorithm", "algorithmName": "RSA-KEY", "algorithmPrimitive": "key",
	}})
	if key.Outcome != Exact || key.OID != "1.2.840.113549.1.1.1" {
		t.Fatalf("RSA key resolution = %#v", key)
	}
	agreement := resolver.ResolveAsset(&entities.CryptographicAsset{Metadata: map[string]string{
		"assetType": "algorithm", "algorithmName": "X25519", "algorithmPrimitive": "key-agree",
	}})
	if agreement.Outcome != Exact || agreement.OID != "1.3.101.110" {
		t.Fatalf("X25519 key-agreement resolution = %#v", agreement)
	}
	wrongClass := resolver.ResolveAsset(&entities.CryptographicAsset{Metadata: map[string]string{
		"assetType": "algorithm", "algorithmName": "RSA-KEY", "algorithmPrimitive": "pke",
	}})
	if wrongClass.Outcome != NoExactSelection || wrongClass.OID != "" {
		t.Fatalf("RSA key was conflated with PKE: %#v", wrongClass)
	}
}

func TestResolver_NonEmittingNamespaces(t *testing.T) {
	resolver := NewDefaultResolver()
	for _, tt := range []struct {
		name, primitive string
		want            Outcome
	}{
		{"PBKDF1", "kdf", NoStandard},
		{"yescrypt", "kdf", NoStandard},
		{"SP800-108", "kdf", NoStandard},
		{"SP800-56C", "kdf", NoStandard},
		{"ANSI-KDF", "kdf", NoStandard},
		{"TLS-PRF", "kdf", NoStandard},
		{"DRBG", "drbg", NoStandard},
		{"Kyber", "kem", Unresolved},
		{"Dilithium", "signature", Unresolved},
		{"SPHINCS+", "signature", Unresolved},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := resolver.ResolveAsset(&entities.CryptographicAsset{Metadata: map[string]string{
				"assetType": "algorithm", "algorithmName": tt.name, "algorithmPrimitive": tt.primitive,
			}})
			if got.Outcome != tt.want || got.OID != "" {
				t.Fatalf("ResolveAsset() = %#v, want %v without OID", got, tt.want)
			}
		})
	}
}

func TestResolver_EvidenceIntersectionAndClaimPrecedence(t *testing.T) {
	resolver := NewDefaultResolver()
	for _, tt := range []struct {
		name  string
		asset entities.CryptographicAsset
		want  Outcome
	}{
		{"digest function matches digest class", entities.CryptographicAsset{Metadata: map[string]string{"assetType": "algorithm", "algorithmName": "SHA-256", "algorithmPrimitive": "hash", "cryptoFunction": "digest"}}, Exact},
		{"function conflicts with primitive", entities.CryptographicAsset{Metadata: map[string]string{"assetType": "algorithm", "algorithmName": "SHA-256", "algorithmPrimitive": "hash", "cryptoFunction": "encrypt"}}, InvalidEvidence},
		{"unknown function is invalid", entities.CryptographicAsset{Metadata: map[string]string{"assetType": "algorithm", "algorithmName": "SHA-256", "algorithmPrimitive": "hash", "cryptoFunction": "unknown"}}, InvalidEvidence},
		{"malformed claim wins over invalid evidence", entities.CryptographicAsset{OID: "not-an-oid", Metadata: map[string]string{"assetType": "algorithm", "algorithmName": "SHA-256", "algorithmPrimitive": "other"}}, RejectedClaim},
		{"known family arc is a blocked claim", entities.CryptographicAsset{OID: "2.16.840.1.101.3.4.1", Metadata: map[string]string{"assetType": "algorithm", "algorithmName": "AES", "algorithmPrimitive": "block-cipher"}}, RejectedClaim},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolver.ResolveAsset(&tt.asset); got.Outcome != tt.want {
				t.Fatalf("ResolveAsset() = %#v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewResolver_RejectsNonEmittingRegistrationState(t *testing.T) {
	_, err := NewResolver([]Record{{Name: "draft", OID: "1.2.3", Authority: "IETF", PrimarySource: "source", Class: Digest, State: Draft}})
	if err == nil {
		t.Fatal("NewResolver accepted a draft record into the emitting catalog")
	}
}
