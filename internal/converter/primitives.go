package converter

import (
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// mapPrimitiveToCycloneDX maps interim primitive string to CycloneDX primitive enum.
func mapPrimitiveToCycloneDX(primitive string) (cdx.CryptoPrimitive, error) {
	// Normalize to lowercase for comparison
	primitiveLower := strings.ToLower(strings.TrimSpace(primitive))

	switch primitiveLower {
	case "ae":
		return cdx.CryptoPrimitiveAE, nil
	case "block-cipher":
		return cdx.CryptoPrimitiveBlockCipher, nil
	case "stream-cipher":
		return cdx.CryptoPrimitiveStreamCipher, nil
	case "hash":
		return cdx.CryptoPrimitiveHash, nil
	case "signature":
		return cdx.CryptoPrimitiveSignature, nil
	case "mac":
		return cdx.CryptoPrimitiveMAC, nil
	case "kdf":
		return cdx.CryptoPrimitiveKDF, nil
	case "pke":
		return cdx.CryptoPrimitivePKE, nil
	case "kem":
		return cdx.CryptoPrimitiveKEM, nil
	case "xof":
		return cdx.CryptoPrimitiveXOF, nil
	case "key-agree":
		return cdx.CryptoPrimitiveKeyAgree, nil
	case "combiner":
		return cdx.CryptoPrimitiveCombiner, nil
	case "drbg":
		return cdx.CryptoPrimitiveDRBG, nil
	default:
		return "", fmt.Errorf("unknown primitive type: %s (supported: ae, block-cipher, stream-cipher, hash, signature, mac, kdf, pke, kem, xof, key-agree, combiner, drbg, other, unknown)", primitive)
	}
}
