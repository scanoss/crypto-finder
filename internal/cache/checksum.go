package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// CalculateSHA256 calculates the SHA256 checksum of the given data.
func CalculateSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// VerifyChecksum verifies that the calculated checksum matches the expected checksum.
func VerifyChecksum(data []byte, expectedChecksum string) error {
	actualChecksum := CalculateSHA256(data)
	if actualChecksum != expectedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
	}
	return nil
}
