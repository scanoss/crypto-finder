// Package cryptowrapper provides a high-level encryption API
// that wraps golang.org/x/crypto/chacha20poly1305.
//
// This package exists to test multi-hop dependency call chains:
// user code → cryptowrapper.Encrypt → cryptowrapper.newAEAD → chacha20poly1305.New
package cryptowrapper

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Encrypt encrypts plaintext using ChaCha20-Poly1305 with the given key.
// Delegates to newAEAD for cipher construction, creating a 2-function-deep
// dependency chain that tests multi-hop call graph tracing.
func Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, fmt.Errorf("cryptowrapper: encrypt: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cryptowrapper: generating nonce: %w", err)
	}

	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts ciphertext using ChaCha20-Poly1305 with the given key.
// Delegates to newAEAD for cipher construction.
func Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, fmt.Errorf("cryptowrapper: decrypt: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("cryptowrapper: ciphertext too short")
	}

	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("cryptowrapper: decryption failed: %w", err)
	}

	return plaintext, nil
}

// newAEAD creates a new ChaCha20-Poly1305 AEAD cipher.
// This internal function adds depth to the call chain:
// user code → Encrypt/Decrypt → newAEAD → chacha20poly1305.New
func newAEAD(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}
