// Package mypkg provides application-level encryption functions.
// It delegates to the cryptowrapper dependency — it does NOT
// call chacha20poly1305 directly. This creates the call chain:
//
//	main → mypkg.SecureEncrypt → cryptowrapper.Encrypt → chacha20poly1305.New
package mypkg

import (
	"fmt"

	"example.com/cryptowrapper"
)

// SecureEncrypt encrypts plaintext by delegating to the cryptowrapper dependency.
func SecureEncrypt(key []byte, plaintext []byte) ([]byte, error) {
	encrypted, err := cryptowrapper.Encrypt(key, plaintext)
	if err != nil {
		return nil, fmt.Errorf("mypkg: encrypt failed: %w", err)
	}
	return encrypted, nil
}

// SecureDecrypt decrypts ciphertext by delegating to the cryptowrapper dependency.
func SecureDecrypt(key []byte, ciphertext []byte) ([]byte, error) {
	decrypted, err := cryptowrapper.Decrypt(key, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("mypkg: decrypt failed: %w", err)
	}
	return decrypted, nil
}
