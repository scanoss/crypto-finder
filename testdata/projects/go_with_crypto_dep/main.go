package main

import (
	"fmt"
	"log"

	"example.com/crypto-test/mypkg"
)

func main() {
	key := make([]byte, 32) // ChaCha20-Poly1305 key size
	message := []byte("Hello, crypto-finder dependency scanning!")

	encrypted, err := mypkg.SecureEncrypt(key, message)
	if err != nil {
		log.Fatal(err)
	}

	decrypted, err := mypkg.SecureDecrypt(key, encrypted)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Original:  %s\n", message)
	fmt.Printf("Decrypted: %s\n", decrypted)
}
