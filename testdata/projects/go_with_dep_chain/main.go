package main

import (
	"fmt"
	"log"

	"example.com/dep-chain-test/mypkg"
)

func main() {
	key := make([]byte, 32) // ChaCha20-Poly1305 key size
	message := []byte("Hello, multi-hop dependency chain test!")

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
