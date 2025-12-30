package main

import (
	"crypto/des"
	"crypto/tls"
)

func main() {
	// Should trigger go.crypto.tls.load-key-pair
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	_ = cert
	_ = err

	// Should trigger go.crypto.des.key-generation
	keyStr := "12345678"
	block, _ := des.NewCipher([]byte(keyStr))
	_ = block
}
