package main

import (
	"crypto/sha256"
	"net/http"
)

var bootKey = sha256.Sum224([]byte("boot"))

func init() {
	_ = sha256.Sum256([]byte("init"))
}

func main() {
	signer := &api{}
	http.HandleFunc("/digest", digest)
	http.Handle("/legacy", http.HandlerFunc(legacy))
	http.HandleFunc("/sign", signer.sign)
	http.Handle("/metrics", metrics{})
	_ = http.ListenAndServe(":8080", nil)
}
