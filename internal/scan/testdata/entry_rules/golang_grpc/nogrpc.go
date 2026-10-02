package main

import "example.com/ext/bar"

// This file does not import grpc: a registrar of no known type is no evidence.
func registerNope(registrar any) {
	bar.RegisterNopeServer(registrar, &nopeImpl{})
}
