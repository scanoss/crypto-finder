package main

import (
	"crypto/tls"

	"example.com/dep/hasher"
)

var suites = []uint16{tls.TLS_AES_128_GCM_SHA256}

func config(min uint16) *tls.Config {
	if min == tls.VersionTLS10 {
		min = tls.VersionTLS12
	}
	switch min {
	case tls.VersionTLS13:
	}
	return &tls.Config{MinVersion: min, CipherSuites: suites, CurvePreferences: []tls.CurveID{tls.X25519}}
}

func size() int {
	var cfg tls.Config
	_ = cfg
	return hasher.Size
}
