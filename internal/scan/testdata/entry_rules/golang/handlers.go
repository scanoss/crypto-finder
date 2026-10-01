package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha512"
	"net/http"
)

func digest(w http.ResponseWriter, r *http.Request) {
	_ = md5.Sum([]byte(r.URL.Path))
}

func legacy(w http.ResponseWriter, r *http.Request) {
	_ = sha1.Sum([]byte(r.URL.Path))
}

type api struct{}

func (a *api) sign(w http.ResponseWriter, r *http.Request) {
	_ = sha512.Sum512([]byte(r.URL.Path))
}

type metrics struct{}

func (m metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = hmac.New(sha512.New384, []byte("metrics"))
}

// Nothing calls it and no rule makes it an entry point.
func orphan() {
	_ = sha512.Sum384([]byte("orphan"))
}

type audit struct{}

// Same name as the api.sign that main registers, on a type nothing
// registers: not an entry point.
func (a *audit) sign(w http.ResponseWriter, r *http.Request) {
	_ = md5.New().Sum([]byte(r.URL.Path))
}
