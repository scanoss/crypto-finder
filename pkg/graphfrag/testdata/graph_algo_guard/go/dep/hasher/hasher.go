package hasher

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"

	"example.com/dep/internal/pad"
)

type Hasher interface {
	Sum(data []byte) []byte
}

type macHasher struct {
	key []byte
}

func New(key []byte) Hasher {
	return &macHasher{key: pad.Key(key)}
}

func (m *macHasher) mac() hash.Hash {
	return hmac.New(sha256.New, m.key)
}

func (m *macHasher) Sum(data []byte) []byte {
	h := m.mac()
	h.Write(data)
	return h.Sum(nil)
}

func Verify(h Hasher, data, want []byte) bool {
	return hmac.Equal(h.Sum(data), want)
}
