package main

import (
	"context"
	"crypto/sha512"

	"example.com/ext/bar"
)

type barImpl struct{}

// NewBar declares the generated interface as its result.
func NewBar() bar.BarServer {
	return &barImpl{}
}

func (s *barImpl) Sign(ctx context.Context, req *bar.SignRequest) (*bar.SignResponse, error) {
	_ = sha512.Sum512([]byte("sign"))
	return nil, nil
}

func (s *barImpl) Verify(ctx context.Context, req *bar.SignRequest) (*bar.SignResponse, error) {
	_ = sha512.Sum384([]byte("verify"))
	return nil, nil
}

// Rebuild is exported but has no gRPC signature.
func (s *barImpl) Rebuild(key []byte) []byte {
	_ = sha512.Sum512_256(key)
	return key
}

func (s *barImpl) tidy() {
	_ = sha512.Sum512_224(nil)
}

type bazImpl struct{}

func (s *bazImpl) Hash(ctx context.Context, req *bar.SignRequest) (*bar.SignResponse, error) {
	_ = sha512.New()
	return nil, nil
}

type quxImpl struct{}

func (s *quxImpl) Hash(ctx context.Context, req *bar.SignRequest) (*bar.SignResponse, error) {
	_ = sha512.New384()
	return nil, nil
}

func makeQux(v any) any { return v }

type quuxImpl struct{}

// NewQuux declares the interface the service is registered as.
func NewQuux() bar.QuuxServer {
	return &quuxImpl{}
}

func (s *quuxImpl) Hash(ctx context.Context, req *bar.SignRequest) (*bar.SignResponse, error) {
	_ = sha512.New512_256()
	return nil, nil
}

type otherImpl2 struct{}

// NewAudit builds another interface, which nothing registers.
func NewAudit() bar.AuditSink {
	return &otherImpl2{}
}

func (s *otherImpl2) Hash(ctx context.Context, req *bar.SignRequest) (*bar.SignResponse, error) {
	_ = sha512.New512_224()
	return nil, nil
}
