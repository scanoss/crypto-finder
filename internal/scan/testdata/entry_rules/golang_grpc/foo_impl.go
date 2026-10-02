package main

import (
	"context"
	"crypto/sha256"

	"example.com/grpcreg/gen/foo"
)

type fooImpl struct{}

func (s *fooImpl) Encrypt(ctx context.Context, req *foo.EncryptRequest) (*foo.EncryptResponse, error) {
	_ = sha256.Sum256([]byte("encrypt"))
	return &foo.EncryptResponse{}, nil
}

func (s *fooImpl) Watch(req *foo.EncryptRequest, stream foo.Foo_WatchServer) error {
	_ = sha256.Sum224([]byte("watch"))
	return nil
}

// Rebuild has a gRPC-shaped signature but is no method of FooServer.
func (s *fooImpl) Rebuild(ctx context.Context, req *foo.EncryptRequest) (*foo.EncryptResponse, error) {
	_ = sha256.New()
	return nil, nil
}

// otherImpl has FooServer's method names but is never registered.
type otherImpl struct{}

func (s *otherImpl) Encrypt(ctx context.Context, req *foo.EncryptRequest) (*foo.EncryptResponse, error) {
	_ = sha256.New224()
	return nil, nil
}
