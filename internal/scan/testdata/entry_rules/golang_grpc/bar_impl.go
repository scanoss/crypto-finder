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

type mockQuuxImpl struct{}

// NewMockQuux is a test double by its name.
func NewMockQuux() bar.QuuxServer {
	return &mockQuuxImpl{}
}

func (s *mockQuuxImpl) Hash(ctx context.Context, req *bar.SignRequest) (*bar.SignResponse, error) {
	_ = sha512.Sum512_256([]byte("mock"))
	return nil, nil
}

type altImpl struct{}

// NewQuuxAlt is never called, while NewQuux is.
func NewQuuxAlt() bar.QuuxServer {
	return &altImpl{}
}

func (s *altImpl) Hash(ctx context.Context, req *bar.SignRequest) (*bar.SignResponse, error) {
	_ = sha512.Sum512_224([]byte("alt"))
	return nil, nil
}

type multiImpl struct{}

func (s *multiImpl) Hash(ctx context.Context, req *bar.SignRequest) (*bar.SignResponse, error) {
	_ = sha512.Sum512_224([]byte("multi"))
	return nil, nil
}

// httpImpl has a gRPC-shaped method but is registered with a project function
// that has nothing to do with gRPC.
type httpImpl struct{}

func (s *httpImpl) Hash(ctx context.Context, req *bar.SignRequest) (*bar.SignResponse, error) {
	_ = sha512.New384(nil)
	return nil, nil
}

// nopeImpl is registered with a registrar nothing says is gRPC.
type nopeImpl struct{}

func (s *nopeImpl) Hash(ctx context.Context, req *bar.SignRequest) (*bar.SignResponse, error) {
	_ = sha512.New512_224(nil)
	return nil, nil
}

// streamImpl has two stream-shaped methods, only one for the service.
type streamImpl struct{}

func (s *streamImpl) Watch(req *bar.SignRequest, stream bar.Stream_WatchServer) error {
	_ = sha512.Sum512_256(nil)
	return nil
}

func (s *streamImpl) Other(req *bar.SignRequest, stream bar.Audit_FeedServer) error {
	_ = sha512.Sum384(nil)
	return nil
}

type helperImpl struct{}

func (s *helperImpl) Hash(ctx context.Context, req *bar.SignRequest) (*bar.SignResponse, error) {
	_ = sha512.Sum512_224([]byte("helper"))
	return nil, nil
}
