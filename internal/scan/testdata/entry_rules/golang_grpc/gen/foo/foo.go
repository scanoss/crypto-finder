package foo

import "context"

type EncryptRequest struct{}
type EncryptResponse struct{}

type FooServer interface {
	Encrypt(context.Context, *EncryptRequest) (*EncryptResponse, error)
	Watch(*EncryptRequest, Foo_WatchServer) error
}

type Foo_WatchServer interface{}

type grpcRegistrar interface{}

func RegisterFooServer(s grpcRegistrar, srv FooServer) {}

func RegisterFooHandlerServer(ctx context.Context, mux any, srv FooServer) error { return nil }
