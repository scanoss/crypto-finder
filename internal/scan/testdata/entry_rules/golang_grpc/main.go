package main

import (
	"context"

	"example.com/ext/bar"
	"example.com/grpcreg/gen/foo"
)

func main() {
	var grpcServer any
	foo.RegisterFooServer(grpcServer, &fooImpl{})
	bar.RegisterBarServer(grpcServer, NewBar())

	baz := &bazImpl{}
	bar.RegisterBazHandlerServer(context.Background(), nil, baz)

	// The type of the value is unknown: nothing is registered.
	bar.RegisterQuxServer(grpcServer, makeQux(&quxImpl{}))
}

// register is handed the service typed as the generated interface: the
// types that functions declaring that interface build are the service.
func register(grpcServer any, srv bar.QuuxServer) {
	bar.RegisterQuuxServer(grpcServer, srv)
}
