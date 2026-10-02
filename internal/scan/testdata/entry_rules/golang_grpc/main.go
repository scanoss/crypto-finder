package main

import (
	"context"
	"net"
	"net/http"

	"example.com/ext/bar"
	"example.com/ext/boot"
	"example.com/ext/httpx"
	"example.com/grpcreg/gen/foo"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
)

func newGRPC() (net.Listener, *grpc.Server, error) { return nil, nil, nil }

func main() {
	var anything any
	// The interface is in the tree: no registrar evidence is needed.
	foo.RegisterFooServer(anything, &fooImpl{})

	gs := grpc.NewServer()
	bar.RegisterBarServer(gs, NewBar())

	mux := runtime.NewServeMux()
	baz := &bazImpl{}
	bar.RegisterBazHandlerServer(context.Background(), mux, baz)

	// The type of the value is unknown: nothing is registered.
	bar.RegisterQuxServer(gs, makeQux(&quxImpl{}))

	_ = NewQuux()

	// The registrar is a result of a function of the package.
	_, srv, _ := newGRPC()
	bar.RegisterMultiServer(srv, &multiImpl{})

	// The registrar comes from a function outside the tree and the file
	// imports grpc.
	_, helper, _ := boot.Listen()
	bar.RegisterHelperServer(helper, &helperImpl{})

	// A registrar of a known type that is not gRPC: nothing is rooted.
	httpx.RegisterHTTPServer(&http.ServeMux{}, &httpImpl{})
	httpx.RegisterHTTPServer(http.NewServeMux(), &httpImpl{})
	registerNope(anything)

	bar.RegisterStreamServer(gs, &streamImpl{})
}

// register is handed the service typed as the generated interface: the
// types that functions declaring that interface build are the service.
func register(gs *grpc.Server, srv bar.QuuxServer) {
	bar.RegisterQuuxServer(gs, srv)
}
