package main

import (
	"context"
	"crypto/sha512"

	pb "example.com/shop/gen/keys"
)

type keyServer struct {
	pb.UnimplementedKeysServer
}

func (s *keyServer) Rotate(ctx context.Context, req *pb.RotateRequest) (*pb.RotateResponse, error) {
	_ = sha512.Sum512_256([]byte("rotate"))
	return &pb.RotateResponse{}, nil
}
