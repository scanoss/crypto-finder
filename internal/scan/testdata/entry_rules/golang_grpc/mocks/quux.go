package mocks

import (
	"context"
	"crypto/sha512"

	"example.com/ext/bar"
)

type quuxDouble struct{}

// NewQuux builds a test double of the service.
func NewQuux() bar.QuuxServer {
	return &quuxDouble{}
}

func (s *quuxDouble) Hash(ctx context.Context, req *bar.SignRequest) (*bar.SignResponse, error) {
	_ = sha512.New512_384()
	return nil, nil
}
