package main

import (
	"example.com/acme/srv"
	other "example.com/other/srv"
)

func lookalikeServer() {
	s := other.NewUnstarted(nil)
	s.StartTLS()
	_ = srv.Version
}
