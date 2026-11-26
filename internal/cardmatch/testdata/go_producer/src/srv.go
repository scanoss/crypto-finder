package main

import "example.com/acme/srv"

func typedServer(s *srv.Server) {
	s.StartTLS()
}

func producedServer() {
	s := srv.NewUnstarted(nil)
	s.StartTLS()
}

func otherServer() {
	s := srv.Started(nil)
	s.StartTLS()
}
