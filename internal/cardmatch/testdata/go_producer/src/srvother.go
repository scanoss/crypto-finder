package main

import "example.com/other/srv"

func otherPathServer() {
	s := srv.NewUnstarted(nil)
	s.StartTLS()
}
