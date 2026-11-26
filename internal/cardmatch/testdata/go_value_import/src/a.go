package main

import (
	"fmt"

	"example.com/acme/ssh"
	"example.com/acme/tls"
)

func a() {
	c := &tls.Config{}
	d := tls.Config{MinVersion: 1}
	s := &ssh.ServerConfig{NoClientAuth: true}
	k := new(ssh.Key)
	fmt.Println(c, d, s, k)
}
