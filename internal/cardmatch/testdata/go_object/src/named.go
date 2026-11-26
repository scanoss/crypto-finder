package main

import (
	"fmt"

	"example.com/go-acme/v4"
)

func useNamed(c *acme.Client) {
	c.Do(nil)
	fmt.Println()
}

func passNamed() {
	useNamed(&acme.Client{URL: "x"})
}

func useUnpassed(c *acme.Client) {
	c.Do(nil)
}
