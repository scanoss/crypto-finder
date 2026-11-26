package main

import x "example.com/go-acme/v4"

func useAliased(c *x.Client) {
	c.Do(nil)
}

func passAliased() {
	useAliased(&x.Client{URL: "x"})
}
