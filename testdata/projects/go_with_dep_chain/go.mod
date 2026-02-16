module example.com/dep-chain-test

go 1.21

require example.com/cryptowrapper v0.0.0

require (
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
)

replace example.com/cryptowrapper => ../cryptowrapper_dep
