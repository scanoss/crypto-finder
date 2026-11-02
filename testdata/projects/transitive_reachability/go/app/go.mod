module example.com/transapp

go 1.21

require example.com/transliba v0.0.0

require example.com/translibb v0.0.0 // indirect

replace example.com/transliba => ../liba

replace example.com/translibb => ../libb
