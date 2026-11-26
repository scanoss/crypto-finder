package main

import "example.com/types/codec"

func encode(data []byte) (string, string) {
	enc := codec.New("app")
	buf := make([]byte, 1<<4)
	_ = buf
	sealer := codec.NewSealer()
	_ = sealer.Seal(data)
	return enc.Encode(data), codec.Std.Encode(data)
}
