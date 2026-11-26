package pad

func Key(key []byte) []byte {
	if len(key) >= 32 {
		return key
	}
	out := make([]byte, 32)
	copy(out, key)
	return out
}
