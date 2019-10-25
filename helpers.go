package schnorrkel

// https://github.com/w3f/schnorrkel/blob/718678e51006d84c7d8e4b6cde758906172e74f8/src/scalars.rs#L18
func divideScalarByCofactor(s []byte) []byte {
	l := len(s) - 1
	low := byte(0)
	for i := range s {
		r := s[l-i] & 0b00000111 // remainder
		s[l-i] >>= 3
		s[l-i] += low
		low = r << 5
	}

	return s
}
