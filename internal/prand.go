package internal

// Prand16 generates a pseudo random number from a seed.
func Prand16(seed uint16) uint16 {
	// 16bit Xorshift  https://en.wikipedia.org/wiki/Xorshift
	seed ^= seed << 7
	seed ^= seed >> 9
	seed ^= seed << 8
	return seed
}

// Prand32 generates a pseudo random number from a seed.
func Prand32[T ~uint32](seed T) T {
	/* Algorithm "xor" from p. 4 of Marsaglia, "Xorshift RNGs" */
	seed ^= seed << 13
	seed ^= seed >> 17
	seed ^= seed << 5
	return seed
}
