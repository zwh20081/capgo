package capgo

import (
	"fmt"
	"strings"
	"unicode/utf16"
)

// fnv1a32 hashes UTF-16 code units exactly like the JavaScript
// implementation shared by @cap.js/server, capjs-core and the widget.
func fnv1a32(seed string) uint32 {
	return fnv1a32Resume(2166136261, seed)
}

func fnv1a32Resume(state uint32, input string) uint32 {
	h := state
	for _, unit := range utf16.Encode([]rune(input)) {
		h ^= uint32(unit)
		h *= 16777619
	}
	return h
}

// prngFromHash is the xorshift32 generator used to derive salts and targets
// from a challenge token.
func prngFromHash(state uint32, length int) string {
	var out strings.Builder
	out.Grow(length + 8)
	for out.Len() < length {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		fmt.Fprintf(&out, "%08x", state)
	}
	return out.String()[:length]
}

// PRNG returns the deterministic hex string the Cap widget derives from a
// seed. Format-1 challenge i (1-based) uses salt PRNG(token+i, size) and
// target PRNG(token+i+"d", difficulty).
func PRNG(seed string, length int) string {
	return prngFromHash(fnv1a32(seed), length)
}

// format1Pair returns the (salt, target) pair for the 1-based challenge index.
func format1Pair(token string, index, size, difficulty int) (salt, target string) {
	tokenState := fnv1a32(token)
	saltState := fnv1a32Resume(tokenState, fmt.Sprint(index))
	targetState := fnv1a32Resume(saltState, "d")
	return prngFromHash(saltState, size), prngFromHash(targetState, difficulty)
}
