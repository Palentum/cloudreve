package cap

import (
	"crypto/sha256"
	"strconv"
	"strings"
)

func validateSolutions(token string, solutions []uint64, state challengeState) bool {
	tokenSeed := fnv1a(token)
	for i, solution := range solutions {
		idx := strconv.Itoa(i + 1)
		saltSeed := fnv1aResume(tokenSeed, idx)
		targetSeed := fnv1aResume(saltSeed, "d")
		salt := prngFromHash(saltSeed, state.Size)
		target := prngFromHash(targetSeed, state.Difficulty)
		if !solutionMatchesTarget(salt, solution, target) {
			return false
		}
	}
	return true
}

func solutionMatchesTarget(salt string, solution uint64, target string) bool {
	h := sha256.New()
	_, _ = h.Write([]byte(salt))
	var solutionBuf [20]byte
	_, _ = h.Write(strconv.AppendUint(solutionBuf[:0], solution, 10))
	return hashMatchesTarget(h.Sum(nil), target)
}

func hashMatchesTarget(hash []byte, target string) bool {
	fullBytes := len(target) / 2
	for i := 0; i < fullBytes; i++ {
		expected, ok := hexByte(target[i*2], target[i*2+1])
		if !ok || hash[i] != expected {
			return false
		}
	}

	if len(target)%2 == 1 {
		nibble, ok := hexNibble(target[len(target)-1])
		if !ok || hash[fullBytes]>>4 != nibble {
			return false
		}
	}

	return true
}

func hexByte(high byte, low byte) (byte, bool) {
	hi, ok := hexNibble(high)
	if !ok {
		return 0, false
	}
	lo, ok := hexNibble(low)
	if !ok {
		return 0, false
	}
	return hi<<4 | lo, true
}

func hexNibble(ch byte) (byte, bool) {
	switch {
	case ch >= '0' && ch <= '9':
		return ch - '0', true
	case ch >= 'a' && ch <= 'f':
		return ch - 'a' + 10, true
	case ch >= 'A' && ch <= 'F':
		return ch - 'A' + 10, true
	default:
		return 0, false
	}
}

func fnv1a(seed string) uint32 {
	return fnv1aResume(2166136261, seed)
}

func fnv1aResume(state uint32, value string) uint32 {
	for i := 0; i < len(value); i++ {
		state ^= uint32(value[i])
		state += (state << 1) + (state << 4) + (state << 7) + (state << 8) + (state << 24)
	}
	return state
}

func prngFromHash(state uint32, length int) string {
	var builder strings.Builder
	builder.Grow(((length + 7) / 8) * 8)
	for builder.Len() < length {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		writeUint32Hex(&builder, state)
	}
	return builder.String()[:length]
}

func writeUint32Hex(builder *strings.Builder, value uint32) {
	const digits = "0123456789abcdef"
	var buf [8]byte
	for i := len(buf) - 1; i >= 0; i-- {
		buf[i] = digits[value&0x0f]
		value >>= 4
	}
	_, _ = builder.Write(buf[:])
}
