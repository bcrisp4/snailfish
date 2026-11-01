package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// frame is PROTOCOL.md 2.1.
func frame(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = binary.BigEndian.AppendUint64(out, uint64(len(p)))
		out = append(out, p...)
	}
	return out
}

func u64(n uint64) []byte { return binary.BigEndian.AppendUint64(nil, n) }

func sha(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

func s(x string) []byte { return []byte(x) }

// pae is PROTOCOL.md section 1 (DSSE v1).
func pae(typ string, body []byte) []byte {
	out := []byte("DSSEv1 " + strconv.Itoa(len(typ)) + " " + typ + " " + strconv.Itoa(len(body)) + " ")
	return append(out, body...)
}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// crockfordEncode encodes whole bytes, most significant bit first. The input
// must hold a multiple of 5 bits (here 20 bytes).
func crockfordEncode(b []byte) string {
	var sb strings.Builder
	var acc uint32
	bits := 0
	for _, c := range b {
		acc = acc<<8 | uint32(c)
		bits += 8
		for bits >= 5 {
			sb.WriteByte(crockford[(acc>>(bits-5))&31])
			bits -= 5
		}
		acc &= (1 << bits) - 1
	}
	if bits > 0 {
		sb.WriteByte(crockford[(acc<<(5-bits))&31])
	}
	return sb.String()
}

func crockfordDecode(sym string) ([]byte, error) {
	var out []byte
	var acc uint32
	bits := 0
	for i := 0; i < len(sym); i++ {
		v := strings.IndexByte(crockford, sym[i])
		if v < 0 {
			return nil, fmt.Errorf("symbol %q outside alphabet", sym[i])
		}
		acc = acc<<5 | uint32(v)
		bits += 5
		if bits >= 8 {
			out = append(out, byte(acc>>(bits-8)))
			bits -= 8
			acc &= (1 << bits) - 1
		}
	}
	if bits != 0 && acc != 0 {
		return nil, errors.New("non-zero trailing bits")
	}
	return out, nil
}

func recoveryCheck(secret []byte) []byte {
	return sha(frame(s("snailfish.recovery-check.v1"), secret))[:4]
}

func recoverySymbols(secret []byte) string {
	return crockfordEncode(append(append([]byte{}, secret...), recoveryCheck(secret)...))
}

func recoveryDisplay(secret []byte) string { return groups(recoverySymbols(secret)) }

// groups writes 32 symbols in 8 groups of 4, joined with "-" (sections 9 and 11.1).
func groups(sym string) string {
	var g []string
	for i := 0; i < len(sym); i += 4 {
		g = append(g, sym[i:i+4])
	}
	return strings.Join(g, "-")
}

// parseRecoveryKey is the reader of PROTOCOL.md section 9.
func parseRecoveryKey(text string) ([]byte, error) { return parseCode(text, recoveryCheck) }

// parseCode is the five reader steps of PROTOCOL.md section 9 for a 16-byte
// value and its 4-byte check. Section 11.1 uses the same steps with another
// check label.
func parseCode(text string, check func([]byte) []byte) ([]byte, error) {
	t := strings.NewReplacer("-", "", " ", "").Replace(text)
	t = strings.ToUpper(t)
	t = strings.NewReplacer("O", "0", "I", "1", "L", "1").Replace(t)
	for i := 0; i < len(t); i++ {
		if !strings.ContainsRune(crockford, rune(t[i])) {
			return nil, fmt.Errorf("symbol %q refused", t[i])
		}
	}
	if len(t) != 32 {
		return nil, fmt.Errorf("%d symbols, want 32", len(t))
	}
	raw, err := crockfordDecode(t)
	if err != nil {
		return nil, err
	}
	value, c := raw[:16], raw[16:]
	if hex.EncodeToString(c) != hex.EncodeToString(check(value)) {
		return nil, errors.New("check mismatch")
	}
	return value, nil
}
