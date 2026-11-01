package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"filippo.io/edwards25519"
)

// This file is an independent oracle for PROTOCOL.md sections 3 and 6. The
// -check command uses it to confirm the "valid" flag of each strict case.

const maxInt = 1<<53 - 1

type parser struct {
	b []byte
	i int
	// lenient accepts any RFC 8259 number (PROTOCOL.md section 4). Duplicate
	// key, UTF-8 and surrogate checks stay on.
	lenient bool
}

// rawNumber is a number that the lenient parser accepted. It is not a string,
// so a field read with .(string) refuses it.
type rawNumber string

func parseStrict(b []byte) (any, error) { return parseJSON(b, false) }

// parseLenient is the envelope reader of PROTOCOL.md section 4.
func parseLenient(b []byte) (any, error) { return parseJSON(b, true) }

func parseJSON(b []byte, lenient bool) (any, error) {
	if bytes.HasPrefix(b, []byte{0xef, 0xbb, 0xbf}) {
		return nil, errors.New("rule 1: byte order mark")
	}
	if !utf8.Valid(b) {
		return nil, errors.New("rule 1: invalid UTF-8")
	}
	p := &parser{b: b, lenient: lenient}
	p.ws()
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(b) {
		return nil, errors.New("rule 8: data after the top-level value")
	}
	return v, nil
}

func (p *parser) ws() {
	for p.i < len(p.b) && strings.IndexByte(" \t\n\r", p.b[p.i]) >= 0 {
		p.i++
	}
}

func (p *parser) value() (any, error) {
	if p.i >= len(p.b) {
		return nil, errors.New("unexpected end")
	}
	switch c := p.b[p.i]; {
	case c == '{':
		return p.object()
	case c == '[':
		p.i++
		out := []any{}
		p.ws()
		if p.i < len(p.b) && p.b[p.i] == ']' {
			p.i++
			return out, nil
		}
		for {
			p.ws()
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			p.ws()
			if p.i >= len(p.b) {
				return nil, errors.New("unexpected end")
			}
			if p.b[p.i] == ',' {
				p.i++
				continue
			}
			if p.b[p.i] == ']' {
				p.i++
				return out, nil
			}
			return nil, errors.New("bad array")
		}
	case c == '"':
		return p.str()
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	}
	for _, lit := range []string{"true", "false", "null"} {
		if bytes.HasPrefix(p.b[p.i:], []byte(lit)) {
			p.i += len(lit)
			if lit == "null" {
				return nil, nil
			}
			return lit == "true", nil
		}
	}
	return nil, fmt.Errorf("bad token at %d", p.i)
}

func (p *parser) object() (any, error) {
	p.i++
	m := map[string]any{}
	p.ws()
	if p.i < len(p.b) && p.b[p.i] == '}' {
		p.i++
		return m, nil
	}
	for {
		p.ws()
		if p.i >= len(p.b) || p.b[p.i] != '"' {
			return nil, errors.New("object key expected")
		}
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		p.ws()
		if p.i >= len(p.b) || p.b[p.i] != ':' {
			return nil, errors.New("colon expected")
		}
		p.i++
		p.ws()
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		if _, dup := m[k]; dup {
			return nil, fmt.Errorf("rule 3: duplicate key %q", k)
		}
		m[k] = v
		p.ws()
		if p.i >= len(p.b) {
			return nil, errors.New("unexpected end")
		}
		if p.b[p.i] == ',' {
			p.i++
			continue
		}
		if p.b[p.i] == '}' {
			p.i++
			return m, nil
		}
		return nil, errors.New("bad object")
	}
}

func (p *parser) hex4() (rune, error) {
	if p.i+4 > len(p.b) {
		return 0, errors.New("short \\u escape")
	}
	var r rune
	for _, c := range p.b[p.i : p.i+4] {
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, errors.New("bad \\u escape")
		}
		r = r<<4 | rune(d)
	}
	p.i += 4
	return r, nil
}

func (p *parser) str() (string, error) {
	p.i++
	var out []byte
	for p.i < len(p.b) {
		c := p.b[p.i]
		p.i++
		switch {
		case c == '"':
			return string(out), nil
		case c < 0x20:
			return "", errors.New("control character in string")
		case c != '\\':
			out = append(out, c)
		default:
			if p.i >= len(p.b) {
				return "", errors.New("bad escape")
			}
			e := p.b[p.i]
			p.i++
			switch e {
			case '"', '\\', '/':
				out = append(out, e)
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				r, err := p.hex4()
				if err != nil {
					return "", err
				}
				if r >= 0xdc00 && r <= 0xdfff {
					return "", errors.New("rule 5: lone low surrogate")
				}
				if r >= 0xd800 && r <= 0xdbff {
					if !bytes.HasPrefix(p.b[p.i:], []byte("\\u")) {
						return "", errors.New("rule 5: lone high surrogate")
					}
					p.i += 2
					lo, err := p.hex4()
					if err != nil {
						return "", err
					}
					if lo < 0xdc00 || lo > 0xdfff {
						return "", errors.New("rule 5: lone high surrogate")
					}
					r = 0x10000 + (r-0xd800)<<10 + (lo - 0xdc00)
				}
				out = utf8.AppendRune(out, r)
			default:
				return "", errors.New("bad escape")
			}
		}
	}
	return "", errors.New("unterminated string")
}

func (p *parser) lenientNumber() (any, error) {
	start := p.i
	digits := func() int {
		n := 0
		for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
			p.i++
			n++
		}
		return n
	}
	if p.b[p.i] == '-' {
		p.i++
	}
	if p.i < len(p.b) && p.b[p.i] == '0' {
		p.i++
	} else if p.i >= len(p.b) || p.b[p.i] < '1' || p.b[p.i] > '9' {
		return nil, errors.New("bad number")
	} else {
		digits()
	}
	if p.i < len(p.b) && p.b[p.i] == '.' {
		p.i++
		if digits() == 0 {
			return nil, errors.New("bad number")
		}
	}
	if p.i < len(p.b) && (p.b[p.i] == 'e' || p.b[p.i] == 'E') {
		p.i++
		if p.i < len(p.b) && (p.b[p.i] == '+' || p.b[p.i] == '-') {
			p.i++
		}
		if digits() == 0 {
			return nil, errors.New("bad number")
		}
	}
	// PROTOCOL.md section 4: refuse a number outside the binary64 range.
	if _, err := strconv.ParseFloat(string(p.b[start:p.i]), 64); err != nil {
		return nil, errors.New("number outside the binary64 range")
	}
	return rawNumber(p.b[start:p.i]), nil
}

func (p *parser) number() (any, error) {
	if p.lenient {
		return p.lenientNumber()
	}
	start := p.i
	neg := false
	if p.b[p.i] == '-' {
		neg = true
		p.i++
	}
	ds := p.i
	for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
		p.i++
	}
	digits := string(p.b[ds:p.i])
	if digits == "" || (len(digits) > 1 && digits[0] == '0') {
		return nil, errors.New("bad number")
	}
	if p.i < len(p.b) && strings.IndexByte(".eE", p.b[p.i]) >= 0 {
		return nil, errors.New("rule 4: fraction or exponent")
	}
	if neg && digits == "0" {
		return nil, errors.New("rule 4: -0")
	}
	if len(digits) > 16 {
		return nil, errors.New("rule 4: out of range")
	}
	var n int64
	for _, c := range digits {
		n = n*10 + int64(c-'0')
	}
	if n > maxInt {
		return nil, errors.New("rule 4: out of range")
	}
	if neg {
		n = -n
	}
	_ = start
	return n, nil
}

// reader checks the fields of one object.
type reader struct {
	m   map[string]any
	err error
}

func (r *reader) fail(format string, a ...any) {
	if r.err == nil {
		r.err = fmt.Errorf(format, a...)
	}
}

func newReader(v any, names ...string) *reader {
	m, ok := v.(map[string]any)
	r := &reader{m: m}
	if !ok {
		r.fail("rule 2/7: object expected")
		r.m = map[string]any{}
		return r
	}
	for _, n := range names {
		x, ok := m[n]
		if !ok {
			r.fail("rule 6: missing field %q", n)
		} else if x == nil {
			r.fail("rule 6: null field %q", n)
		}
	}
	if len(m) != len(names) {
		for k := range m {
			found := false
			for _, n := range names {
				found = found || n == k
			}
			if !found {
				r.fail("rule 6: unknown field %q", k)
			}
		}
	}
	return r
}

func (r *reader) str(k string) string {
	v, ok := r.m[k].(string)
	if !ok {
		r.fail("rule 7: %q is not a string", k)
	}
	return v
}

func (r *reader) num(k string, lo, hi int64) int64 {
	v, ok := r.m[k].(int64)
	if !ok {
		r.fail("rule 7: %q is not an integer", k)
		return 0
	}
	if v < lo || v > hi {
		r.fail("rule 7: %q out of range", k)
	}
	return v
}

func decodeID(t, prefix string, n int) ([]byte, error) {
	if !strings.HasPrefix(t, prefix) {
		return nil, fmt.Errorf("id %q lacks prefix %s", t, prefix)
	}
	h := t[len(prefix):]
	if len(h) != 2*n || h != strings.ToLower(h) {
		return nil, fmt.Errorf("id %q has bad length or case", t)
	}
	return hex.DecodeString(h)
}

func (r *reader) id(k, prefixes string, n int) (string, []byte) {
	t := r.str(k)
	var lastErr error
	for _, p := range strings.Split(prefixes, "|") {
		b, err := decodeID(t, p, n)
		if err == nil {
			return t, b
		}
		lastErr = err
	}
	r.fail("rule 7: %q: %v", k, lastErr)
	return t, nil
}

func decodeB64(t string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(t)
	if err != nil || base64.StdEncoding.EncodeToString(b) != t {
		return nil, errors.New("not canonical standard base64")
	}
	return b, nil
}

// bin reads a binary field of exactly n bytes, or of at least min bytes if n < 0.
func (r *reader) bin(k string, n, min int) []byte {
	b, err := decodeB64(r.str(k))
	if err != nil {
		r.fail("rule 7: %q: %v", k, err)
		return nil
	}
	if (n >= 0 && len(b) != n) || (n < 0 && len(b) < min) {
		r.fail("rule 7: %q has %d bytes", k, len(b))
	}
	return b
}

func (r *reader) list(k string) []any {
	v, ok := r.m[k].([]any)
	if !ok {
		r.fail("rule 7: %q is not a list", k)
	}
	return v
}

func (r *reader) sub(k string, names ...string) *reader {
	x := newReader(r.m[k], names...)
	if x.err != nil {
		r.fail("%q: %v", k, x.err)
	}
	return x
}

// checkSignKey applies PROTOCOL.md 6.1 and 7.1: a sign key must be a canonical
// Ed25519 public key that is not of small order.
func checkSignKey(b []byte) error {
	if len(b) != 32 {
		return fmt.Errorf("sign key has %d bytes", len(b))
	}
	p, err := new(edwards25519.Point).SetBytes(b)
	if err != nil {
		return fmt.Errorf("sign key is not a curve point: %w", err)
	}
	if !bytes.Equal(p.Bytes(), b) {
		return errors.New("sign key is not canonical")
	}
	if new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return errors.New("sign key has small order")
	}
	return nil
}

// signKey reads a 32-byte sign key field and applies checkSignKey.
func (r *reader) signKey(k string) []byte {
	b := r.bin(k, 32, 0)
	if r.err == nil {
		if err := checkSignKey(b); err != nil {
			r.fail("rule 6.2: %q: %v", k, err)
		}
	}
	return b
}

type position struct {
	n int64
	d []byte
}

func (r *reader) pos(k string, minPos int64) position {
	x := r.sub(k, "position", "digest")
	p := position{n: x.num("position", minPos, maxInt), d: x.bin("digest", 32, 0)}
	if x.err != nil {
		r.fail("%q: %v", k, x.err)
	}
	return p
}

func idsOf(r *reader, k string) [][]byte {
	var out [][]byte
	for _, v := range r.list(k) {
		t, ok := v.(string)
		if !ok {
			r.fail("rule 7: %q holds a non-string", k)
			continue
		}
		b, err := decodeID(t, "d_", 32)
		if err != nil {
			r.fail("rule 7: %q: %v", k, err)
			continue
		}
		out = append(out, b)
	}
	for i := 1; i < len(out); i++ {
		if bytes.Compare(out[i-1], out[i]) >= 0 {
			r.fail("rule 6.2: %q not sorted or has a duplicate", k)
		}
	}
	return out
}

type keySetInfo struct {
	to     []byte
	toRec  bool
	epochs []int64
}

func keySets(r *reader, k string) []keySetInfo {
	var out []keySetInfo
	for _, v := range r.list(k) {
		x := newReader(v, "to", "epochs", "sealed")
		var ks keySetInfo
		if x.err == nil {
			var toText string
			toText, ks.to = x.id("to", "d_|r_", 32)
			ks.toRec = strings.HasPrefix(toText, "r_")
			for _, e := range x.list("epochs") {
				n, ok := e.(int64)
				if !ok || n < 1 {
					x.fail("rule 7: bad epoch")
					continue
				}
				if len(ks.epochs) > 0 && n <= ks.epochs[len(ks.epochs)-1] {
					x.fail("rule 6.2: epochs not strictly increasing")
				}
				ks.epochs = append(ks.epochs, n)
			}
			if len(ks.epochs) == 0 {
				x.fail("rule 6.2: epochs empty")
			}
			x.bin("sealed", 1120+32*len(ks.epochs)+16, 0)
		}
		if x.err != nil {
			r.fail("%q: %v", k, x.err)
			continue
		}
		out = append(out, ks)
	}
	for i := 1; i < len(out); i++ {
		if bytes.Compare(out[i-1].to, out[i].to) >= 0 {
			r.fail("rule 6.2: key sets not sorted or duplicate")
		}
	}
	return out
}

func deviceObj(r *reader, k string) []byte {
	x := r.sub(k, "id", "sign", "seal", "name", "level")
	_, id := x.id("id", "d_", 32)
	sign := x.signKey("sign")
	seal := x.bin("seal", 1216, 0)
	if n := len(x.str("name")); n < 1 || n > 128 {
		x.fail("rule 6.2: name length %d", n)
	}
	x.num("level", 1, 65535)
	if x.err == nil && !bytes.Equal(id, sha(frame(s("snailfish.device-id.v1"), sign, seal))) {
		x.fail("rule 6.2: device id does not match keys")
	}
	if x.err != nil {
		r.fail("%q: %v", k, x.err)
	}
	return id
}

func keysObj(r *reader, k string) (sign, seal, rid []byte) {
	x := r.sub(k, "sign", "seal")
	sign, seal = x.signKey("sign"), x.bin("seal", 1216, 0)
	if x.err != nil {
		r.fail("%q: %v", k, x.err)
		return
	}
	return sign, seal, sha(frame(s("snailfish.recovery-id.v1"), sign, seal))
}

func eqEpochs(ks keySetInfo, e ...int64) bool {
	if len(ks.epochs) != len(e) {
		return false
	}
	for i := range e {
		if ks.epochs[i] != e[i] {
			return false
		}
	}
	return true
}

// validatePayload applies PROTOCOL.md sections 3 and 6.2 to one payload.
func validatePayload(ptype string, raw []byte) error {
	v, err := parseStrict(raw)
	if err != nil {
		return err
	}
	if _, ok := v.(map[string]any); !ok {
		return errors.New("rule 2: top-level value is not an object")
	}
	common := []string{"log", "author", "base"}
	var names []string
	switch ptype {
	case "snailfish.genesis.v1":
		names = append(common, "app", "recovery", "level", "device", "epoch", "commitment", "keys")
	case "snailfish.grant.v1":
		names = append(common, "device", "keys")
	case "snailfish.epoch.v1":
		names = append(common, "epoch", "removed", "stay", "commitment", "keys")
	case "snailfish.recovery.v1":
		names = append(common, "recovery", "proof", "keys")
	case "snailfish.device.v1", "snailfish.level.v1":
		names = append(common, "level")
	case "snailfish.change.v1":
		names = append(common, "epoch", "change_id", "ciphertext")
	case "snailfish.snapshot.v1":
		names = append(common, "epoch", "state", "ciphertext")
	case "snailfish.accept.v1":
		names = append(common, "snapshot", "applied")
	case "snailfish.checkpoint.v1":
		names = []string{"log", "author", "position", "digest"}
	case "snailfish.delete.v1":
		names = []string{"log", "author", "head", "expires"}
	case "snailfish.confirm.v1":
		names = []string{"session", "trusted", "device", "trusted_nonce", "new_nonce"}
	default:
		return fmt.Errorf("unknown payload type %q", ptype)
	}
	r := newReader(v, names...)
	if r.err != nil {
		return r.err
	}
	// 6.3: a confirmation has no log and no author. device.sign signs it.
	if ptype == "snailfish.confirm.v1" {
		r.id("session", "e_", 16)
		r.id("trusted", "d_", 32)
		deviceObj(r, "device")
		r.bin("trusted_nonce", 32, 0)
		r.bin("new_nonce", 32, 0)
		return r.err
	}
	_, logID := r.id("log", "l_", 16)
	authorT, author := r.id("author", "d_|r_", 32)
	isRec := strings.HasPrefix(authorT, "r_")
	switch ptype {
	case "snailfish.checkpoint.v1":
		r.num("position", 1, maxInt)
		r.bin("digest", 32, 0)
		deviceOnly(r, isRec)
		return r.err
	case "snailfish.delete.v1":
		r.pos("head", 0)
		r.num("expires", 0, maxInt)
		return r.err
	}
	base := r.pos("base", 0)
	if ptype == "snailfish.genesis.v1" {
		if base.n != 0 || (r.err == nil && !bytes.Equal(base.d, sha(frame(s("snailfish.log-root.v1"), logID)))) {
			r.fail("rule 6.2: genesis base is not position 0 with digest(0)")
		}
	} else if base.n < 1 {
		r.fail("rule 6.2: base position below 1")
	}
	switch ptype {
	case "snailfish.genesis.v1":
		if n := len(r.str("app")); n < 1 || n > 255 {
			r.fail("rule 6.2: app length")
		}
		_, _, rid := keysObj(r, "recovery")
		r.num("level", 1, 65535)
		dev := deviceObj(r, "device")
		if r.num("epoch", 1, maxInt) != 1 {
			r.fail("rule 6.2: genesis epoch must be 1")
		}
		r.bin("commitment", 32, 0)
		ks := keySets(r, "keys")
		if !isRec || (rid != nil && !bytes.Equal(author, rid)) {
			r.fail("rule 6.2: author is not the recovery id")
		}
		if r.err == nil {
			if len(ks) != 2 || !eqEpochs(ks[0], 1) || !eqEpochs(ks[1], 1) {
				r.fail("rule 6.2: genesis needs 2 key sets with epochs [1]")
			} else if !((bytes.Equal(ks[0].to, dev) && bytes.Equal(ks[1].to, rid)) || (bytes.Equal(ks[1].to, dev) && bytes.Equal(ks[0].to, rid))) {
				r.fail("rule 6.2: genesis key sets are not for the device and the recovery id")
			}
		}
	case "snailfish.grant.v1":
		dev := deviceObj(r, "device")
		ks := keySets(r, "keys")
		if r.err == nil && (len(ks) != 1 || !bytes.Equal(ks[0].to, dev)) {
			r.fail("rule 6.2: grant needs one key set to the new device")
		}
	case "snailfish.epoch.v1":
		e := r.num("epoch", 2, maxInt)
		removed := idsOf(r, "removed")
		stay := idsOf(r, "stay")
		for _, x := range removed {
			for _, y := range stay {
				if bytes.Equal(x, y) {
					r.fail("rule 6.2: device in both removed and stay")
				}
			}
		}
		if r.err == nil && len(stay) == 0 {
			r.fail("rule 6.2: stay is empty")
		}
		r.bin("commitment", 32, 0)
		ks := keySets(r, "keys")
		if r.err == nil {
			recs := 0
			for _, k := range ks {
				if !eqEpochs(k, e) {
					r.fail("rule 6.2: key set epochs must be [epoch]")
				}
				if k.toRec {
					recs++
					continue
				}
				in := false
				for _, y := range stay {
					in = in || bytes.Equal(k.to, y)
				}
				if !in {
					r.fail("rule 6.2: key set to a device that is not in stay")
				}
			}
			if recs != 1 {
				r.fail("rule 6.2: epoch needs exactly one key set to a recovery id, got %d", recs)
			}
			if len(ks) != len(stay)+1 {
				r.fail("rule 6.2: key set count")
			}
		}
	case "snailfish.recovery.v1":
		sign, seal, rid := keysObj(r, "recovery")
		proof := r.bin("proof", 64, 0)
		ks := keySets(r, "keys")
		if !isRec {
			r.fail("rule 6.2: author is not a recovery id")
		}
		if r.err == nil {
			if len(ks) != 1 || !bytes.Equal(ks[0].to, rid) {
				r.fail("rule 6.2: recovery needs one key set to the new recovery id")
			}
			if !ed25519.Verify(sign, frame(s("snailfish.recovery-proof.v1"), logID, sign, seal), proof) {
				r.fail("rule 6.2: bad recovery proof")
			}
		}
	case "snailfish.device.v1", "snailfish.level.v1":
		r.num("level", 1, 65535)
		deviceOnly(r, isRec)
	case "snailfish.change.v1":
		r.num("epoch", 1, maxInt)
		r.id("change_id", "c_", 16)
		r.bin("ciphertext", -1, 40)
		deviceOnly(r, isRec)
	case "snailfish.snapshot.v1":
		r.num("epoch", 1, maxInt)
		r.pos("state", 0)
		r.bin("ciphertext", -1, 40)
		deviceOnly(r, isRec)
	case "snailfish.accept.v1":
		x := r.sub("snapshot", "position", "hash")
		x.num("position", 1, maxInt)
		x.bin("hash", 32, 0)
		if x.err != nil {
			r.fail("snapshot: %v", x.err)
		}
		r.pos("applied", 0)
		deviceOnly(r, isRec)
	}
	return r.err
}

func deviceOnly(r *reader, isRec bool) {
	if isRec {
		r.fail("rule 6.2: author must be a device id")
	}
}
