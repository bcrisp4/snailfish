package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// splitFields splits the writer-form payload (no whitespace) into its top-level fields.
func splitFields(payload string) fields {
	var out fields
	i := 1
	for i < len(payload)-1 {
		j := i + 1
		for payload[j] != '"' {
			j++
		}
		k := payload[i+1 : j]
		start := j + 2
		depth, inStr := 0, false
		e := start
		for ; e < len(payload); e++ {
			c := payload[e]
			if inStr {
				if c == '\\' {
					e++
				} else if c == '"' {
					inStr = false
				}
				continue
			}
			if c == '"' {
				inStr = true
			} else if c == '{' || c == '[' {
				depth++
			} else if c == '}' || c == ']' {
				if depth == 0 {
					break
				}
				depth--
			} else if c == ',' && depth == 0 {
				break
			}
		}
		out = append(out, kv{k, payload[start:e]})
		i = e + 1
	}
	return out
}

type caseSpec struct {
	name, rule, ptype string
	payload           string
	raw               []byte // used when set instead of payload
	valid             bool
}

func buildStrict(p *protocolJ, w *world) (*strictJ, error) {
	ent := func(n int) (string, fields) { e := p.Log.Entries[n-1]; return e.PayloadType, splitFields(e.Payload) }
	ct, change := ent(3)
	gt, genesis := ent(1)
	et, epoch := ent(9)
	rt, recov := ent(11)
	var cs []caseSpec
	add := func(name, rule, ptype, payload string, valid bool) {
		cs = append(cs, caseSpec{name: name, rule: rule, ptype: ptype, payload: payload, valid: valid})
	}
	addRaw := func(name, rule, ptype string, raw []byte, valid bool) {
		cs = append(cs, caseSpec{name: name, rule: rule, ptype: ptype, raw: raw, valid: valid})
	}
	canon := change.render()
	base := change.get("base")
	cid := change.get("change_id")

	add("canonical", "3", ct, canon, true)
	rev := fields{}
	for i := len(change) - 1; i >= 0; i-- {
		rev = append(rev, change[i])
	}
	var sb strings.Builder
	sb.WriteString("\n {\n")
	for i, f := range rev {
		if i > 0 {
			sb.WriteString(" ,\n")
		}
		sb.WriteString("\t" + q(f.k) + " :\r\n " + f.v)
	}
	sb.WriteString("\n}")
	add("reordered-keys-with-whitespace", "3", ct, sb.String(), true)
	add("trailing-whitespace", "8", ct, canon+" \t\r\n", true)
	add("duplicate-key", "3", ct, canon[:len(canon)-1]+`,"epoch":1}`, false)
	add("duplicate-key-via-escape", "3", ct, canon[:len(canon)-1]+`,"\u0065poch":1}`, false)
	nested := change.set("base", strings.Replace(base, `"digest"`, `"position":1,"digest"`, 1))
	add("nested-duplicate-in-base", "3", ct, nested.render(), false)
	add("float-1.0", "4", ct, change.set("epoch", "1.0").render(), false)
	add("exponent-1e2", "4", ct, change.set("epoch", "1e2").render(), false)
	add("negative-zero", "4", ct, change.set("base", strings.Replace(base, `"position":2`, `"position":-0`, 1)).render(), false)
	add("position-2^53", "4", ct, change.set("base", strings.Replace(base, `"position":2`, `"position":9007199254740992`, 1)).render(), false)
	add("position-2^53-1", "4", ct, change.set("base", strings.Replace(base, `"position":2`, `"position":9007199254740991`, 1)).render(), true)
	add("position-negative", "7", ct, change.set("base", strings.Replace(base, `"position":2`, `"position":-1`, 1)).render(), false)
	add("epoch-zero", "7", ct, change.set("epoch", "0").render(), false)
	add("epoch-string", "7", ct, change.set("epoch", `"1"`).render(), false)

	genApp := func(app string) string { return genesis.set("app", app).render() }
	add("string-escapes-valid", "5", gt, genApp(`"a\u00e9\n\"\\\/\ud83d\ude00"`), true)
	add("lone-high-surrogate", "5", gt, genApp(`"\ud800"`), false)
	add("lone-low-surrogate", "5", gt, genApp(`"\udc00"`), false)
	addRaw("invalid-utf8", "1", gt, []byte(genApp("\"a\xffb\"")), false)
	addRaw("leading-bom", "1", ct, append([]byte{0xef, 0xbb, 0xbf}, canon...), false)
	add("top-level-array", "2", ct, "["+canon+"]", false)
	add("unknown-field", "6", ct, canon[:len(canon)-1]+`,"extra":1}`, false)
	add("missing-field", "6", ct, change.drop("ciphertext").render(), false)
	add("null-field", "6", ct, change.set("ciphertext", "null").render(), false)
	add("trailing-garbage", "8", ct, canon+"x", false)
	add("second-top-level-object", "8", ct, canon+canon, false)

	// ciphertext encodings
	ctOf := func(t string) string { return change.set("ciphertext", q(t)).render() }
	plus := strings.Repeat("+/v7", 14) // 42 bytes of 0xfb
	add("ciphertext-standard-alphabet-plus-slash", "7", ct, ctOf(plus), true)
	add("ciphertext-url-safe-alphabet", "7", ct, ctOf(strings.NewReplacer("+", "-", "/", "_").Replace(plus)), false)
	zero40 := strings.Repeat("A", 52) + "AA=="
	add("ciphertext-40-bytes", "7", ct, ctOf(zero40), true)
	add("ciphertext-missing-padding", "7", ct, ctOf(strings.TrimRight(zero40, "=")), false)
	add("ciphertext-nonzero-trailing-bits", "7", ct, ctOf(strings.Repeat("A", 52)+"AB=="), false)
	add("ciphertext-39-bytes", "7", ct, ctOf(strings.Repeat("A", 52)), false)
	add("ciphertext-whitespace", "7", ct, ctOf(zero40[:20]+"\\n"+zero40[20:]), false)

	// identifiers
	hexPart := strings.TrimPrefix(strings.Trim(cid, `"`), "c_")
	idCase := func(v string) string { return change.set("change_id", q(v)).render() }
	add("change-id-uppercase-hex", "7", ct, idCase("c_"+strings.ToUpper(hexPart)), false)
	add("change-id-wrong-prefix", "7", ct, idCase("d_"+hexPart), false)
	add("change-id-wrong-length", "7", ct, idCase("c_"+hexPart[:30]), false)

	// genesis rules
	add("genesis-valid", "6.2", gt, genesis.render(), true)
	add("genesis-epoch-2", "6.2", gt, genesis.set("epoch", "2").render(), false)
	ksRaw := genesis.get("keys")
	items := splitList(ksRaw)
	add("genesis-key-sets-unsorted", "6.2", gt, genesis.set("keys", list(items[1], items[0])).render(), false)
	dev := genesis.get("device")
	badDev := strings.Replace(dev, p.Devices[0].ID, p.Devices[1].ID, 1)
	add("genesis-device-id-mismatch", "6.2", gt, genesis.set("device", badDev).render(), false)
	nameOf := func(n int) string {
		return strings.Replace(dev, `"name":"Laptop"`, `"name":"`+strings.Repeat("n", n)+`"`, 1)
	}
	add("genesis-name-128-bytes", "6.2", gt, genesis.set("device", nameOf(128)).render(), true)
	add("genesis-name-129-bytes", "6.2", gt, genesis.set("device", nameOf(129)).render(), false)
	add("genesis-name-empty", "6.2", gt, genesis.set("device", nameOf(0)).render(), false)
	add("genesis-level-0", "6.2", gt, genesis.set("level", "0").render(), false)
	add("genesis-level-65535", "6.2", gt, genesis.set("level", "65535").render(), true)
	add("genesis-level-65536", "6.2", gt, genesis.set("level", "65536").render(), false)
	add("genesis-author-not-recovery-id", "6.2", gt, genesis.set("author", q(p.Recovery[1].ID)).render(), false)
	add("genesis-author-is-device", "6.2", gt, genesis.set("author", q(p.Devices[0].ID)).render(), false)

	// epoch record rules
	add("epoch-valid", "6.2", et, epoch.render(), true)
	// Neither ID is in stay (A and B). The second one is a device that no record created.
	rm := []string{p.Devices[2].ID, "d_" + hx(sha(s("snailfish.test.removed-device")))}
	if rm[0] > rm[1] {
		rm[0], rm[1] = rm[1], rm[0]
	}
	add("epoch-removed-sorted", "6.2", et, epoch.set("removed", list(q(rm[0]), q(rm[1]))).render(), true)
	add("epoch-removed-unsorted", "6.2", et, epoch.set("removed", list(q(rm[1]), q(rm[0]))).render(), false)
	add("epoch-removed-duplicate", "6.2", et, epoch.set("removed", list(q(rm[0]), q(rm[0]))).render(), false)
	eitems := splitList(epoch.get("keys"))
	recoveryKS := ""
	for _, it := range eitems {
		if strings.Contains(it, p.Recovery[0].ID) {
			recoveryKS = it
		}
	}
	add("epoch-stay-empty", "6.2", et, epoch.set("stay", "[]").set("keys", list(recoveryKS)).render(), false)
	add("epoch-number-1", "6.2", et, epoch.set("epoch", "1").render(), false)

	// key set epochs
	add("recovery-valid", "6.2", rt, recov.render(), true)
	rk := recov.get("keys")
	add("key-set-epochs-not-increasing", "6.2", rt, recov.set("keys", strings.Replace(rk, `"epochs":[1,2]`, `"epochs":[2,1]`, 1)).render(), false)
	add("key-set-epochs-repeated", "6.2", rt, recov.set("keys", strings.Replace(rk, `"epochs":[1,2]`, `"epochs":[2,2]`, 1)).render(), false)

	cs = append(cs, signKeyCases(p, w)...)

	out := &strictJ{Version: 1}
	for _, c := range cs {
		raw := c.raw
		if raw == nil {
			raw = []byte(c.payload)
		}
		got := validatePayload(c.ptype, raw)
		if (got == nil) != c.valid {
			return nil, fmt.Errorf("strict case %q: oracle says err=%v, case says valid=%v", c.name, got, c.valid)
		}
		sc := strictCase{Name: c.name, Rule: c.rule, PayloadType: c.ptype, Valid: c.valid}
		if c.raw != nil {
			h := hx(c.raw)
			sc.PayloadHex = &h
		} else {
			pl := c.payload
			sc.Payload = &pl
		}
		out.Cases = append(out.Cases, sc)
	}
	return out, nil
}

var (
	identityKey     = append([]byte{1}, make([]byte, 31)...)
	nonCanonicalKey = append(append([]byte{1}, make([]byte, 30)...), 0x80)
)

type ksItem struct {
	id     []byte
	to     string
	epochs []int
	sealed string
}

// renderKeySets writes key sets sorted by the 32 ID bytes of `to`.
func renderKeySets(items ...ksItem) string {
	sort.Slice(items, func(i, j int) bool { return bytes.Compare(items[i].id, items[j].id) < 0 })
	var raws []string
	for _, it := range items {
		raws = append(raws, obj("to", q(it.to), "epochs", intList(it.epochs), "sealed", q(it.sealed)))
	}
	return list(raws...)
}

// sealedOf returns the sealed field of the key set to `to` in a stored key set list.
func sealedOf(keys, to string) string {
	for _, it := range splitList(keys) {
		if strings.Contains(it, to) {
			i := strings.Index(it, `"sealed":"`) + len(`"sealed":"`)
			return it[i : len(it)-2]
		}
	}
	panic("no key set to " + to)
}

func deviceWithSign(p *party, sign []byte, name string, level int) (string, []byte) {
	id := sha(frame(s("snailfish.device-id.v1"), sign, p.sealPk))
	return obj("id", q("d_"+hx(id)), "sign", q(b64(sign)), "seal", q(b64(p.sealPk)),
		"name", q(name), "level", fmt.Sprint(level)), id
}

func recoveryWithSign(p *party, sign []byte) (string, []byte) {
	return obj("sign", q(b64(sign)), "seal", q(b64(p.sealPk))), sha(frame(s("snailfish.recovery-id.v1"), sign, p.sealPk))
}

// signKeyCases covers PROTOCOL.md 6.1 (sign keys) and 6.2 (recovery proof, epoch rules).
// Each case breaks one rule and keeps every derived field consistent.
func signKeyCases(p *protocolJ, w *world) []caseSpec {
	field := func(n int) (string, fields) { e := p.Log.Entries[n-1]; return e.PayloadType, splitFields(e.Payload) }
	var cs []caseSpec
	add := func(name, ptype, payload string, valid bool) {
		cs = append(cs, caseSpec{name: name, rule: "6.2", ptype: ptype, payload: payload, valid: valid})
	}
	idt := func(id []byte, prefix string) string { return prefix + hx(id) }

	gt, genesis := field(1)
	grt, grant := field(2)
	et, epoch := field(9)
	rt, recov := field(11)

	// grant: device.sign
	for _, c := range []struct {
		name string
		key  []byte
	}{{"grant-device-sign-non-canonical", nonCanonicalKey}, {"grant-device-sign-small-order", identityKey}} {
		dev, id := deviceWithSign(w.B, c.key, "Phone", 1)
		keys := renderKeySets(ksItem{id, idt(id, "d_"), []int{1}, sealedOf(grant.get("keys"), w.B.idText)})
		add(c.name, grt, grant.set("device", dev).set("keys", keys).render(), false)
	}

	// genesis: recovery.sign and device.sign
	gk := genesis.get("keys")
	genesisWith := func(recSign, devSign []byte) string {
		rec, rid := recoveryWithSign(w.R1, recSign)
		dev, did := deviceWithSign(w.A, devSign, "Laptop", 2)
		keys := renderKeySets(
			ksItem{did, idt(did, "d_"), []int{1}, sealedOf(gk, w.A.idText)},
			ksItem{rid, idt(rid, "r_"), []int{1}, sealedOf(gk, w.R1.idText)})
		return genesis.set("author", q(idt(rid, "r_"))).set("recovery", rec).set("device", dev).set("keys", keys).render()
	}
	add("genesis-recovery-sign-non-canonical", gt, genesisWith(nonCanonicalKey, w.A.signPk), false)
	add("genesis-device-sign-small-order", gt, genesisWith(w.R1.signPk, identityKey), false)

	// recovery record
	rk := recov.get("keys")
	recoveryWith := func(sign, proof []byte) string {
		rec, rid := recoveryWithSign(w.R2, sign)
		keys := renderKeySets(ksItem{rid, idt(rid, "r_"), []int{1, 2}, sealedOf(rk, w.R2.idText)})
		return recov.set("recovery", rec).set("proof", q(b64(proof))).set("keys", keys).render()
	}
	proofMsg := frame(s("snailfish.recovery-proof.v1"), w.logID, w.R2.signPk, w.R2.sealPk)
	good := ed25519.Sign(w.R2.signPriv, proofMsg)
	// The identity key with R = identity and S = 0 is a valid Ed25519 signature, so only the key rule fails.
	identityProof := append(append([]byte{}, identityKey...), make([]byte, 32)...)
	idMsg := frame(s("snailfish.recovery-proof.v1"), w.logID, identityKey, w.R2.sealPk)
	if !ed25519.Verify(identityKey, idMsg, identityProof) {
		panic("identity proof does not verify")
	}
	add("recovery-sign-small-order", rt, func() string {
		rec, rid := recoveryWithSign(w.R2, identityKey)
		keys := renderKeySets(ksItem{rid, idt(rid, "r_"), []int{1, 2}, sealedOf(rk, w.R2.idText)})
		return recov.set("recovery", rec).set("proof", q(b64(identityProof))).set("keys", keys).render()
	}(), false)
	add("recovery-proof-wrong-key", rt, recoveryWith(w.R2.signPk, ed25519.Sign(w.R1.signPriv, proofMsg)), false)
	flipped := append([]byte{}, good...)
	flipped[0] ^= 1
	add("recovery-proof-flipped-byte", rt, recoveryWith(w.R2.signPk, flipped), false)

	// epoch record
	ek := epoch.get("keys")
	ids := func(ps ...*party) []string {
		sorted := sortParties(ps)
		var out []string
		for _, x := range sorted {
			out = append(out, q(x.idText))
		}
		return out
	}
	add("epoch-device-in-removed-and-stay", et, epoch.set("removed", list(ids(w.A, w.C)...)).render(), false)
	ksOf := func(ps ...*party) string {
		var items []ksItem
		for _, x := range ps {
			src := x
			if x == w.R2 {
				src = w.R1 // same length, the parser does not open it
			}
			items = append(items, ksItem{x.id, x.idText, []int{2}, sealedOf(ek, src.idText)})
		}
		return renderKeySets(items...)
	}
	add("epoch-two-recovery-key-sets", et, epoch.set("stay", list(q(w.A.idText))).set("keys", ksOf(w.A, w.R1, w.R2)).render(), false)
	return cs
}

func splitList(raw string) []string {
	if len(raw) < 2 || raw[0] != '[' {
		panic("not a list")
	}
	var out []string
	depth, inStr, start := 0, false, 1
	for i := 1; i < len(raw)-1; i++ {
		c := raw[i]
		if inStr {
			if c == '\\' {
				i++
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{', '[':
			depth++
		case '}', ']':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, raw[start:i])
				start = i + 1
			}
		}
	}
	return append(out, raw[start:len(raw)-1])
}

func buildRecoveryKeys(w *world) (*recoveryKeyJ, error) {
	r := &recoveryKeyJ{Version: 1}
	for _, p := range []*party{w.R1, w.R2} {
		r.Valid = append(r.Valid, recValid{recoveryDisplay(p.secret), hx(p.secret)})
	}
	d := recoveryDisplay(w.R1.secret)
	sec := hx(w.R1.secret)
	add := func(text string) { r.Valid = append(r.Valid, recValid{text, sec}) }
	add(strings.ToLower(d))
	add(strings.ReplaceAll(d, "-", ""))
	add(strings.ReplaceAll(d, "-", " "))
	add(strings.ReplaceAll(strings.ToLower(d), "-", " - "))

	var alias []byte
	for i := 0; i < 100000; i++ {
		c := testSeed(fmt.Sprintf("recovery-alias-%d", i), "recovery-secret")[:16]
		sym := recoverySymbols(c)
		if strings.Count(sym, "0") >= 1 && strings.Count(sym, "1") >= 1 {
			alias = c
			break
		}
	}
	if alias == nil {
		return nil, errors.New("no alias secret found")
	}
	ad, as := recoveryDisplay(alias), hx(alias)
	aliasAdd := func(text string) { r.Valid = append(r.Valid, recValid{text, as}) }
	aliasAdd(ad)
	aliasAdd(strings.ReplaceAll(ad, "0", "O"))
	aliasAdd(strings.ReplaceAll(strings.ReplaceAll(ad, "0", "o"), "1", "i"))
	aliasAdd(strings.ReplaceAll(ad, "1", "I"))
	aliasAdd(strings.ReplaceAll(ad, "1", "L"))
	aliasAdd(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(ad, "0", "O"), "1", "l"), "-", " "))

	flip := func(x string) string {
		last := x[len(x)-1]
		n := byte('0')
		if last == '0' {
			n = '1'
		}
		return x[:len(x)-1] + string(n)
	}
	nd := strings.ReplaceAll(d, "-", "")
	grp := func(x string) string {
		var g []string
		for i := 0; i < len(x); i += 4 {
			e := i + 4
			if e > len(x) {
				e = len(x)
			}
			g = append(g, x[i:e])
		}
		return strings.Join(g, "-")
	}
	r.Invalid = []recInvalid{
		{"contains-U", grp("U" + nd[1:])},
		{"contains-U-lowercase", strings.ToLower(grp(nd[:10] + "U" + nd[11:]))},
		{"wrong-check", grp(flip(nd))},
		{"31-symbols", grp(nd[:31])},
		{"33-symbols", grp(nd + "0")},
		{"empty", ""},
		{"only-dashes", "----"},
		{"contains-other-symbol", grp(nd[:5] + "#" + nd[6:])},
	}
	for _, c := range r.Valid {
		if _, err := parseRecoveryKey(c.Text); err != nil {
			return nil, fmt.Errorf("valid recovery text %q refused: %v", c.Text, err)
		}
	}
	for _, c := range r.Invalid {
		if _, err := parseRecoveryKey(c.Text); err == nil {
			return nil, fmt.Errorf("invalid recovery text %q accepted (%s)", c.Text, c.Name)
		}
	}
	return r, nil
}
