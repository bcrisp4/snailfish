package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
)

type kv struct{ k, v string }
type fields []kv

func (f fields) render() string {
	var a []string
	for _, x := range f {
		a = append(a, x.k, x.v)
	}
	return obj(a...)
}

func (f fields) set(k, v string) fields {
	out := append(fields{}, f...)
	for i := range out {
		if out[i].k == k {
			out[i].v = v
			return out
		}
	}
	panic("no field " + k)
}

func (f fields) get(k string) string {
	for _, x := range f {
		if x.k == k {
			return x.v
		}
	}
	panic("no field " + k)
}

func (f fields) drop(k string) fields {
	var out fields
	for _, x := range f {
		if x.k != k {
			out = append(out, x)
		}
	}
	return out
}

type world struct {
	A, B, C, R1, R2 *party
	logID           []byte
	logIDText       string
	appKeys         map[int][]byte
	byName          map[string]*party
}

func newWorld() (*world, error) {
	w := &world{appKeys: map[int][]byte{}, byName: map[string]*party{}}
	var err error
	mk := func(name string, rec bool) (*party, error) {
		var p *party
		var err error
		if rec {
			p, err = newRecoveryFromLabel(name)
		} else {
			p, err = newParty(name, false, nil)
		}
		if err == nil {
			w.byName[name] = p
		}
		return p, err
	}
	if w.A, err = mk("A", false); err != nil {
		return nil, err
	}
	if w.B, err = mk("B", false); err != nil {
		return nil, err
	}
	if w.C, err = mk("C", false); err != nil {
		return nil, err
	}
	if w.R1, err = mk("R1", true); err != nil {
		return nil, err
	}
	if w.R2, err = mk("R2", true); err != nil {
		return nil, err
	}
	w.logID = testSeed("log", "log-id")[:16]
	w.logIDText = "l_" + hx(w.logID)
	w.appKeys[1] = testSeed("log", "app-key-1")
	w.appKeys[2] = testSeed("log", "app-key-2")
	return w, nil
}

type built struct {
	proto  protocolJ
	strict strictJ
	rec    recoveryKeyJ
}

type logBuilder struct {
	w       *world
	seal    sealer
	entries []entryJ
	digests map[int][]byte
	rhs     map[int][]byte
	ks      []keySetJ
	cts     []cipherJ
	sigs    map[int][]byte
	payload map[int][]byte
}

func (b *logBuilder) baseRaw(n int) string { return posRaw(n, b.digests[n]) }

func (b *logBuilder) keySet(entry, index int, to *party, epochs []int) (string, error) {
	info := keysetInfo(b.w.logID, to.id, epochs)
	var pt []byte
	for _, e := range epochs {
		pt = append(pt, b.w.appKeys[e]...)
	}
	sealed, err := b.seal(entry, index, to.sealPk, info, pt)
	if err != nil {
		return "", err
	}
	b.ks = append(b.ks, keySetJ{Entry: entry, Index: index, To: to.idText, Epochs: epochs, Info: hx(info), Plaintext: hx(pt)})
	return obj("to", q(to.idText), "epochs", intList(epochs), "sealed", q(b64(sealed))), nil
}

func (b *logBuilder) keySets(entry int, epochs []int, to ...*party) (string, error) {
	var raws []string
	for i, p := range sortParties(to) {
		r, err := b.keySet(entry, i, p, epochs)
		if err != nil {
			return "", err
		}
		raws = append(raws, r)
	}
	return list(raws...), nil
}

func (b *logBuilder) add(name, ptype string, signer *party, payload string, changeID []byte) {
	n := len(b.entries) + 1
	pl := []byte(payload)
	sig := ed25519.Sign(signer.signPriv, pae(ptype, pl))
	rh := recordHash(ptype, pl, sig)
	eh := entryHash(ptype, changeID, rh)
	prev := sha(frame(s("snailfish.log-root.v1"), b.w.logID))
	if n > 1 {
		prev = b.digests[n-1]
	}
	d := digestN(prev, n, eh)
	b.digests[n], b.rhs[n], b.sigs[n], b.payload[n] = d, rh, sig, pl
	cid := ""
	if len(changeID) > 0 {
		cid = hx(changeID)
	}
	b.entries = append(b.entries, entryJ{
		Position: n, Name: name, PayloadType: ptype, Payload: payload,
		Envelope: envelopeJSON(ptype, pl, sig, signer.idText), Signer: signer.name,
		Sig: hx(sig), RecordHash: hx(rh), ChangeID: cid, EntryHash: hx(eh), Digest: hx(d),
	})
}

func (b *logBuilder) encrypt(entry int, aad []byte, pt string) ([]byte, error) {
	nonce := sha(frame(s("snailfish.test-seed.v1"), s("log"), s(fmt.Sprintf("nonce-%d", entry))))[:24]
	key := b.w.appKeys[1]
	if entry == 10 {
		key = b.w.appKeys[2]
	}
	ct, err := aeadSeal(key, nonce, aad, []byte(pt))
	if err != nil {
		return nil, err
	}
	b.cts = append(b.cts, cipherJ{Entry: entry, AAD: hx(aad), Nonce: hx(nonce), Plaintext: hx([]byte(pt))})
	return ct, nil
}

func changeIDFor(n int) []byte {
	return testSeed("log", fmt.Sprintf("change-id-%d", n))[:16]
}

func changeAAD(w *world, epoch int, cid []byte, author *party) []byte {
	return frame(s("snailfish.change.v1"), w.logID, u64(uint64(epoch)), cid, author.id)
}

func snapshotAAD(w *world, epoch int, author *party, pos int, d []byte) []byte {
	return frame(s("snailfish.snapshot.v1"), w.logID, u64(uint64(epoch)), author.id, u64(uint64(pos)), d)
}

func buildLog(w *world, seal sealer) (*logBuilder, error) {
	b := &logBuilder{w: w, seal: seal, digests: map[int][]byte{}, rhs: map[int][]byte{}, sigs: map[int][]byte{}, payload: map[int][]byte{}}
	b.digests[0] = sha(frame(s("snailfish.log-root.v1"), w.logID))
	log := q(w.logIDText)

	// 1 genesis
	ks, err := b.keySets(1, []int{1}, w.A, w.R1)
	if err != nil {
		return nil, err
	}
	b.add("genesis", "snailfish.genesis.v1", w.R1, obj(
		"log", log, "author", q(w.R1.idText), "base", b.baseRaw(0),
		"app", q(appName), "recovery", keysRaw(w.R1), "level", "1",
		"device", deviceRaw(w.A, "Laptop", 2), "epoch", "1",
		"commitment", q(b64(commitment(w.logID, 1, w.appKeys[1]))), "keys", ks), nil)

	// 2 grant B
	if ks, err = b.keySets(2, []int{1}, w.B); err != nil {
		return nil, err
	}
	b.add("grant-B", "snailfish.grant.v1", w.A, obj(
		"log", log, "author", q(w.A.idText), "base", b.baseRaw(1),
		"device", deviceRaw(w.B, "Phone", 1), "keys", ks), nil)

	// 3 change
	cid := changeIDFor(3)
	ct, err := b.encrypt(3, changeAAD(w, 1, cid, w.A), `{"op":"rename","task":1,"title":"Buy milk"}`)
	if err != nil {
		return nil, err
	}
	b.add("change", "snailfish.change.v1", w.A, obj(
		"log", log, "author", q(w.A.idText), "base", b.baseRaw(2),
		"epoch", "1", "change_id", q("c_"+hx(cid)), "ciphertext", q(b64(ct))), cid)

	// 4 snapshot
	ct, err = b.encrypt(4, snapshotAAD(w, 1, w.B, 3, b.digests[3]), `{"tasks":[{"id":1,"title":"Buy milk"}]}`)
	if err != nil {
		return nil, err
	}
	b.add("snapshot", "snailfish.snapshot.v1", w.B, obj(
		"log", log, "author", q(w.B.idText), "base", b.baseRaw(3),
		"epoch", "1", "state", b.baseRaw(3), "ciphertext", q(b64(ct))), nil)

	// 5 accept (base is position 3, not 4)
	b.add("accept", "snailfish.accept.v1", w.A, obj(
		"log", log, "author", q(w.A.idText), "base", b.baseRaw(3),
		"snapshot", fmt.Sprintf(`{"position":4,"hash":"%s"}`, b64(b.rhs[4])), "applied", b.baseRaw(3)), nil)

	// 6 device, 7 level
	b.add("device", "snailfish.device.v1", w.B, obj(
		"log", log, "author", q(w.B.idText), "base", b.baseRaw(5), "level", "2"), nil)
	b.add("level", "snailfish.level.v1", w.A, obj(
		"log", log, "author", q(w.A.idText), "base", b.baseRaw(6), "level", "2"), nil)

	// 8 grant C
	if ks, err = b.keySets(8, []int{1}, w.C); err != nil {
		return nil, err
	}
	b.add("grant-C", "snailfish.grant.v1", w.A, obj(
		"log", log, "author", q(w.A.idText), "base", b.baseRaw(7),
		"device", deviceRaw(w.C, "Tablet", 2), "keys", ks), nil)

	// 9 epoch
	if ks, err = b.keySets(9, []int{2}, w.A, w.B, w.R1); err != nil {
		return nil, err
	}
	stay := sortParties([]*party{w.A, w.B})
	b.add("epoch", "snailfish.epoch.v1", w.A, obj(
		"log", log, "author", q(w.A.idText), "base", b.baseRaw(8),
		"epoch", "2", "removed", list(q(w.C.idText)),
		"stay", list(q(stay[0].idText), q(stay[1].idText)),
		"commitment", q(b64(commitment(w.logID, 2, w.appKeys[2]))), "keys", ks), nil)

	// 10 change in epoch 2
	cid = changeIDFor(10)
	ct, err = b.encrypt(10, changeAAD(w, 2, cid, w.B), `{"op":"done","task":1}`)
	if err != nil {
		return nil, err
	}
	b.add("change-epoch-2", "snailfish.change.v1", w.B, obj(
		"log", log, "author", q(w.B.idText), "base", b.baseRaw(9),
		"epoch", "2", "change_id", q("c_"+hx(cid)), "ciphertext", q(b64(ct))), cid)

	// 11 recovery
	if ks, err = b.keySets(11, []int{1, 2}, w.R2); err != nil {
		return nil, err
	}
	proof := ed25519.Sign(w.R2.signPriv, frame(s("snailfish.recovery-proof.v1"), w.logID, w.R2.signPk, w.R2.sealPk))
	b.add("recovery", "snailfish.recovery.v1", w.R1, obj(
		"log", log, "author", q(w.R1.idText), "base", b.baseRaw(10),
		"recovery", keysRaw(w.R2), "proof", q(b64(proof)), "keys", ks), nil)
	return b, nil
}

func partyJ(p *party) deviceJ {
	return deviceJ{p.name, hx(p.signSeed), hx(p.sealSeed), hx(p.signPk), hx(p.sealPk), p.idText}
}

func recJ(p *party) recoveryJ {
	return recoveryJ{p.name, hx(p.secret), recoveryDisplay(p.secret), hx(p.signSeed), hx(p.sealSeed), hx(p.signPk), hx(p.sealPk), p.idText}
}

func framesJ() []frameJ {
	sets := [][][]byte{
		{s("ab"), {}},
		{},
		{s("snailfish.entry-hash.v1")},
		{s("snailfish.test.v1"), u64(1), u64(1<<53 - 1), {0x00, 0xff}},
		{{}, {}, {}},
		{s("snailfish.entry-hash.v1"), s("snailfish.change.v1"), bytes.Repeat([]byte{0xab}, 16), bytes.Repeat([]byte{0xcd}, 32)},
	}
	var out []frameJ
	for _, p := range sets {
		parts := []string{}
		for _, x := range p {
			parts = append(parts, hx(x))
		}
		out = append(out, frameJ{parts, hx(frame(p...))})
	}
	return out
}

func buildProtocol(w *world, seal sealer) (*protocolJ, *logBuilder, error) {
	b, err := buildLog(w, seal)
	if err != nil {
		return nil, nil, err
	}
	p := &protocolJ{Version: 1, Frames: framesJ()}
	for _, d := range []*party{w.A, w.B, w.C} {
		p.Devices = append(p.Devices, partyJ(d))
	}
	for _, r := range []*party{w.R1, w.R2} {
		p.Recovery = append(p.Recovery, recJ(r))
	}
	p.Log = logJ{
		LogID: w.logIDText, App: appName, Digest0: hx(b.digests[0]),
		AppKeys:     map[string]string{"1": hx(w.appKeys[1]), "2": hx(w.appKeys[2])},
		Commitments: map[string]string{"1": hx(commitment(w.logID, 1, w.appKeys[1])), "2": hx(commitment(w.logID, 2, w.appKeys[2]))},
		Entries:     b.entries,
	}
	// statements
	lg := q(w.logIDText)
	stmt := func(name, ptype string, signer *party, payload string) statementJ {
		pl := []byte(payload)
		sig := ed25519.Sign(signer.signPriv, pae(ptype, pl))
		return statementJ{name, ptype, payload, envelopeJSON(ptype, pl, sig, signer.idText), signer.name, hx(sig), hx(recordHash(ptype, pl, sig))}
	}
	p.Statements = []statementJ{
		stmt("checkpoint", "snailfish.checkpoint.v1", w.A, obj("log", lg, "author", q(w.A.idText), "position", "11", "digest", q(b64(b.digests[11])))),
		stmt("delete", "snailfish.delete.v1", w.R2, obj("log", lg, "author", q(w.R2.idText), "head", b.baseRaw(11), "expires", "1893456000")),
	}
	p.KeySets, p.Ciphertexts = b.ks, b.cts

	// envelope variants of entry 3
	e3 := b.entries[2]
	pl, sig, rh := b.payload[3], b.sigs[3], hx(b.rhs[3])
	ptype := e3.PayloadType
	url := func(x string) string {
		return strings.NewReplacer("+", "-", "/", "_").Replace(strings.TrimRight(x, "="))
	}
	std := func(x []byte) string { return b64(x) }
	if !strings.ContainsAny(std(pl)+std(sig), "+/") {
		return nil, nil, errors.New("entry 3 base64 holds no + or /, the url-safe variant would not differ")
	}
	if len(pl)%3 == 0 && len(sig)%3 == 0 {
		return nil, nil, errors.New("entry 3 base64 needs no padding, the unpadded variant would not differ")
	}
	mk := func(payloadT, sigsT string) string {
		return fmt.Sprintf(`{"payloadType":%q,"payload":"%s","signatures":%s}`, ptype, payloadT, sigsT)
	}
	one := func(keyid, sg string) string {
		return fmt.Sprintf(`[{"keyid":"%s","sig":"%s"}]`, keyid, sg)
	}
	kid := w.A.idText
	env3 := func(extra, sigs string) string {
		return fmt.Sprintf(`{"payloadType":%q,"payload":"%s","signatures":%s%s}`, ptype, std(pl), sigs, extra)
	}
	p.Envelopes = []envelopeJ{
		{"canonical", e3.Envelope, true, rh},
		{"url-safe-alphabet", mk(strings.NewReplacer("+", "-", "/", "_").Replace(std(pl)), one(kid, strings.NewReplacer("+", "-", "/", "_").Replace(std(sig)))), true, rh},
		{"no-padding", mk(strings.TrimRight(std(pl), "="), one(kid, strings.TrimRight(std(sig), "="))), true, rh},
		{"url-safe-no-padding", mk(url(std(pl)), one(kid, url(std(sig)))), true, rh},
		{"other-keyid", mk(std(pl), one("other", std(sig))), true, rh},
		{"no-keyid", mk(std(pl), fmt.Sprintf(`[{"sig":"%s"}]`, std(sig))), true, rh},
		{"unknown-field", fmt.Sprintf(`{"payloadType":%q,"payload":"%s","signatures":%s,"x":1}`, ptype, std(pl), one(kid, std(sig))), true, rh},
		{"unknown-field-float", env3(`,"x":1.5e3`, one(kid, std(sig))), true, rh},
		{"unknown-field-negative-zero", env3(`,"x":-0`, one(kid, std(sig))), true, rh},
		{"unknown-field-above-2^53", env3(`,"x":9007199254740993`, one(kid, std(sig))), true, rh},
		{"unknown-field-in-signature-float", env3("", fmt.Sprintf(`[{"keyid":"%s","sig":"%s","x":1.0}]`, kid, std(sig))), true, rh},
		{"unknown-field-nested", env3(`,"x":{"a":[1.5,-0,{"b":null}],"c":true}`, one(kid, std(sig))), true, rh},
		{"duplicate-key-in-signature", env3("", fmt.Sprintf(`[{"keyid":"%s","sig":"%s","keyid":"%s"}]`, kid, std(sig), kid)), false, ""},
		{"duplicate-key-in-unknown-object", env3(`,"x":{"a":1,"a":2}`, one(kid, std(sig))), false, ""},
		{"unknown-field-outside-binary64", env3(`,"x":1e999`, one(kid, std(sig))), false, ""},
		{"extra-whitespace", fmt.Sprintf("\n {\n \"payloadType\" : %q ,\n\t\"payload\" :\n \"%s\" ,\n \"signatures\" : [ {\n \"keyid\" : \"%s\" , \"sig\" : \"%s\" } ]\n }\n ", ptype, std(pl), kid, std(sig)), true, rh},
		{"two-signatures", mk(std(pl), fmt.Sprintf(`[{"keyid":"%s","sig":"%s"},{"keyid":"%s","sig":"%s"}]`, kid, std(sig), w.B.idText, std(sig))), false, ""},
		{"empty-signatures", mk(std(pl), "[]"), false, ""},
		{"duplicate-key-payload", fmt.Sprintf(`{"payloadType":%q,"payload":"%s","payload":"%s","signatures":%s}`, ptype, std(pl), std(pl), one(kid, std(sig))), false, ""},
		{"sig-63-bytes", mk(std(pl), one(kid, std(sig[:63]))), false, ""},
		{"sig-not-base64", mk(std(pl), one(kid, "!!not base64!!")), false, ""},
		{"missing-payload-type", fmt.Sprintf(`{"payload":"%s","signatures":%s}`, std(pl), one(kid, std(sig))), false, ""},
	}
	return p, b, nil
}
