package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

func main() {
	out := flag.String("out", "", "write vector files to this directory")
	outHTTP := flag.String("out-http", "", "write only http.json to this directory, using the sealed values of protocol.json there")
	outEnroll := flag.String("out-enroll", "", "write only enroll.json to this directory")
	check := flag.String("check", "", "check vector files in this directory")
	openRust := flag.String("open-rust", "", "open key sets that Rust sealed (JSON file)")
	flag.Parse()
	n := 0
	for _, v := range []string{*out, *outHTTP, *outEnroll, *check, *openRust} {
		if v != "" {
			n++
		}
	}
	if n != 1 {
		fmt.Fprintln(os.Stderr, "give exactly one of -out, -out-http, -out-enroll, -check, -open-rust")
		os.Exit(2)
	}
	var err error
	switch {
	case *out != "":
		err = runOut(*out)
	case *outHTTP != "":
		err = runOutHTTP(*outHTTP)
	case *outEnroll != "":
		err = runOutEnroll(*outEnroll)
	case *check != "":
		err = runCheck(*check)
	default:
		err = runOpenRust(*openRust)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func buildAll(sl sealer) (*protocolJ, *strictJ, *recoveryKeyJ, error) {
	w, err := newWorld()
	if err != nil {
		return nil, nil, nil, err
	}
	p, _, err := buildProtocol(w, sl)
	if err != nil {
		return nil, nil, nil, err
	}
	st, err := buildStrict(p, w)
	if err != nil {
		return nil, nil, nil, err
	}
	rk, err := buildRecoveryKeys(w)
	if err != nil {
		return nil, nil, nil, err
	}
	return p, st, rk, nil
}

func runOut(dir string) error {
	p, st, rk, err := buildAll(freshSealer)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	w, err := newWorld()
	if err != nil {
		return err
	}
	h, err := buildHTTP(w, httpSealer(p))
	if err != nil {
		return err
	}
	en, err := buildEnroll(w)
	if err != nil {
		return err
	}
	for name, v := range map[string]any{"protocol.json": p, "strict-json.json": st, "recovery-key.json": rk, "http.json": h, "enroll.json": en} {
		b, err := marshal(v)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			return err
		}
		fmt.Printf("wrote %s (%d bytes)\n", filepath.Join(dir, name), len(b))
	}
	return nil
}

// runOutHTTP writes http.json only. protocol.json holds the sealed key sets,
// because Go cannot fix the HPKE ephemeral key.
func runOutHTTP(dir string) error {
	var p protocolJ
	if err := load(filepath.Join(dir, "protocol.json"), &p); err != nil {
		return err
	}
	w, err := newWorld()
	if err != nil {
		return err
	}
	h, err := buildHTTP(w, httpSealer(&p))
	if err != nil {
		return err
	}
	b, err := marshal(h)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "http.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d bytes)\n", path, len(b))
	return nil
}

// runOutEnroll writes enroll.json only. It holds no sealed values.
func runOutEnroll(dir string) error {
	w, err := newWorld()
	if err != nil {
		return err
	}
	en, err := buildEnroll(w)
	if err != nil {
		return err
	}
	b, err := marshal(en)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "enroll.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d bytes)\n", path, len(b))
	return nil
}

func load(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if !bytes.HasSuffix(b, []byte("}\n")) {
		return fmt.Errorf("%s: no trailing newline", path)
	}
	// the file must be in the pretty-printed form that -out writes
	re, err := marshal(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(re, b) {
		return fmt.Errorf("%s: not in canonical pretty-printed form", path)
	}
	return nil
}

// diff returns the path of the first difference between two decoded JSON values.
func diff(path string, a, b any) string {
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok {
			return path
		}
		for k := range x {
			if _, ok := y[k]; !ok {
				return path + "." + k + " (missing in rebuilt)"
			}
			if d := diff(path+"."+k, x[k], y[k]); d != "" {
				return d
			}
		}
		for k := range y {
			if _, ok := x[k]; !ok {
				return path + "." + k + " (missing in file)"
			}
		}
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return path + " (length)"
		}
		for i := range x {
			if d := diff(fmt.Sprintf("%s[%d]", path, i), x[i], y[i]); d != "" {
				return d
			}
		}
	default:
		if !reflect.DeepEqual(a, b) {
			return fmt.Sprintf("%s: file has %v, recomputed %v", path, trunc(a), trunc(b))
		}
	}
	return ""
}

func trunc(v any) string {
	t := fmt.Sprint(v)
	if len(t) > 60 {
		t = t[:60] + "..."
	}
	return t
}

func compare(name string, file, rebuilt any) error {
	fb, _ := json.Marshal(file)
	rb, _ := json.Marshal(rebuilt)
	if bytes.Equal(fb, rb) {
		return nil
	}
	var fa, ra any
	_ = json.Unmarshal(fb, &fa)
	_ = json.Unmarshal(rb, &ra)
	return fmt.Errorf("%s: mismatch at %s", name, diff("$", fa, ra))
}

func runCheck(dir string) error {
	var p protocolJ
	var st strictJ
	var rk recoveryKeyJ
	if err := load(filepath.Join(dir, "protocol.json"), &p); err != nil {
		return err
	}
	if err := load(filepath.Join(dir, "strict-json.json"), &st); err != nil {
		return err
	}
	if err := load(filepath.Join(dir, "recovery-key.json"), &rk); err != nil {
		return err
	}
	var hf httpJ
	if err := load(filepath.Join(dir, "http.json"), &hf); err != nil {
		return err
	}
	var ef enrollJ
	if err := load(filepath.Join(dir, "enroll.json"), &ef); err != nil {
		return err
	}
	w, err := newWorld()
	if err != nil {
		return err
	}
	if err := checkKeySets(w, &p); err != nil {
		return err
	}
	// Rebuild everything. HPKE sealed values come from the file, since Go cannot fix the ephemeral key.
	stored := func(entry, index int, pk, info, plaintext []byte) ([]byte, error) {
		return storedSealed(&p, entry, index)
	}
	rp, rst, rrk, err := buildAll(stored)
	if err != nil {
		return err
	}
	if err := compare("protocol.json", &p, rp); err != nil {
		return err
	}
	if err := compare("strict-json.json", &st, rst); err != nil {
		return err
	}
	if err := compare("recovery-key.json", &rk, rrk); err != nil {
		return err
	}
	rh, err := buildHTTP(w, httpSealer(&p))
	if err != nil {
		return err
	}
	if err := compare("http.json", &hf, rh); err != nil {
		return err
	}
	if err := checkHTTP(&hf, w); err != nil {
		return fmt.Errorf("http.json: %w", err)
	}
	re, err := buildEnroll(w)
	if err != nil {
		return err
	}
	if err := compare("enroll.json", &ef, re); err != nil {
		return err
	}
	if err := checkEnrollOracle(&ef, w); err != nil {
		return fmt.Errorf("enroll.json: %w", err)
	}
	if err := checkEnvelopes(&p); err != nil {
		return err
	}
	if err := checkStrict(&st); err != nil {
		return err
	}
	if err := checkRecovery(&rk); err != nil {
		return err
	}
	fmt.Printf("OK: %d entries, %d statements, %d key sets opened, %d ciphertexts, %d envelopes, %d strict cases, %d+%d recovery texts, http: %d signed, %d invalid, %d append, %d append_hold, %d fetch, %d status, %d repair, %d enroll; enroll: %d codes, %d+%d typed, %d+%d payloads, %d transcripts, %d confirmations\n",
		len(p.Log.Entries), len(p.Statements), len(p.KeySets), len(p.Ciphertexts), len(p.Envelopes), len(st.Cases), len(rk.Valid), len(rk.Invalid), len(hf.Signed), len(hf.Invalid), len(hf.Append), len(hf.AppendHold), len(hf.Fetch), len(hf.Status), len(hf.Repair), len(hf.Enroll),
		len(ef.Codes), len(ef.Typed.Valid), len(ef.Typed.Invalid), len(ef.Payloads.Valid), len(ef.Payloads.Invalid), len(ef.Transcripts), len(ef.Confirmations))
	return nil
}

type rawKeySet struct {
	To     string `json:"to"`
	Epochs []int  `json:"epochs"`
	Sealed string `json:"sealed"`
}

func storedKeySets(p *protocolJ, entry int) ([]rawKeySet, error) {
	if entry < 1 || entry > len(p.Log.Entries) {
		return nil, fmt.Errorf("key set refers to entry %d", entry)
	}
	var pl struct {
		Keys []rawKeySet `json:"keys"`
	}
	if err := json.Unmarshal([]byte(p.Log.Entries[entry-1].Payload), &pl); err != nil {
		return nil, fmt.Errorf("entry %d payload: %w", entry, err)
	}
	return pl.Keys, nil
}

func storedSealed(p *protocolJ, entry, index int) ([]byte, error) {
	ks, err := storedKeySets(p, entry)
	if err != nil {
		return nil, err
	}
	if index >= len(ks) {
		return nil, fmt.Errorf("entry %d has no key set %d", entry, index)
	}
	return base64.StdEncoding.DecodeString(ks[index].Sealed)
}

func partyByID(w *world, id string) *party {
	for _, x := range []*party{w.A, w.B, w.C, w.R1, w.R2} {
		if x.idText == id {
			return x
		}
	}
	return nil
}

// checkKeySets opens every key set of the file with crypto/hpke.
func checkKeySets(w *world, p *protocolJ) error {
	if len(p.KeySets) == 0 {
		return errors.New("protocol.json holds no key sets")
	}
	for _, k := range p.KeySets {
		who := fmt.Sprintf("key set entry %d index %d", k.Entry, k.Index)
		sealed, err := storedSealed(p, k.Entry, k.Index)
		if err != nil {
			return fmt.Errorf("%s: %w", who, err)
		}
		raws, _ := storedKeySets(p, k.Entry)
		if raws[k.Index].To != k.To {
			return fmt.Errorf("%s: payload to %s differs from key_sets to %s", who, raws[k.Index].To, k.To)
		}
		to := partyByID(w, k.To)
		if to == nil {
			return fmt.Errorf("%s: unknown recipient %s", who, k.To)
		}
		info, err := hex.DecodeString(k.Info)
		if err != nil {
			return err
		}
		want := keysetInfo(w.logID, to.id, k.Epochs)
		if !bytes.Equal(info, want) {
			return fmt.Errorf("%s: info differs from PROTOCOL.md 7.3", who)
		}
		pt, err := openKeySet(to.sealSeed, info, sealed)
		if err != nil {
			return fmt.Errorf("%s: hpke.Open failed: %w", who, err)
		}
		if hex.EncodeToString(pt) != k.Plaintext {
			return fmt.Errorf("%s: opened plaintext differs from the file", who)
		}
		var exp []byte
		for _, e := range k.Epochs {
			exp = append(exp, w.appKeys[e]...)
		}
		if !bytes.Equal(pt, exp) {
			return fmt.Errorf("%s: plaintext is not the app keys of the epochs", who)
		}
	}
	return nil
}

type parsedEnvelope struct {
	ptype   string
	payload []byte
	sig     []byte
}

func decodeLoose(t string) ([]byte, error) {
	t = strings.NewReplacer("-", "+", "_", "/").Replace(strings.TrimRight(t, "="))
	return base64.RawStdEncoding.DecodeString(t)
}

// parseEnvelope is the reader of PROTOCOL.md section 4.
func parseEnvelope(text string) (*parsedEnvelope, error) {
	v, err := parseLenient([]byte(text))
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("envelope is not an object")
	}
	pt, ok := m["payloadType"].(string)
	if !ok {
		return nil, errors.New("no payloadType")
	}
	pls, ok := m["payload"].(string)
	if !ok {
		return nil, errors.New("no payload")
	}
	payload, err := decodeLoose(pls)
	if err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	sigs, ok := m["signatures"].([]any)
	if !ok || len(sigs) != 1 {
		return nil, errors.New("signatures must hold exactly one entry")
	}
	sm, ok := sigs[0].(map[string]any)
	if !ok {
		return nil, errors.New("bad signature entry")
	}
	ss, ok := sm["sig"].(string)
	if !ok {
		return nil, errors.New("no sig")
	}
	sig, err := decodeLoose(ss)
	if err != nil {
		return nil, fmt.Errorf("sig: %w", err)
	}
	if len(sig) != 64 {
		return nil, fmt.Errorf("sig has %d bytes", len(sig))
	}
	return &parsedEnvelope{pt, payload, sig}, nil
}

func checkEnvelopes(p *protocolJ) error {
	signers := map[string]*party{}
	for _, d := range p.Devices {
		pk, _ := hex.DecodeString(d.SignPk)
		signers[d.Name] = &party{signPk: pk}
	}
	for _, d := range p.Recovery {
		pk, _ := hex.DecodeString(d.SignPk)
		signers[d.Name] = &party{signPk: pk}
	}
	verify := func(what, env, signer, recordHashHex string) error {
		e, err := parseEnvelope(env)
		if err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		sg := signers[signer]
		if sg == nil {
			return fmt.Errorf("%s: unknown signer %q", what, signer)
		}
		if !ed25519.Verify(sg.signPk, pae(e.ptype, e.payload), e.sig) {
			return fmt.Errorf("%s: signature does not verify", what)
		}
		if hx(recordHash(e.ptype, e.payload, e.sig)) != recordHashHex {
			return fmt.Errorf("%s: record hash differs", what)
		}
		return nil
	}
	for _, e := range p.Log.Entries {
		if err := verify(fmt.Sprintf("entry %d", e.Position), e.Envelope, e.Signer, e.RecordHash); err != nil {
			return err
		}
	}
	for _, e := range p.Statements {
		if err := verify("statement "+e.Name, e.Envelope, e.Signer, e.RecordHash); err != nil {
			return err
		}
	}
	for _, e := range p.Envelopes {
		pe, err := parseEnvelope(e.Envelope)
		if e.Valid != (err == nil) {
			return fmt.Errorf("envelope %q: valid=%v but reader says %v", e.Name, e.Valid, err)
		}
		if e.Valid {
			if !ed25519.Verify(signers["A"].signPk, pae(pe.ptype, pe.payload), pe.sig) {
				return fmt.Errorf("envelope %q: signature does not verify", e.Name)
			}
			if hx(recordHash(pe.ptype, pe.payload, pe.sig)) != e.RecordHash || e.RecordHash != p.Log.Entries[2].RecordHash {
				return fmt.Errorf("envelope %q: record hash is not that of entry 3", e.Name)
			}
		} else if e.RecordHash != "" {
			return fmt.Errorf("envelope %q: invalid case carries a record hash", e.Name)
		}
	}
	return nil
}

func checkStrict(st *strictJ) error {
	for _, c := range st.Cases {
		var raw []byte
		switch {
		case c.Payload != nil && c.PayloadHex == nil:
			raw = []byte(*c.Payload)
		case c.PayloadHex != nil && c.Payload == nil:
			var err error
			if raw, err = hex.DecodeString(*c.PayloadHex); err != nil {
				return fmt.Errorf("strict case %q: %w", c.Name, err)
			}
		default:
			return fmt.Errorf("strict case %q: needs exactly one of payload and payload_hex", c.Name)
		}
		if err := validatePayload(c.PayloadType, raw); (err == nil) != c.Valid {
			return fmt.Errorf("strict case %q: valid=%v but oracle says %v", c.Name, c.Valid, err)
		}
	}
	return nil
}

func checkRecovery(rk *recoveryKeyJ) error {
	for _, c := range rk.Valid {
		sec, err := parseRecoveryKey(c.Text)
		if err != nil || hx(sec) != c.Secret {
			return fmt.Errorf("recovery text %q: want secret %s, got %x, err %v", c.Text, c.Secret, sec, err)
		}
	}
	for _, c := range rk.Invalid {
		if _, err := parseRecoveryKey(c.Text); err == nil {
			return fmt.Errorf("invalid recovery text %q (%s) accepted", c.Text, c.Name)
		}
	}
	return nil
}

type rustSet struct {
	SealSeed  string   `json:"seal_seed"`
	To        string   `json:"to"`
	LogID     string   `json:"log_id"`
	Epochs    []int    `json:"epochs"`
	Sealed    string   `json:"sealed"`
	Plaintext string   `json:"plaintext"`
	_         struct{} `json:"-"`
}

func runOpenRust(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var f struct {
		KeySets []rustSet `json:"key_sets"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if len(f.KeySets) == 0 {
		return fmt.Errorf("%s holds zero key sets", path)
	}
	for i, k := range f.KeySets {
		who := fmt.Sprintf("key set %d (to %s)", i, k.To)
		if !strings.HasPrefix(k.LogID, "l_") || len(k.Epochs) == 0 {
			return fmt.Errorf("%s: bad log_id or empty epochs", who)
		}
		logID, err := decodeID(k.LogID, "l_", 16)
		if err != nil {
			return fmt.Errorf("%s: %w", who, err)
		}
		var rid []byte
		if strings.HasPrefix(k.To, "d_") {
			rid, err = decodeID(k.To, "d_", 32)
		} else {
			rid, err = decodeID(k.To, "r_", 32)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", who, err)
		}
		seed, err1 := hex.DecodeString(k.SealSeed)
		sealed, err2 := hex.DecodeString(k.Sealed)
		want, err3 := hex.DecodeString(k.Plaintext)
		if err := errors.Join(err1, err2, err3); err != nil {
			return fmt.Errorf("%s: %w", who, err)
		}
		pt, err := openKeySet(seed, keysetInfo(logID, rid, k.Epochs), sealed)
		if err != nil {
			return fmt.Errorf("%s: hpke.Open failed: %w", who, err)
		}
		if !bytes.Equal(pt, want) {
			return fmt.Errorf("%s: opened plaintext differs from the file", who)
		}
	}
	fmt.Printf("OK: opened %d Rust-sealed key sets\n", len(f.KeySets))
	return nil
}
