package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// This file builds and checks vectors/enroll.json (vectors/README.md "Format
// of enroll.json"): the session code and payload of PROTOCOL.md 11.1, the
// transcript of 11.2 and the confirmation statement of 6.3.

const (
	enrollRelayURL = "https://" + httpAuthority
	enrollPayload  = "snailfish-enroll-v1"
)

type codeJ struct {
	Name     string `json:"name"`
	Session  string `json:"session"`
	Symbols  string `json:"symbols"`
	Display  string `json:"display"`
	PayloadT string `json:"payload_t"`
	PayloadN string `json:"payload_n"`
}

type typedValidJ struct {
	Name    string `json:"name"`
	Text    string `json:"text"`
	Session string `json:"session"`
}

type textInvalidJ struct {
	Name string `json:"name"`
	Text string `json:"text"`
}

type typedJ struct {
	Valid   []typedValidJ  `json:"valid"`
	Invalid []textInvalidJ `json:"invalid"`
}

type payloadValidJ struct {
	Name     string `json:"name"`
	Text     string `json:"text"`
	Role     string `json:"role"`
	RelayURL string `json:"relay_url"`
	Session  string `json:"session"`
}

type payloadsJ struct {
	Valid   []payloadValidJ `json:"valid"`
	Invalid []textInvalidJ  `json:"invalid"`
}

type transcriptJ struct {
	Name        string `json:"name"`
	Session     string `json:"session"`
	Trusted     string `json:"trusted"`
	New         string `json:"new"`
	TID         string `json:"t_id"`
	NID         string `json:"n_id"`
	NewDevice   string `json:"new_device"`
	TNonce      string `json:"t_nonce"`
	NNonce      string `json:"n_nonce"`
	CommitFrame string `json:"commit_frame"`
	Commitment  string `json:"commitment"`
	CodeFrame   string `json:"code_frame"`
	Digits      string `json:"digits"`
	Code        string `json:"code"`
}

type confirmJ struct {
	Name       string `json:"name"`
	Transcript string `json:"transcript"`
	Rule       string `json:"rule"`
	Payload    string `json:"payload"`
	Envelope   string `json:"envelope"`
	Signer     string `json:"signer"`
	Valid      bool   `json:"valid"`
}

type enrollJ struct {
	Version       int           `json:"version"`
	RelayURL      string        `json:"relay_url"`
	Devices       []deviceJ     `json:"devices"`
	Codes         []codeJ       `json:"codes"`
	Typed         typedJ        `json:"typed"`
	Payloads      payloadsJ     `json:"payloads"`
	Transcripts   []transcriptJ `json:"transcripts"`
	Confirmations []confirmJ    `json:"confirmations"`
}

// ---- 11.1 session code and payload ----

func sessionCheck(sid []byte) []byte {
	return sha(frame(s("snailfish.enroll-check.v1"), sid))[:4]
}

func sessionSymbols(sid []byte) string {
	return crockfordEncode(append(append([]byte{}, sid...), sessionCheck(sid)...))
}

func sessionText(sid []byte) string { return "e_" + hx(sid) }

func payloadText(role, relayURL string, sid []byte) string {
	return strings.Join([]string{enrollPayload, role, relayURL, sessionSymbols(sid)}, " ")
}

// parseSessionCode is the typed code reader of 11.1.
func parseSessionCode(text string) ([]byte, error) { return parseCode(text, sessionCheck) }

var relayURLRe = regexp.MustCompile(`^(https?)://([a-z0-9]([a-z0-9.-]*[a-z0-9])?)(:([1-9][0-9]{0,4}))?$`)

// checkRelayURL is the relay URL rule of 8.3: the scheme, then the authority
// (lowercase host, and a port only if it is not the default port), with no
// path. A trailing "/" is a path.
func checkRelayURL(u string) error {
	m := relayURLRe.FindStringSubmatch(u)
	if m == nil {
		return fmt.Errorf("relay URL %q breaks 8.3", u)
	}
	if m[5] != "" {
		port, _ := strconv.Atoi(m[5])
		if port > 65535 || (m[1] == "https" && port == 443) || (m[1] == "http" && port == 80) {
			return fmt.Errorf("relay URL %q: bad port", u)
		}
	}
	return nil
}

// parsePayload is the payload reader of 11.1.
func parsePayload(text string) (role, relayURL string, sid []byte, err error) {
	parts := strings.Split(text, " ")
	if len(parts) != 4 {
		return "", "", nil, fmt.Errorf("%d parts, want 4", len(parts))
	}
	if parts[0] != enrollPayload {
		return "", "", nil, fmt.Errorf("first part %q", parts[0])
	}
	if parts[1] != "t" && parts[1] != "n" {
		return "", "", nil, fmt.Errorf("role %q", parts[1])
	}
	if err := checkRelayURL(parts[2]); err != nil {
		return "", "", nil, err
	}
	sid, err = parseSessionCode(parts[3])
	if err != nil {
		return "", "", nil, err
	}
	return parts[1], parts[2], sid, nil
}

// ---- 11.2 transcript ----

func commitFrame(sid, tID, nID, tNonce []byte) []byte {
	return frame(s("snailfish.enroll-commit.v1"), sid, s("trusted"), tID, s("new"), nID, tNonce)
}

func codeFrame(sid, tID, nID, tNonce, nNonce []byte) []byte {
	return frame(s("snailfish.enroll-code.v1"), sid, s("trusted"), tID, s("new"), nID, tNonce, nNonce)
}

func codeOf(digits []byte) string {
	return fmt.Sprintf("%06d", binary.BigEndian.Uint64(digits[:8])%1000000)
}

// deviceLabels are the device objects of protocol.json for each device.
var deviceLabels = map[string]struct {
	name  string
	level int
}{"A": {"Laptop", 2}, "B": {"Phone", 1}, "C": {"Tablet", 2}}

func helloDevice(p *party) string {
	l := deviceLabels[p.name]
	return deviceRaw(p, l.name, l.level)
}

func newTranscript(name string, sid []byte, t, n *party, tNonce, nNonce []byte) transcriptJ {
	cf := commitFrame(sid, t.id, n.id, tNonce)
	df := codeFrame(sid, t.id, n.id, tNonce, nNonce)
	digits := sha(df)
	return transcriptJ{
		Name: name, Session: sessionText(sid), Trusted: t.name, New: n.name, TID: t.idText, NID: n.idText,
		NewDevice: helloDevice(n), TNonce: hx(tNonce), NNonce: hx(nNonce),
		CommitFrame: hx(cf), Commitment: hx(sha(cf)), CodeFrame: hx(df), Digits: hx(digits), Code: codeOf(digits),
	}
}

func enrollSeed(purpose string) []byte { return testSeed("enroll", purpose) }

// mainTranscript is the transcript of the honest enrollment of C by A. The
// enroll cases of http.json use the same values.
func mainTranscript(w *world) transcriptJ {
	return newTranscript("a-trusted-c-new", enrollSeed("session-1")[:16], w.A, w.C, enrollSeed("t-nonce-1"), enrollSeed("n-nonce-1"))
}

// ---- 6.3 confirmation ----

func confirmPayload(sess, trusted, device string, tNonce, nNonce []byte) string {
	return obj("session", q(sess), "trusted", q(trusted), "device", device,
		"trusted_nonce", q(b64(tNonce)), "new_nonce", q(b64(nNonce)))
}

func confirmOf(t transcriptJ) string {
	return confirmPayload(t.Session, t.TID, t.NewDevice, unhex(t.TNonce), unhex(t.NNonce))
}

func unhex(x string) []byte {
	b, err := hex.DecodeString(x)
	if err != nil {
		panic(err)
	}
	return b
}

// acceptConfirm is the check of the trusted device in 11.2.
func acceptConfirm(env string, t transcriptJ) error {
	e, err := parseEnvelope(env)
	if err != nil {
		return err
	}
	if e.ptype != "snailfish.confirm.v1" {
		return fmt.Errorf("payload type %q", e.ptype)
	}
	if err := validatePayload(e.ptype, e.payload); err != nil {
		return err
	}
	v, _ := parseStrict(e.payload)
	m := v.(map[string]any)
	dev := m["device"].(map[string]any)
	sign, _ := decodeB64(dev["sign"].(string))
	if !ed25519.Verify(sign, pae(e.ptype, e.payload), e.sig) {
		return errors.New("signature does not verify with device.sign")
	}
	hv, err := parseStrict([]byte(t.NewDevice))
	if err != nil {
		return err
	}
	hello := hv.(map[string]any)
	if len(dev) != len(hello) {
		return errors.New("device differs from new.hello")
	}
	for k, x := range hello {
		if dev[k] != x {
			return fmt.Errorf("device.%s differs from new.hello", k)
		}
	}
	switch {
	case m["session"] != t.Session:
		return errors.New("session differs")
	case m["trusted"] != t.TID:
		return errors.New("trusted differs")
	case m["trusted_nonce"] != b64(unhex(t.TNonce)):
		return errors.New("trusted_nonce differs")
	case m["new_nonce"] != b64(unhex(t.NNonce)):
		return errors.New("new_nonce differs")
	}
	return nil
}

// ---- build ----

func buildEnroll(w *world) (*enrollJ, error) {
	e := &enrollJ{Version: 1, RelayURL: enrollRelayURL}
	for _, d := range []*party{w.A, w.B, w.C} {
		e.Devices = append(e.Devices, partyJ(d))
	}

	// codes
	sid1 := enrollSeed("session-1")[:16]
	var alias []byte
	for i := 0; i < 100000; i++ {
		c := enrollSeed(fmt.Sprintf("session-alias-%d", i))[:16]
		sym := sessionSymbols(c)
		if strings.Contains(sym, "0") && strings.Contains(sym, "1") {
			alias = c
			break
		}
	}
	if alias == nil {
		return nil, errors.New("no alias session found")
	}
	for _, c := range []struct {
		name string
		sid  []byte
	}{
		{"session-1", sid1},
		{"session-2", enrollSeed("session-2")[:16]},
		{"alias", alias},
		{"all-zero", make([]byte, 16)},
		{"all-ff", bytes.Repeat([]byte{0xff}, 16)},
	} {
		sym := sessionSymbols(c.sid)
		e.Codes = append(e.Codes, codeJ{c.name, sessionText(c.sid), sym, groups(sym),
			payloadText("t", enrollRelayURL, c.sid), payloadText("n", enrollRelayURL, c.sid)})
	}

	// typed codes
	d := groups(sessionSymbols(sid1))
	ad, as := groups(sessionSymbols(alias)), sessionText(alias)
	add := func(name, text, sess string) { e.Typed.Valid = append(e.Typed.Valid, typedValidJ{name, text, sess}) }
	add("display", d, sessionText(sid1))
	add("lowercase", strings.ToLower(d), sessionText(sid1))
	add("no-dashes", strings.ReplaceAll(d, "-", ""), sessionText(sid1))
	add("spaces", strings.ReplaceAll(d, "-", " "), sessionText(sid1))
	add("spaces-and-dashes", strings.ReplaceAll(strings.ToLower(d), "-", " - "), sessionText(sid1))
	add("alias-display", ad, as)
	add("alias-O-for-0", strings.ReplaceAll(ad, "0", "O"), as)
	add("alias-I-for-1", strings.ReplaceAll(ad, "1", "I"), as)
	add("alias-L-for-1", strings.ReplaceAll(ad, "1", "L"), as)
	add("alias-lowercase-o-i-l", strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(ad), "0", "o"), "1", "l"), as)
	nd := sessionSymbols(sid1)
	flip := func(x string) string {
		last, n := x[len(x)-1], byte('0')
		if last == '0' {
			n = '1'
		}
		return x[:len(x)-1] + string(n)
	}
	recCheck := crockfordEncode(append(append([]byte{}, sid1...), recoveryCheck(sid1)...))
	e.Typed.Invalid = []textInvalidJ{
		{"wrong-check", groups(flip(nd))},
		{"recovery-check-label", groups(recCheck)},
		{"contains-U", groups("U" + nd[1:])},
		{"31-symbols", d[:len(d)-1]},
		{"33-symbols", d + "0"},
		{"empty", ""},
	}

	// payloads
	sym := sessionSymbols(sid1)
	pv := func(name, text, role, url string) {
		e.Payloads.Valid = append(e.Payloads.Valid, payloadValidJ{name, text, role, url, sessionText(sid1)})
	}
	pv("role-t", payloadText("t", enrollRelayURL, sid1), "t", enrollRelayURL)
	pv("role-n", payloadText("n", enrollRelayURL, sid1), "n", enrollRelayURL)
	portURL := "http://" + portAuth
	pv("http-with-port", payloadText("n", portURL, sid1), "n", portURL)
	pv("lowercase-symbols", strings.Join([]string{enrollPayload, "t", enrollRelayURL, strings.ToLower(sym)}, " "), "t", enrollRelayURL)
	pt := func(parts ...string) string { return strings.Join(parts, " ") }
	e.Payloads.Invalid = []textInvalidJ{
		{"wrong-first-part", pt("snailfish-enroll-v2", "t", enrollRelayURL, sym)},
		{"bad-role", pt(enrollPayload, "x", enrollRelayURL, sym)},
		{"role-uppercase", pt(enrollPayload, "T", enrollRelayURL, sym)},
		{"relay-url-with-path", pt(enrollPayload, "t", enrollRelayURL+"/sync", sym)},
		{"relay-url-trailing-slash", pt(enrollPayload, "t", enrollRelayURL+"/", sym)},
		{"relay-url-other-scheme", pt(enrollPayload, "t", "wss://"+httpAuthority, sym)},
		{"three-parts", pt(enrollPayload, "t", enrollRelayURL)},
		{"five-parts", pt(enrollPayload, "t", enrollRelayURL, sym, "x")},
		{"double-space", enrollPayload + "  t " + enrollRelayURL + " " + sym},
		{"symbols-wrong-check", pt(enrollPayload, "t", enrollRelayURL, flip(sym))},
	}

	// transcripts
	main := mainTranscript(w)
	e.Transcripts = []transcriptJ{
		main,
		newTranscript("a-trusted-b-new", enrollSeed("session-2")[:16], w.A, w.B, enrollSeed("t-nonce-2"), enrollSeed("n-nonce-2")),
		newTranscript("b-trusted-a-new", enrollSeed("session-3")[:16], w.B, w.A, enrollSeed("t-nonce-3"), enrollSeed("n-nonce-3")),
	}
	sid4, tn4 := enrollSeed("session-4")[:16], enrollSeed("t-nonce-4")
	found := false
	for i := 0; i < 1000000; i++ {
		nn := enrollSeed(fmt.Sprintf("n-nonce-4-%d", i))
		if t := newTranscript("code-leading-zeros", sid4, w.A, w.C, tn4, nn); strings.HasPrefix(t.Code, "000") {
			e.Transcripts = append(e.Transcripts, t)
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("no n_nonce gives a code with leading zeros")
	}

	// confirmations, all for the main transcript
	sid, tNonce := sid1, unhex(main.TNonce)
	other := enrollSeed("other-nonce")
	conf := func(name, rule, ptype, payload string, sg *party, valid bool) confirmJ {
		env, _, _ := signEnv(sg, ptype, payload)
		return confirmJ{name, main.Name, rule, payload, env, sg.name, valid}
	}
	ok := confirmOf(main)
	f := splitFields(ok)
	ct := "snailfish.confirm.v1"
	rev := fields{}
	for i := len(f) - 1; i >= 0; i-- {
		rev = append(rev, f[i])
	}
	badDev := strings.Replace(main.NewDevice, w.C.idText, w.A.idText, 1)
	e.Confirmations = []confirmJ{
		conf("valid", "", ct, ok, w.C, true),
		conf("valid-other-key-order", "", ct, rev.render(), w.C, true),
		conf("missing-new-nonce", "6.3", ct, f.drop("new_nonce").render(), w.C, false),
		conf("extra-field", "6.3", ct, f.render()[:len(ok)-1]+`,"x":1}`, w.C, false),
		conf("author-field", "6.3", ct, f.render()[:len(ok)-1]+`,"author":"`+w.C.idText+`"}`, w.C, false),
		conf("device-id-not-matching-keys", "6.3", ct, f.set("device", badDev).render(), w.C, false),
		conf("trusted-nonce-31-bytes", "6.3", ct, f.set("trusted_nonce", q(b64(tNonce[:31]))).render(), w.C, false),
		conf("session-uppercase-hex", "6.3", ct, f.set("session", q("e_"+strings.ToUpper(hx(sid)))).render(), w.C, false),
		conf("session-wrong-prefix", "6.3", ct, f.set("session", q("l_"+hx(sid))).render(), w.C, false),
		conf("signed-by-trusted-device", "11.2", ct, ok, w.A, false),
		conf("wrong-payload-type", "11.2", "snailfish.checkpoint.v1", ok, w.C, false),
		conf("other-session", "11.2", ct, f.set("session", q(sessionText(enrollSeed("session-2")[:16]))).render(), w.C, false),
		conf("other-trusted", "11.2", ct, f.set("trusted", q(w.B.idText)).render(), w.C, false),
		conf("device-differs-from-hello", "11.2", ct, f.set("device", deviceRaw(w.C, "Other tablet", 2)).render(), w.C, false),
		conf("other-trusted-nonce", "11.2", ct, f.set("trusted_nonce", q(b64(other))).render(), w.C, false),
		conf("other-new-nonce", "11.2", ct, f.set("new_nonce", q(b64(other))).render(), w.C, false),
	}
	if err := checkEnrollOracle(e, w); err != nil {
		return nil, fmt.Errorf("self-check: %w", err)
	}
	return e, nil
}

// checkEnrollOracle checks each case of e with the readers of this file. It
// does not trust any derived field of the file.
func checkEnrollOracle(e *enrollJ, w *world) error {
	if e.Version != 1 || e.RelayURL != enrollRelayURL || checkRelayURL(e.RelayURL) != nil {
		return errors.New("bad header fields")
	}
	for _, d := range e.Devices {
		p := w.byName[d.Name]
		if p == nil || d != partyJ(p) {
			return fmt.Errorf("device %s differs from the world", d.Name)
		}
	}
	for _, c := range e.Codes {
		sid, err := decodeID(c.Session, "e_", 16)
		if err != nil {
			return fmt.Errorf("code %s: %w", c.Name, err)
		}
		if c.Symbols != sessionSymbols(sid) || c.Display != groups(c.Symbols) {
			return fmt.Errorf("code %s: symbols or display differ from 11.1", c.Name)
		}
		for _, x := range []struct{ text, role string }{{c.Display, ""}, {c.Symbols, ""}, {c.PayloadT, "t"}, {c.PayloadN, "n"}} {
			var got []byte
			if x.role == "" {
				got, err = parseSessionCode(x.text)
			} else {
				var role, url string
				role, url, got, err = parsePayload(x.text)
				if err == nil && (role != x.role || url != e.RelayURL) {
					err = fmt.Errorf("role %s url %s", role, url)
				}
			}
			if err != nil || !bytes.Equal(got, sid) {
				return fmt.Errorf("code %s: %q: %v", c.Name, x.text, err)
			}
		}
	}
	for _, c := range e.Typed.Valid {
		sid, err := parseSessionCode(c.Text)
		if err != nil || sessionText(sid) != c.Session {
			return fmt.Errorf("typed %s: %q: want %s, err %v", c.Name, c.Text, c.Session, err)
		}
	}
	for _, c := range e.Typed.Invalid {
		if _, err := parseSessionCode(c.Text); err == nil {
			return fmt.Errorf("invalid typed %s: %q accepted", c.Name, c.Text)
		}
	}
	for _, c := range e.Payloads.Valid {
		role, url, sid, err := parsePayload(c.Text)
		if err != nil || role != c.Role || url != c.RelayURL || sessionText(sid) != c.Session {
			return fmt.Errorf("payload %s: %q: %v", c.Name, c.Text, err)
		}
	}
	for _, c := range e.Payloads.Invalid {
		if _, _, _, err := parsePayload(c.Text); err == nil {
			return fmt.Errorf("invalid payload %s: %q accepted", c.Name, c.Text)
		}
	}
	byName := map[string]transcriptJ{}
	leading := false
	for _, t := range e.Transcripts {
		tp, np := w.byName[t.Trusted], w.byName[t.New]
		if tp == nil || np == nil {
			return fmt.Errorf("transcript %s: unknown device", t.Name)
		}
		sid, err := decodeID(t.Session, "e_", 16)
		if err != nil {
			return fmt.Errorf("transcript %s: %w", t.Name, err)
		}
		if t != newTranscript(t.Name, sid, tp, np, unhex(t.TNonce), unhex(t.NNonce)) {
			return fmt.Errorf("transcript %s: a derived value differs from 11.2", t.Name)
		}
		if len(t.TNonce) != 64 || len(t.NNonce) != 64 || len(t.Code) != 6 {
			return fmt.Errorf("transcript %s: bad nonce or code length", t.Name)
		}
		leading = leading || t.Code[0] == '0'
		byName[t.Name] = t
	}
	if !leading {
		return errors.New("no transcript has a code with a leading zero")
	}
	valid, invalid := 0, 0
	for _, c := range e.Confirmations {
		t, ok := byName[c.Transcript]
		if !ok {
			return fmt.Errorf("confirmation %s: unknown transcript", c.Name)
		}
		sg := w.byName[c.Signer]
		pe, err := parseEnvelope(c.Envelope)
		if sg == nil || err != nil || string(pe.payload) != c.Payload || !ed25519.Verify(sg.signPk, pae(pe.ptype, pe.payload), pe.sig) {
			return fmt.Errorf("confirmation %s: envelope does not hold the payload signed by %s", c.Name, c.Signer)
		}
		err = acceptConfirm(c.Envelope, t)
		if (err == nil) != c.Valid {
			return fmt.Errorf("confirmation %s: valid=%v but the 11.2 check says %v", c.Name, c.Valid, err)
		}
		perr := validatePayload("snailfish.confirm.v1", []byte(c.Payload))
		switch c.Rule {
		case "":
			valid++
		case "6.3":
			if perr == nil {
				return fmt.Errorf("confirmation %s: rule 6.3 but the payload parses", c.Name)
			}
			invalid++
		case "11.2":
			if perr != nil {
				return fmt.Errorf("confirmation %s: rule 11.2 but the payload breaks 6.3: %v", c.Name, perr)
			}
			invalid++
		default:
			return fmt.Errorf("confirmation %s: rule %q", c.Name, c.Rule)
		}
		if (c.Rule == "") != c.Valid {
			return fmt.Errorf("confirmation %s: rule and valid disagree", c.Name)
		}
	}
	if valid == 0 || invalid == 0 {
		return errors.New("confirmations need valid and invalid cases")
	}
	return nil
}
