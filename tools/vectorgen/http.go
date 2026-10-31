package main

import (
	"crypto/ed25519"
	"fmt"
	"strings"
)

// This file builds vectors/http.json (vectors/README.md "Format of http.json").
// The expected value of each append and fetch case is written by hand here and
// asserted against the reference implementation of PROTOCOL.md 10.6 and 10.7
// (httpref.go), so a mistake in either one stops the generator.

const (
	httpNow       = 1767225600
	httpAuthority = "sync.example.net"
	otherAuth     = "other.example.net"
	portAuth      = "relay.example.ts.net:8443"
)

type limitsJ struct {
	MaxRequestBytes    int `json:"max_request_bytes"`
	MaxChangeBytes     int `json:"max_change_bytes"`
	MaxSnapshotBytes   int `json:"max_snapshot_bytes"`
	MaxAppendEnvelopes int `json:"max_append_envelopes"`
	MaxFetchEntries    int `json:"max_fetch_entries"`
}

type httpDeviceJ struct {
	Name     string `json:"name"`
	SignSeed string `json:"sign_seed"`
	ID       string `json:"id"`
}

type signedJ struct {
	Name            string      `json:"name"`
	Signer          string      `json:"signer"`
	Method          string      `json:"method"`
	Authority       string      `json:"authority"`
	Path            string      `json:"path"`
	Query           string      `json:"query"`
	Body            string      `json:"body"`
	Created         int64       `json:"created"`
	Expires         int64       `json:"expires"`
	Nonce           string      `json:"nonce"`
	ContentDigest   string      `json:"content_digest"`
	SignatureParams string      `json:"signature_params"`
	SignatureBase   string      `json:"signature_base"`
	Sig             string      `json:"sig"`
	Headers         [][2]string `json:"headers"`
}

type invalidJ struct {
	Name    string      `json:"name"`
	Signer  string      `json:"signer"`
	Method  string      `json:"method"`
	Path    string      `json:"path"`
	Query   string      `json:"query"`
	Body    string      `json:"body"`
	Headers [][2]string `json:"headers"`
	Error   string      `json:"error"`
}

type spaceEntryJ struct {
	Position   int    `json:"position"`
	Envelope   string `json:"envelope"`
	RecordHash string `json:"record_hash"`
	Digest     string `json:"digest"`
}

type spaceJ struct {
	Genesis       string        `json:"genesis"`
	GenesisDigest string        `json:"genesis_digest"`
	Log           []spaceEntryJ `json:"log"`
}

type resultJ struct {
	Status   string  `json:"status"`
	Position *int    `json:"position"`
	Error    *string `json:"error"`
}

type headJ struct {
	Position int    `json:"position"`
	Digest   string `json:"digest"`
}

type appendJ struct {
	Name    string    `json:"name"`
	Signer  string    `json:"signer"`
	Body    string    `json:"body"`
	Results []resultJ `json:"results"`
	Head    headJ     `json:"head"`
}

type fetchJ struct {
	Name      string `json:"name"`
	After     int    `json:"after"`
	Limit     int    `json:"limit"`
	Positions []int  `json:"positions"`
	Head      int    `json:"head"`
	HasMore   bool   `json:"has_more"`
}

type httpJ struct {
	Version    int           `json:"version"`
	Authority  string        `json:"authority"`
	Now        int64         `json:"now"`
	Limits     limitsJ       `json:"limits"`
	UsedNonces [][2]string   `json:"used_nonces"`
	Tenant     string        `json:"tenant"`
	LogID      string        `json:"log_id"`
	Devices    []httpDeviceJ `json:"devices"`
	Signed     []signedJ     `json:"signed"`
	Invalid    []invalidJ    `json:"invalid"`
	Space      spaceJ        `json:"space"`
	Append     []appendJ     `json:"append"`
	Fetch      []fetchJ      `json:"fetch"`
}

func httpLimits() limitsJ {
	return limitsJ{MaxRequestBytes: 16384, MaxChangeBytes: 512, MaxSnapshotBytes: 4096, MaxAppendEnvelopes: 8, MaxFetchEntries: 500}
}

func httpTenant() string { return "t_" + hx(testSeed("tenant", "handle")[:16]) }

// httpSealer reuses the sealed key sets of protocol.json: the http log holds
// the same recipients, epoch and log ID, so the HPKE info is the same.
// http entry 1 is genesis (protocol entry 1), 3 is the grant to B (protocol
// entry 2), 100 is a grant to C (protocol entry 8).
func httpSealer(p *protocolJ) sealer {
	m := map[int]int{1: 1, 3: 2, 100: 8}
	return func(entry, index int, pk, info, plaintext []byte) ([]byte, error) {
		pe, ok := m[entry]
		if !ok {
			return nil, fmt.Errorf("no stored key set for http entry %d", entry)
		}
		return storedSealed(p, pe, index)
	}
}

// ---- request signatures (PROTOCOL.md section 8) ----

func digestHeader(body string) string { return "sha-256=:" + b64(sha([]byte(body))) + ":" }

func paramsLine(created, expires int64, nonce, keyid string) string {
	return fmt.Sprintf(`("@method" "@authority" "@path" "@query" "content-digest");created=%d;expires=%d;nonce="%s";keyid="%s";alg="ed25519";tag="snailfish.request.v1"`,
		created, expires, nonce, keyid)
}

func sigBase(method, authority, path, query, digest, params string) string {
	return strings.Join([]string{
		`"@method": ` + method,
		`"@authority": ` + authority,
		`"@path": ` + path,
		`"@query": ?` + query,
		`"content-digest": ` + digest,
		`"@signature-params": ` + params,
	}, "\n")
}

func nonceFor(name string) string { return hx(sha(s("snailfish.http-nonce." + name)))[:32] }

func newSigned(name string, sg *party, method, authority, path, query, body string, created, expires int64, nonce string) signedJ {
	cd := digestHeader(body)
	params := paramsLine(created, expires, nonce, sg.idText)
	base := sigBase(method, authority, path, query, cd, params)
	sig := ed25519.Sign(sg.signPriv, []byte(base))
	return signedJ{
		Name: name, Signer: sg.name, Method: method, Authority: authority, Path: path, Query: query, Body: body,
		Created: created, Expires: expires, Nonce: nonce, ContentDigest: cd, SignatureParams: params, SignatureBase: base,
		Sig: hx(sig),
		Headers: [][2]string{
			{"content-digest", cd}, {"signature-input", "sf=" + params},
			{"signature", "sf=:" + b64(sig) + ":"}, {"snailfish-authority", authority},
		},
	}
}

func withHdr(h [][2]string, name, val string) [][2]string {
	out := append([][2]string{}, h...)
	for i := range out {
		if out[i][0] == name {
			out[i][1] = val
			return out
		}
	}
	panic("no header " + name)
}

func withoutHdr(h [][2]string, name string) [][2]string {
	var out [][2]string
	for _, x := range h {
		if x[0] != name {
			out = append(out, x)
		}
	}
	return out
}

func sigHdr(sig []byte) string { return "sf=:" + b64(sig) + ":" }

// ---- the space and the append and fetch cases ----

func buildHTTPLog(w *world, seal sealer) (*logBuilder, error) {
	b := &logBuilder{w: w, seal: seal, digests: map[int][]byte{}, rhs: map[int][]byte{}, sigs: map[int][]byte{}, payload: map[int][]byte{}}
	b.digests[0] = sha(frame(s("snailfish.log-root.v1"), w.logID))
	log := q(w.logIDText)
	ks, err := b.keySets(1, []int{1}, w.A, w.R1)
	if err != nil {
		return nil, err
	}
	b.add("genesis", "snailfish.genesis.v1", w.R1, obj(
		"log", log, "author", q(w.R1.idText), "base", b.baseRaw(0),
		"app", q(appName), "recovery", keysRaw(w.R1), "level", "1",
		"device", deviceRaw(w.A, "Laptop", 2), "epoch", "1",
		"commitment", q(b64(commitment(w.logID, 1, w.appKeys[1]))), "keys", ks), nil)
	ct, err := b.encrypt(2, changeAAD(w, 1, changeIDFor(2), w.A), `{"op":"rename","task":1,"title":"Buy milk"}`)
	if err != nil {
		return nil, err
	}
	b.add("change-A", "snailfish.change.v1", w.A, obj(
		"log", log, "author", q(w.A.idText), "base", b.baseRaw(1),
		"epoch", "1", "change_id", q("c_"+hx(changeIDFor(2))), "ciphertext", q(b64(ct))), changeIDFor(2))
	if ks, err = b.keySets(3, []int{1}, w.B); err != nil {
		return nil, err
	}
	b.add("grant-B", "snailfish.grant.v1", w.A, obj(
		"log", log, "author", q(w.A.idText), "base", b.baseRaw(2),
		"device", deviceRaw(w.B, "Phone", 1), "keys", ks), nil)
	if ct, err = b.encrypt(4, changeAAD(w, 1, changeIDFor(4), w.B), `{"op":"done","task":1}`); err != nil {
		return nil, err
	}
	b.add("change-B", "snailfish.change.v1", w.B, obj(
		"log", log, "author", q(w.B.idText), "base", b.baseRaw(3),
		"epoch", "1", "change_id", q("c_"+hx(changeIDFor(4))), "ciphertext", q(b64(ct))), changeIDFor(4))
	return b, nil
}

func signEnv(sg *party, ptype, payload string) (env string, sig, rh []byte) {
	pl := []byte(payload)
	sig = ed25519.Sign(sg.signPriv, pae(ptype, pl))
	return envelopeJSON(ptype, pl, sig, sg.idText), sig, recordHash(ptype, pl, sig)
}

func ptr[T any](v T) *T { return &v }

// want is a hand-written expected result: "stored:5", "known:2", "conflict:2" or "refused:bad_base".
func resultFrom(r result) string {
	if r.err != "" {
		return "refused:" + r.err
	}
	return fmt.Sprintf("%s:%d", r.status, r.pos)
}

func resultJOf(r result) resultJ {
	if r.err != "" {
		return resultJ{Status: "refused", Error: ptr(r.err)}
	}
	return resultJ{Status: r.status, Position: ptr(r.pos)}
}

func buildHTTP(w *world, seal sealer) (*httpJ, error) {
	b, err := buildHTTPLog(w, seal)
	if err != nil {
		return nil, err
	}
	h := &httpJ{
		Version: 1, Authority: httpAuthority, Now: httpNow, Limits: httpLimits(),
		UsedNonces: [][2]string{{w.A.idText, nonceFor("used-A")}, {w.B.idText, nonceFor("used-B")}},
		Tenant:     httpTenant(), LogID: w.logIDText,
	}
	for _, d := range []*party{w.A, w.B, w.C} {
		h.Devices = append(h.Devices, httpDeviceJ{d.name, hx(d.signSeed), d.idText})
	}
	var envs []string
	for _, e := range b.entries {
		h.Space.Log = append(h.Space.Log, spaceEntryJ{e.Position, e.Envelope, e.RecordHash, e.Digest})
		envs = append(envs, e.Envelope)
	}
	h.Space.Genesis = b.entries[0].Envelope
	h.Space.GenesisDigest = b.entries[0].Digest
	sp, err := newSpaceFromEnvelopes(w.logIDText, envs)
	if err != nil {
		return nil, fmt.Errorf("space log: %w", err)
	}

	spacePath := "/v1/t/" + h.Tenant + "/s/" + w.logIDText
	entriesPath := spacePath + "/entries"
	appendPath := spacePath + "/append"

	// ---- append cases ----
	logText := w.logIDText
	base4 := b.baseRaw(4)
	mkChange := func(au *party, cidN int, baseRaw string, epoch int, lg, plain string) (string, []byte, []byte, error) {
		cid := changeIDFor(cidN)
		nonce := sha(frame(s("snailfish.test-seed.v1"), s("http"), s(fmt.Sprintf("nonce-%d-%d", cidN, len(plain)))))[:24]
		ct, err := aeadSeal(w.appKeys[epoch], nonce, changeAAD(w, epoch, cid, au), []byte(plain))
		if err != nil {
			return "", nil, nil, err
		}
		env, sig, rh := signEnv(au, "snailfish.change.v1", obj(
			"log", q(lg), "author", q(au.idText), "base", baseRaw,
			"epoch", fmt.Sprint(epoch), "change_id", q("c_"+hx(cid)), "ciphertext", q(b64(ct))))
		return env, sig, rh, nil
	}
	mustChange := func(au *party, cidN int, baseRaw string, epoch int, lg, plain string) string {
		env, _, _, e := mkChange(au, cidN, baseRaw, epoch, lg, plain)
		if e != nil && err == nil {
			err = e
		}
		return env
	}
	grant := func(au, to *party, level int, entry int, baseRaw string) string {
		ks, e := b.keySets(entry, []int{1}, to)
		if e != nil && err == nil {
			err = e
		}
		env, _, _ := signEnv(au, "snailfish.grant.v1", obj(
			"log", q(logText), "author", q(au.idText), "base", baseRaw,
			"device", deviceRaw(to, to.name, level), "keys", ks))
		return env
	}
	otherLog := "l_" + hx(testSeed("log", "other")[:16])
	zeros := make([]byte, 32)
	e2, e4 := b.entries[1].Envelope, b.entries[3].Envelope
	_ = e4

	newB := mustChange(w.B, 20, base4, 1, logText, `{"op":"add","task":2}`)
	newA21, _, rh21, e := mkChange(w.A, 21, base4, 1, logText, `{"op":"add","task":3}`)
	if e != nil {
		return nil, e
	}
	d5 := digestN(b.digests[4], 5, entryHash("snailfish.change.v1", changeIDFor(21), rh21))
	badSigEnv := func() string {
		env, sig, _, _ := mkChange(w.A, 30, base4, 1, logText, `{"op":"add","task":4}`)
		bad := append([]byte{}, sig...)
		bad[0] ^= 1
		pe, _ := parseEnvelope(env)
		return envelopeJSON(pe.ptype, pe.payload, bad, w.A.idText)
	}()
	level2, _, _ := signEnv(w.A, "snailfish.level.v1", obj(
		"log", q(logText), "author", q(w.A.idText), "base", base4, "level", "2"))
	type ac struct {
		name   string
		signer *party
		envs   []string
		want   []string
		head   int
		hd     []byte
	}
	cases := []ac{
		{"new-change", w.B, []string{newB}, []string{"stored:5"}, 0, nil},
		{"exact-retry", w.A, []string{e2}, []string{"known:2"}, 0, nil},
		{"same-change-id-other-hash", w.A, []string{mustChange(w.A, 2, base4, 1, logText, `{"op":"rename","task":1,"title":"Other"}`)}, []string{"conflict:2"}, 0, nil},
		{"second-copy-in-one-request", w.B, []string{newB, newB}, []string{"stored:5", "known:5"}, 0, nil},
		{"known-before-not-author", w.B, []string{e2}, []string{"known:2"}, 0, nil},
		{"bad-base-digest", w.A, []string{mustChange(w.A, 22, posRaw(3, b.digests[2]), 1, logText, `{"op":"x"}`)}, []string{"refused:bad_base"}, 0, nil},
		{"base-at-new-position", w.A, []string{mustChange(w.A, 22, posRaw(5, zeros), 1, logText, `{"op":"x"}`)}, []string{"refused:bad_base"}, 0, nil},
		{"base-after-new-position", w.A, []string{mustChange(w.A, 22, posRaw(9, zeros), 1, logText, `{"op":"x"}`)}, []string{"refused:bad_base"}, 0, nil},
		{"author-not-request-signer", w.A, []string{mustChange(w.C, 23, base4, 1, logText, `{"op":"x"}`)}, []string{"refused:not_author"}, 0, nil},
		{"other-log-id", w.A, []string{mustChange(w.A, 24, base4, 1, otherLog, `{"op":"x"}`)}, []string{"refused:invalid_record"}, 0, nil},
		{"unsupported-type", w.A, []string{level2}, []string{"refused:unsupported"}, 0, nil},
		{"wrong-epoch", w.A, []string{mustChange(w.A, 25, base4, 2, logText, `{"op":"x"}`)}, []string{"refused:wrong_epoch"}, 0, nil},
		{"too-large-change", w.A, []string{mustChange(w.A, 26, base4, 1, logText, `{"pad":"`+strings.Repeat("x", 600)+`"}`)}, []string{"refused:too_large"}, 0, nil},
		{"grant-of-active-device", w.A, []string{grant(w.A, w.B, 1, 3, base4)}, []string{"refused:invalid_record"}, 0, nil},
		{"grant-of-new-device", w.A, []string{grant(w.A, w.C, 2, 100, base4)}, []string{"stored:5"}, 0, nil},
		{"bad-record-signature", w.A, []string{badSigEnv}, []string{"refused:invalid_record"}, 0, nil},
		{"malformed-envelope", w.A, []string{`{"payloadType":"snailfish.change.v1","payload":"AA==","signatures":[]}`}, []string{"refused:invalid_record"}, 0, nil},
		{"mixed-results", w.A, []string{
			newA21, e2,
			mustChange(w.A, 2, base4, 1, logText, `{"op":"rename","task":1,"title":"Other"}`),
			mustChange(w.A, 22, posRaw(3, b.digests[2]), 1, logText, `{"op":"x"}`),
			grant(w.A, w.B, 1, 3, base4),
			mustChange(w.A, 27, posRaw(5, d5), 1, logText, `{"op":"after-stored"}`),
		}, []string{"stored:5", "known:2", "conflict:2", "refused:bad_base", "refused:invalid_record", "stored:6"}, 0, nil},
	}
	if err != nil {
		return nil, err
	}
	for _, c := range cases {
		body := `{"envelopes":[` + strings.Join(c.envs, ",") + `]}`
		st := sp.clone()
		res, e := st.appendBatch(c.signer.idText, body, h.Limits)
		if e != nil {
			return nil, fmt.Errorf("append %s: %w", c.name, e)
		}
		var got []string
		var rj []resultJ
		for _, r := range res {
			got = append(got, resultFrom(r))
			rj = append(rj, resultJOf(r))
		}
		if strings.Join(got, " ") != strings.Join(c.want, " ") {
			return nil, fmt.Errorf("append %s: reference gives %v, expected %v", c.name, got, c.want)
		}
		n := len(st.entries)
		h.Append = append(h.Append, appendJ{c.name, c.signer.name, body, rj, headJ{n, hx(st.digestAt(n))}})
	}

	// ---- fetch cases ----
	type fc struct {
		name         string
		after, limit int
		pos          []int
		more         bool
	}
	for _, c := range []fc{
		{"after-0-limit-2", 0, 2, []int{1, 2}, true},
		{"after-0-limit-3", 0, 3, []int{1, 2, 3}, true},
		{"after-0-limit-4", 0, 4, []int{1, 2, 3, 4}, false},
		{"after-2", 2, 500, []int{3, 4}, false},
		{"after-3-limit-1", 3, 1, []int{4}, false},
		{"after-head", 4, 500, []int{}, false},
		{"after-beyond-head", 9, 10, []int{}, false},
	} {
		pos, head, more := sp.fetch(c.after, c.limit)
		if fmt.Sprint(pos) != fmt.Sprint(c.pos) || more != c.more || head != 4 {
			return nil, fmt.Errorf("fetch %s: reference gives %v head %d more %v", c.name, pos, head, more)
		}
		h.Fetch = append(h.Fetch, fetchJ{c.name, c.after, c.limit, c.pos, head, more})
	}

	// ---- signed cases ----
	now := int64(httpNow)
	std := func(name string, sg *party, method, authority, path, query, body string) signedJ {
		return newSigned(name, sg, method, authority, path, query, body, now, now+300, nonceFor(name))
	}
	// B uses the nonce that the tenant file holds for A: the pair is what counts.
	postB := newSigned("post-append", w.B, "POST", httpAuthority, appendPath, "", `{"envelopes":[`+newB+`]}`, now, now+300, nonceFor("used-A"))
	h.Signed = []signedJ{
		std("fetch-get", w.A, "GET", httpAuthority, entriesPath, "after=0&limit=500", ""),
		postB,
		std("put-create", w.A, "PUT", httpAuthority, spacePath, "", `{"genesis":`+h.Space.Genesis+`}`),
		std("fetch-query-several-params", w.A, "GET", httpAuthority, entriesPath, "after=2&limit=2&a=b%20c&d=%2F&e=", ""),
		std("fetch-port-authority", w.A, "GET", portAuth, entriesPath, "after=0&limit=500", ""),
	}

	// ---- invalid cases ----
	mk := func(name string) signedJ {
		return newSigned(name, w.A, "GET", httpAuthority, entriesPath, "after=0&limit=2", "", now, now+300, nonceFor(name))
	}
	var inv []invalidJ
	add := func(s signedJ, hdr [][2]string, code string) {
		inv = append(inv, invalidJ{s.Name, s.Signer, s.Method, s.Path, s.Query, s.Body, hdr, code})
	}
	// resign signs a custom parameter line and swaps it into a base case.
	resign := func(s signedJ, sg *party, params string) [][2]string {
		sig := ed25519.Sign(sg.signPriv, []byte(sigBase(s.Method, s.Authority, s.Path, s.Query, s.ContentDigest, params)))
		return withHdr(withHdr(s.Headers, "signature-input", "sf="+params), "signature", sigHdr(sig))
	}
	sub := func(name, from, to string) (signedJ, [][2]string) {
		s := mk(name)
		if !strings.Contains(s.SignatureParams, from) {
			panic("no " + from)
		}
		return s, resign(s, w.A, strings.Replace(s.SignatureParams, from, to, 1))
	}
	{
		s := mk("missing-signature-header")
		add(s, withoutHdr(s.Headers, "signature"), "bad_signature")
		s = mk("missing-content-digest-header")
		add(s, withoutHdr(s.Headers, "content-digest"), "bad_signature")
		s = mk("duplicate-signature-input-header")
		add(s, append(append([][2]string{}, s.Headers...), [2]string{"signature-input", s.Headers[1][1]}), "bad_signature")
		s = mk("wrong-label")
		add(s, withHdr(withHdr(s.Headers, "signature-input", "sig="+s.SignatureParams), "signature", "sig="+s.Headers[2][1][3:]), "bad_signature")
		s = mk("params-other-order")
		other := fmt.Sprintf(`("@method" "@authority" "@path" "@query" "content-digest");expires=%d;created=%d;nonce="%s";keyid="%s";alg="ed25519";tag="snailfish.request.v1"`,
			s.Expires, s.Created, s.Nonce, w.A.idText)
		add(s, resign(s, w.A, other), "bad_signature")
		s = mk("extra-component")
		ext := strings.Replace(s.SignatureParams, `"content-digest")`, `"content-digest" "@scheme")`, 1)
		lines := strings.Split(s.SignatureBase, "\n")
		lines = append(lines[:5], `"@scheme": https`, `"@signature-params": `+ext)
		sig := ed25519.Sign(w.A.signPriv, []byte(strings.Join(lines, "\n")))
		add(s, withHdr(withHdr(s.Headers, "signature-input", "sf="+ext), "signature", sigHdr(sig)), "bad_signature")
		s, hd := sub("wrong-tag", `tag="snailfish.request.v1"`, `tag="snailfish.other.v1"`)
		add(s, hd, "bad_signature")
		s, hd = sub("wrong-alg", `alg="ed25519"`, `alg="ecdsa-p256-sha256"`)
		add(s, hd, "bad_signature")
		s = newSigned("expires-after-created-plus-300", w.A, "GET", httpAuthority, entriesPath, "after=0&limit=2", "", now, now+301, nonceFor("expires-301"))
		add(s, s.Headers, "bad_signature")
		s = newSigned("expired", w.A, "GET", httpAuthority, entriesPath, "after=0&limit=2", "", now-400, now-100, nonceFor("expired"))
		add(s, s.Headers, "expired")
		s = newSigned("created-too-far-in-future", w.A, "GET", httpAuthority, entriesPath, "after=0&limit=2", "", now+61, now+361, nonceFor("future"))
		add(s, s.Headers, "expired")
		// The signature covers the wrong digest header, so only step 4 fails.
		s = newSigned("bad-digest", w.A, "POST", httpAuthority, appendPath, "", `{"envelopes":[]}`, now, now+300, nonceFor("bad-digest"))
		wrong := newSigned("x", w.A, "POST", httpAuthority, appendPath, "", `{"envelopes":[1]}`, now, now+300, nonceFor("bad-digest"))
		add(s, wrong.Headers, "bad_digest")
		s = newSigned("unknown-device", w.C, "GET", httpAuthority, entriesPath, "after=0&limit=2", "", now, now+300, nonceFor("unknown-device"))
		add(s, s.Headers, "unknown_device")
		s = mk("bad-signature")
		sg, _ := decodeB64(s.Headers[2][1][4 : len(s.Headers[2][1])-1])
		sg[17] ^= 0x04
		add(s, withHdr(s.Headers, "signature", sigHdr(sg)), "bad_signature")
		s = newSigned("nonce-reused", w.A, "GET", httpAuthority, entriesPath, "after=0&limit=2", "", now, now+300, nonceFor("used-A"))
		add(s, s.Headers, "nonce_reused")
		s = mk("wrong-authority")
		add(s, withHdr(s.Headers, "snailfish-authority", otherAuth), "wrong_authority")
		s = newSigned("signed-for-other-authority", w.A, "GET", otherAuth, entriesPath, "after=0&limit=2", "", now, now+300, nonceFor("other-auth"))
		add(s, withHdr(s.Headers, "snailfish-authority", httpAuthority), "bad_signature")
		// Search for a signature whose standard base64 holds + or /.
		for i := 0; ; i++ {
			if i > 200 {
				return nil, fmt.Errorf("no signature with + or /")
			}
			s = newSigned("signature-url-safe-base64", w.A, "GET", httpAuthority, entriesPath, "after=0&limit=2", "", now, now+300, nonceFor(fmt.Sprintf("urlsafe-%d", i)))
			v := s.Headers[2][1]
			if strings.ContainsAny(v, "+/") {
				add(s, withHdr(s.Headers, "signature", strings.NewReplacer("+", "-", "/", "_").Replace(v)), "bad_signature")
				break
			}
		}
	}
	h.Invalid = inv

	// the reference relay must accept every signed case and give each invalid case its code
	if err := checkHTTP(h, w); err != nil {
		return nil, fmt.Errorf("self-check: %w", err)
	}
	return h, nil
}
