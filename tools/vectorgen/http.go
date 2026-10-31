package main

import (
	"crypto/ed25519"
	"fmt"
	"strings"
)

// This file builds vectors/http.json (vectors/README.md "Format of http.json").
// The expected value of each append, fetch, status and repair case is written
// by hand here and asserted against the reference implementation of PROTOCOL.md
// 10.6 to 10.9 (httpref.go), so a mistake in either one stops the generator.

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
	Hold      bool   `json:"hold"`
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
	AppendHold []appendJ     `json:"append_hold"`
	Fetch      []fetchJ      `json:"fetch"`
	Status     []statusJ     `json:"status"`
	Repair     []repairJ     `json:"repair"`
}

type statusRespJ struct {
	Hold bool `json:"hold"`
}

type statusJ struct {
	Name     string       `json:"name"`
	Signer   string       `json:"signer"`
	Hold     bool         `json:"hold"`
	Body     string       `json:"body"`
	Response *statusRespJ `json:"response"`
	Error    *string      `json:"error"`
	TipInLog *bool        `json:"tip_in_log"`
}

type repairStepJ struct {
	Route  string  `json:"route"`
	Signer string  `json:"signer"`
	At     int64   `json:"at"`
	Body   string  `json:"body"`
	Status int     `json:"status"`
	Next   *int    `json:"next"`
	Head   *headJ  `json:"head"`
	Error  *string `json:"error"`
}

type repairJ struct {
	Name      string        `json:"name"`
	LogPrefix int           `json:"log_prefix"`
	Hold      bool          `json:"hold"`
	Steps     []repairStepJ `json:"steps"`
	Log       []string      `json:"log"`
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
		// [LOG-7]: the last security record is the grant to B at position 3.
		{"grant-stale-base", w.A, []string{grant(w.A, w.C, 2, 100, b.baseRaw(2))}, []string{"refused:stale_base"}, 0, nil},
		{"grant-base-before-change", w.A, []string{grant(w.A, w.C, 2, 100, b.baseRaw(3))}, []string{"stored:5"}, 0, nil},
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
	runAppend := func(cases []ac, hold bool) ([]appendJ, error) {
		var out []appendJ
		for _, c := range cases {
			body := `{"envelopes":[` + strings.Join(c.envs, ",") + `]}`
			st := sp.clone()
			st.hold = hold
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
			out = append(out, appendJ{c.name, c.signer.name, body, rj, headJ{n, hx(st.digestAt(n))}})
		}
		return out, nil
	}
	if h.Append, err = runAppend(cases, false); err != nil {
		return nil, err
	}

	// ---- append cases during a restore hold ([LOG-14]) ----
	holdCases := []ac{
		{"change-on-hold", w.B, []string{newB}, []string{"refused:on_hold"}, 0, nil},
		{"exact-retry-on-hold", w.A, []string{e2}, []string{"known:2"}, 0, nil},
		{"grant-on-hold", w.A, []string{grant(w.A, w.C, 2, 100, base4)}, []string{"stored:5"}, 0, nil},
		{"grant-stale-base-on-hold", w.A, []string{grant(w.A, w.C, 2, 100, b.baseRaw(2))}, []string{"refused:stale_base"}, 0, nil},
	}
	if err != nil {
		return nil, err
	}
	if h.AppendHold, err = runAppend(holdCases, true); err != nil {
		return nil, err
	}

	// ---- fetch cases ----
	type fc struct {
		name         string
		after, limit int
		hold         bool
		pos          []int
		more         bool
	}
	for _, c := range []fc{
		{"after-0-limit-2", 0, 2, false, []int{1, 2}, true},
		{"after-0-limit-3", 0, 3, false, []int{1, 2, 3}, true},
		{"after-0-limit-4", 0, 4, false, []int{1, 2, 3, 4}, false},
		{"after-2", 2, 500, false, []int{3, 4}, false},
		{"after-3-limit-1", 3, 1, false, []int{4}, false},
		{"after-head", 4, 500, false, []int{}, false},
		{"after-beyond-head", 9, 10, false, []int{}, false},
		{"hold-after-0-limit-2", 0, 2, true, []int{1, 2}, true},
		{"hold-after-head", 4, 500, true, []int{}, false},
	} {
		st := sp.clone()
		st.hold = c.hold
		pos, head, more, hold := st.fetch(c.after, c.limit)
		if fmt.Sprint(pos) != fmt.Sprint(c.pos) || more != c.more || head != 4 || hold != c.hold {
			return nil, fmt.Errorf("fetch %s: reference gives %v head %d more %v hold %v", c.name, pos, head, more, hold)
		}
		h.Fetch = append(h.Fetch, fetchJ{c.name, c.after, c.limit, hold, c.pos, head, more})
	}

	keys := map[string]*party{}
	for _, d := range []*party{w.A, w.B, w.C} {
		keys[d.name] = d
	}

	// ---- status reports (10.8) ----
	tip := func(n int, d []byte, fresh bool) string {
		return `{"tip":` + posRaw(n, d) + `,"fresh":` + fmt.Sprint(fresh) + `}`
	}
	type sc struct {
		name   string
		signer *party
		hold   bool
		body   string
		want   string // "hold:<bool> reported:<bool|null>" or "error:<code>"
	}
	for _, c := range []sc{
		{"hold-tip-in-log", w.A, true, tip(2, b.digests[2], false), "hold:true reported:true"},
		{"hold-tip-at-head-fresh", w.B, true, tip(4, b.digests[4], true), "hold:true reported:true"},
		{"hold-tip-after-head", w.A, true, tip(6, zeros, false), "hold:true reported:false"},
		{"hold-tip-other-digest", w.A, true, tip(3, b.digests[2], false), "hold:true reported:false"},
		{"no-hold", w.A, false, tip(4, b.digests[4], false), "hold:false reported:null"},
		{"malformed-missing-fresh", w.A, true, `{"tip":` + posRaw(2, b.digests[2]) + `}`, "error:bad_request"},
		{"malformed-fresh-not-boolean", w.A, true, `{"tip":` + posRaw(2, b.digests[2]) + `,"fresh":1}`, "error:bad_request"},
		{"malformed-negative-position", w.A, true, tip(-1, b.digests[2], false), "error:bad_request"},
		{"malformed-short-digest", w.A, true, tip(2, b.digests[2][:31], false), "error:bad_request"},
		{"malformed-unknown-field", w.A, true, `{"tip":` + posRaw(2, b.digests[2]) + `,"fresh":false,"x":1}`, "error:bad_request"},
		{"malformed-not-json", w.A, true, `{"tip":`, "error:bad_request"},
	} {
		got := replayStatus(sp, statusJ{Name: c.name, Signer: c.signer.name, Hold: c.hold, Body: c.body}, c.signer.idText, h.Now)
		if g := statusWant(got); g != c.want {
			return nil, fmt.Errorf("status %s: reference gives %q, expected %q", c.name, g, c.want)
		}
		h.Status = append(h.Status, got)
	}

	// ---- repair sessions (10.9) ----
	if err := buildRepair(h, b, w, envs, keys); err != nil {
		return nil, err
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
		// The last digest symbol has non-zero trailing bits. The signature
		// covers this value, so a reader that skips the strict decode
		// reaches step 4 and answers bad_digest.
		s = mk("content-digest-non-canonical-base64")
		const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
		cd := []byte(s.ContentDigest)
		i := len(cd) - len("=:") - 1
		cd[i] = alpha[strings.IndexByte(alpha, cd[i])^1]
		sig = ed25519.Sign(w.A.signPriv, []byte(sigBase(s.Method, s.Authority, s.Path, s.Query, string(cd), s.SignatureParams)))
		add(s, withHdr(withHdr(s.Headers, "content-digest", string(cd)), "signature", sigHdr(sig)), "bad_signature")
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

// buildRepair writes the repair cases of http.json. Each case starts from the
// first log_prefix entries of space.log, and the device uploads the others.
func buildRepair(h *httpJ, b *logBuilder, w *world, envs []string, keys map[string]*party) error {
	const day = sessionTTL
	now := int64(httpNow)
	d := b.digests
	A, B, C := w.A, w.B, w.C
	at := func(n int, env string) string { return fmt.Sprintf(`{"position":%d,"envelope":%s}`, n, env) }
	ent := func(n int) string { return at(n, b.entries[n-1].Envelope) }
	start := func(baseN int, baseD []byte, es ...string) string {
		return `{"base":` + posRaw(baseN, baseD) + `,"entries":[` + strings.Join(es, ",") + `]}`
	}
	chunk := func(es ...string) string {
		return `{"session":"{{session}}","entries":[` + strings.Join(es, ",") + `]}`
	}
	finish := func(n int, dg []byte) string { return `{"session":"{{session}}","tip":` + posRaw(n, dg) + `}` }
	badSig := append([]byte{}, b.sigs[3]...)
	badSig[0] ^= 1
	badGrant := envelopeJSON("snailfish.grant.v1", b.payload[3], badSig, A.idText)
	stubChange := fmt.Sprintf(`{"position":2,"stub":{"type":"snailfish.change.v1","change_id":"c_%s","hash":"%s"}}`, hx(changeIDFor(2)), b64(b.rhs[2]))
	stubGrant := fmt.Sprintf(`{"position":3,"stub":{"type":"snailfish.grant.v1","hash":"%s"}}`, b64(b.rhs[3]))
	const fixedSession = "00112233445566778899aabbccddeeff"
	// padded fills a body with trailing JSON white space up to n bytes.
	padded := func(body string, n int) string { return body + strings.Repeat(" ", n-len(body)) }
	maxRepair := h.Limits.MaxRequestBytes + repairAllowance

	type st struct {
		route  string
		signer *party
		at     int64
		body   string
		want   string // "<status> next <n>", "<status> head <n>" or "<status> <code>"
	}
	type rc struct {
		name   string
		prefix int
		hold   bool
		steps  []st
		logLen int
	}
	oneStart := []st{
		{"start", A, now, start(2, d[2], ent(3), ent(4)), "201 next 5"},
		{"finish", A, now, finish(4, d[4]), "200 head 4"},
	}
	cases := []rc{
		{"one-start", 2, false, oneStart, 4},
		{"start-and-chunks", 1, false, []st{
			{"start", A, now, start(1, d[1], ent(2)), "201 next 3"},
			{"chunk", A, now + 10, chunk(ent(3)), "200 next 4"},
			{"chunk", A, now + 20, chunk(ent(4)), "200 next 5"},
			{"finish", A, now + 30, finish(4, d[4]), "200 head 4"},
		}, 4},
		{"during-hold", 2, true, oneStart, 4},
		// [LOG-12]: the grant to B is position 3, which the relay lost.
		{"signer-granted-in-entries", 2, false, []st{
			{"start", B, now, start(2, d[2], ent(3), ent(4)), "201 next 5"},
			{"finish", B, now, finish(4, d[4]), "200 head 4"},
		}, 4},
		{"signer-active-nowhere", 1, false, []st{
			{"start", C, now, start(1, d[1], ent(2), ent(3)), "403 unknown_device"},
		}, 1},
		{"wrong-base-position", 2, false, []st{
			{"start", A, now, start(1, d[1], ent(3), ent(4)), "409 bad_repair"},
		}, 2},
		{"wrong-base-digest", 2, false, []st{
			{"start", A, now, start(2, d[1], ent(3), ent(4)), "409 bad_repair"},
		}, 2},
		// With a wrong base no entry passes the chain check, so B is not active (step 4 before step 5).
		{"wrong-base-signer-granted-in-entries", 2, false, []st{
			{"start", B, now, start(1, d[1], ent(3), ent(4)), "403 unknown_device"},
		}, 2},
		{"gap-in-positions", 1, false, []st{
			{"start", A, now, start(1, d[1], ent(2), ent(4)), "409 bad_repair"},
			{"start", A, now, start(1, d[1], ent(3)), "409 bad_repair"},
		}, 1},
		{"entry-bad-signature", 1, false, []st{
			{"start", A, now, start(1, d[1], ent(2), at(3, badGrant)), "422 invalid_record"},
		}, 1},
		{"known-change-id-in-entries", 2, false, []st{
			{"start", A, now, start(2, d[2], ent(3), ent(4), at(5, b.entries[3].Envelope)), "422 invalid_record"},
		}, 2},
		{"stub", 1, false, []st{
			{"start", A, now, start(1, d[1], stubChange), "422 uncovered_stub"},
			{"start", A, now, start(1, d[1], ent(2), stubGrant), "422 uncovered_stub"},
		}, 1},
		{"wrong-tip", 1, false, []st{
			{"start", A, now, start(1, d[1], ent(2), ent(3), ent(4)), "201 next 5"},
			{"finish", A, now + 10, finish(4, d[3]), "409 bad_repair"},
			{"finish", A, now + 20, finish(3, d[3]), "409 bad_repair"},
			{"finish", A, now + 30, finish(4, d[4]), "200 head 4"},
		}, 4},
		{"second-device-busy", 1, false, []st{
			{"start", A, now, start(1, d[1], ent(2)), "201 next 3"},
			{"start", B, now + 10, start(1, d[1], ent(2), ent(3)), "409 repair_busy"},
			{"chunk", A, now + 20, chunk(ent(3), ent(4)), "200 next 5"},
			{"finish", A, now + 30, finish(4, d[4]), "200 head 4"},
		}, 4},
		{"restart-same-device", 1, false, []st{
			{"start", A, now, start(1, d[1], ent(2)), "201 next 3"},
			{"start", A, now + 10, start(1, d[1], ent(2), ent(3)), "201 next 4"},
			{"chunk", A, now + 20, chunk(ent(4)), "200 next 5"},
			{"finish", A, now + 30, finish(4, d[4]), "200 head 4"},
		}, 4},
		// B is active only through the staged grant in its chunk and finish ([LOG-12]).
		{"session-after-expiry", 1, false, []st{
			{"start", A, now, start(1, d[1], ent(2)), "201 next 3"},
			{"chunk", A, now + day + 1, chunk(ent(3)), "409 bad_repair"},
			{"start", B, now + day + 2, start(1, d[1], ent(2), ent(3)), "201 next 4"},
			{"chunk", B, now + day + 3, chunk(ent(4)), "200 next 5"},
			{"finish", B, now + day + 4, finish(4, d[4]), "200 head 4"},
		}, 4},
		{"finish-after-expiry", 1, false, []st{
			{"start", A, now, start(1, d[1], ent(2), ent(3), ent(4)), "201 next 5"},
			{"finish", A, now + day + 1, finish(4, d[4]), "409 bad_repair"},
		}, 1},
		{"chunk-extends-session", 1, false, []st{
			{"start", A, now, start(1, d[1], ent(2)), "201 next 3"},
			{"chunk", A, now + day - 1, chunk(ent(3)), "200 next 4"},
			{"chunk", A, now + 2*day - 2, chunk(ent(4)), "200 next 5"},
			{"finish", A, now + 2*day - 2, finish(4, d[4]), "200 head 4"},
		}, 4},
		{"chunk-from-other-device", 1, false, []st{
			{"start", A, now, start(1, d[1], ent(2)), "201 next 3"},
			{"chunk", B, now + 10, chunk(ent(3)), "409 bad_repair"},
			{"chunk", A, now + 20, chunk(ent(3)), "200 next 4"},
			{"finish", A, now + 30, finish(3, d[3]), "200 head 3"},
		}, 3},
		{"unknown-session", 1, false, []st{
			{"chunk", A, now, `{"session":"` + fixedSession + `","entries":[` + ent(2) + `]}`, "409 bad_repair"},
			{"finish", A, now, `{"session":"` + fixedSession + `","tip":` + posRaw(1, d[1]) + `}`, "409 bad_repair"},
		}, 1},
		{"body-at-allowance", 1, false, []st{
			{"start", A, now, padded(start(1, d[1], ent(2)), maxRepair), "201 next 3"},
		}, 1},
		{"body-over-allowance", 1, false, []st{
			{"start", A, now, padded(start(1, d[1], ent(2)), maxRepair+1), "413 too_large"},
		}, 1},
		{"malformed-start", 1, false, []st{
			{"start", A, now, start(1, d[1]), "400 bad_request"},
		}, 1},
	}
	for _, c := range cases {
		in := repairJ{Name: c.name, LogPrefix: c.prefix, Hold: c.hold}
		for _, s := range c.steps {
			in.Steps = append(in.Steps, repairStepJ{Route: s.route, Signer: s.signer.name, At: s.at, Body: s.body})
		}
		got, err := replayRepair(envs, h.LogID, in, keys, h.Limits, "")
		if err != nil {
			return fmt.Errorf("repair %s: %w", c.name, err)
		}
		for i, s := range got.Steps {
			if g := stepWant(s); g != c.steps[i].want {
				return fmt.Errorf("repair %s step %d: reference gives %q, expected %q", c.name, i+1, g, c.steps[i].want)
			}
		}
		if len(got.Log) != c.logLen {
			return fmt.Errorf("repair %s: reference log has %d entries, expected %d", c.name, len(got.Log), c.logLen)
		}
		h.Repair = append(h.Repair, got)
	}
	return nil
}
