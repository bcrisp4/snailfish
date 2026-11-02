package main

// M7 vectors: removal, recovery records, levels (PROTOCOL.md 10.2, 10.6 steps
// 11 to 15, 8.6 steps 5 to 7, section 13).

import (
	"crypto/ed25519"
	"fmt"
	"strings"
)

// appendCase is one append request of http.json: the signer, the envelopes
// and the expected result of each.
type appendCase struct {
	name   string
	signer *party
	envs   []string
	want   []string
	head   int
	hd     []byte
}

type changeFn func(au *party, cidN int, baseRaw string, epoch int, lg, plain string) string

// m7Builder signs the M7 records on the 4-entry log of http.json.
type m7Builder struct {
	b      *logBuilder
	w      *world
	log    string
	base4  string
	change changeFn
	err    error
	entry  int // a key set entry number for the sealer, outside the log
}

func (m *m7Builder) keys(epochs []int, to ...*party) string {
	m.entry++
	ks, err := m.b.keySets(200+m.entry, epochs, to...)
	if err != nil && m.err == nil {
		m.err = err
	}
	return ks
}

func ids(ps ...*party) string {
	var out []string
	for _, p := range sortParties(ps) {
		out = append(out, q(p.idText))
	}
	return list(out...)
}

// epoch signs an epoch record. rec is the recovery ID of the recovery key set.
func (m *m7Builder) epoch(au *party, base string, e int, removed, stay []*party, rec *party) (string, []byte) {
	to := append(append([]*party{}, stay...), rec)
	removedList := "[]"
	if len(removed) > 0 {
		removedList = ids(removed...)
	}
	env, _, rh := signEnv(au, "snailfish.epoch.v1", obj(
		"log", q(m.log), "author", q(au.idText), "base", base,
		"epoch", fmt.Sprint(e), "removed", removedList, "stay", ids(stay...),
		"commitment", q(b64(commitment(m.w.logID, e, m.w.appKeys[2]))), "keys", m.keys([]int{e}, to...)))
	return env, rh
}

func (m *m7Builder) grant(au, to *party, level int, base string, epochs []int) string {
	env, _, _ := signEnv(au, "snailfish.grant.v1", obj(
		"log", q(m.log), "author", q(au.idText), "base", base,
		"device", deviceRaw(to, to.name, level), "keys", m.keys(epochs, to)))
	return env
}

// recovery signs a recovery record by au that names the keys of nu.
func (m *m7Builder) recovery(au, nu *party, base string, epochs []int) (string, []byte) {
	proof := ed25519.Sign(nu.signPriv, frame(s("snailfish.recovery-proof.v1"), m.w.logID, nu.signPk, nu.sealPk))
	env, _, rh := signEnv(au, "snailfish.recovery.v1", obj(
		"log", q(m.log), "author", q(au.idText), "base", base,
		"recovery", keysRaw(nu), "proof", q(b64(proof)), "keys", m.keys(epochs, nu)))
	return env, rh
}

func (m *m7Builder) level(ptype string, au *party, base string, level int) string {
	env, _, _ := signEnv(au, ptype, obj("log", q(m.log), "author", q(au.idText), "base", base, "level", fmt.Sprint(level)))
	return env
}

// after is the base of a record at position 6, after a record with type ptype
// and record hash rh at position 5.
func (m *m7Builder) after(ptype string, rh []byte) string {
	return posRaw(5, digestN(m.b.digests[4], 5, entryHash(ptype, nil, rh)))
}

func m7AppendCases(b *logBuilder, w *world, logText, base4 string, change changeFn) ([]appendCase, error) {
	m := &m7Builder{b: b, w: w, log: logText, base4: base4, change: change}
	A, B, C, R1, R2 := w.A, w.B, w.C, w.R1, w.R2
	// The epoch skip case needs a key for epoch 3. protocol.json has keys
	// for epochs 1 and 2 only, so the key exists only here.
	w.appKeys[3] = testSeed("log", "app-key-3")
	defer delete(w.appKeys, 3)
	removeB, removeBrh := m.epoch(A, base4, 2, []*party{B}, []*party{A}, R1)
	recRemoveB, _ := m.epoch(R1, base4, 2, []*party{B}, []*party{A}, R1)
	rotate, rotateRh := m.epoch(A, base4, 2, nil, []*party{A, B}, R1)
	recToR2, recToR2rh := m.recovery(R1, R2, base4, []int{1})
	after5 := m.after("snailfish.epoch.v1", removeBrh)
	afterRot := m.after("snailfish.epoch.v1", rotateRh)
	afterRec := m.after("snailfish.recovery.v1", recToR2rh)
	cases := []appendCase{
		// 10.6 step 13, epoch records ([LOG-8], T8).
		{"epoch-removes-device", A, []string{removeB}, []string{"stored:5"}, 0, nil},
		{"epoch-wrong-recovery", A, []string{func() string { e, _ := m.epoch(A, base4, 2, []*party{B}, []*party{A}, R2); return e }()}, []string{"refused:invalid_record"}, 0, nil},
		{"epoch-skips-epoch", A, []string{func() string { e, _ := m.epoch(A, base4, 3, []*party{B}, []*party{A}, R1); return e }()}, []string{"refused:invalid_record"}, 0, nil},
		{"epoch-removes-author", A, []string{func() string { e, _ := m.epoch(A, base4, 2, []*party{A}, []*party{B}, R1); return e }()}, []string{"refused:invalid_record"}, 0, nil},
		{"epoch-stay-not-active-devices", A, []string{func() string { e, _ := m.epoch(A, base4, 2, nil, []*party{A}, R1); return e }()}, []string{"refused:invalid_record"}, 0, nil},
		{"epoch-removes-inactive-device", A, []string{func() string { e, _ := m.epoch(A, base4, 2, []*party{C}, []*party{A, B}, R1); return e }()}, []string{"refused:invalid_record"}, 0, nil},
		// 10.6 step 7: a removed author is not active.
		{"removed-author-after-epoch", B, []string{recRemoveB, change(B, 40, base4, 1, logText, `{"op":"x"}`)}, []string{"stored:5", "refused:not_active"}, 0, nil},
		// 10.6 step 12 and [DLV-7]: after a rotation, a change needs epoch 2.
		{"change-old-epoch-after-rotation", A, []string{rotate,
			change(A, 41, base4, 1, logText, `{"op":"old"}`),
			change(A, 42, base4, 2, logText, `{"op":"new"}`)}, []string{"stored:5", "refused:wrong_epoch", "stored:6"}, 0, nil},
		// 10.6 step 13, grants after a rotation and after a removal.
		{"grant-after-rotation-misses-an-epoch", A, []string{rotate, m.grant(A, C, 1, afterRot, []int{1})}, []string{"stored:5", "refused:invalid_record"}, 0, nil},
		{"grant-after-rotation-holds-each-epoch", A, []string{rotate, m.grant(A, C, 1, afterRot, []int{1, 2})}, []string{"stored:5", "stored:6"}, 0, nil},
		{"grant-of-removed-device", A, []string{removeB, m.grant(A, B, 1, after5, []int{1, 2})}, []string{"stored:5", "refused:invalid_record"}, 0, nil},
		// 10.6 steps 7 and 13, recovery records (T9).
		{"recovery-record", B, []string{recToR2}, []string{"stored:5"}, 0, nil},
		{"recovery-record-same-key", B, []string{func() string { e, _ := m.recovery(R1, R1, base4, []int{1}); return e }()}, []string{"refused:invalid_record"}, 0, nil},
		{"recovery-record-not-current", B, []string{func() string { e, _ := m.recovery(R2, R1, base4, []int{1}); return e }()}, []string{"refused:not_active"}, 0, nil},
		{"recovery-then-old-key", B, []string{recToR2, m.grant(R1, C, 1, afterRec, []int{1})}, []string{"stored:5", "refused:not_active"}, 0, nil},
		{"recovery-then-new-key", B, []string{recToR2, m.grant(R2, C, 1, afterRec, []int{1})}, []string{"stored:5", "stored:6"}, 0, nil},
		// 10.6 steps 11 and 13, levels ([VER-7] to [VER-9]).
		{"device-record-same-level", B, []string{m.level("snailfish.device.v1", B, base4, 1)}, []string{"refused:invalid_record"}, 0, nil},
		{"device-record-above-relay-level", B, []string{m.level("snailfish.device.v1", B, base4, 2)}, []string{"refused:unsupported"}, 0, nil},
		{"level-record-same-level", A, []string{m.level("snailfish.level.v1", A, base4, 1)}, []string{"refused:invalid_record"}, 0, nil},
	}
	return cases, m.err
}

// ---- 8.6 steps 5 to 7 (access) ----

type accessJ struct {
	Name    string      `json:"name"`
	Signer  string      `json:"signer"`
	Extra   []string    `json:"extra"`
	Blocked []string    `json:"blocked"`
	Method  string      `json:"method"`
	Path    string      `json:"path"`
	Query   string      `json:"query"`
	Body    string      `json:"body"`
	Headers [][2]string `json:"headers"`
	Error   string      `json:"error"`
}

// replayAccess applies the extra records of c to a copy of sp, then runs the
// request checks with the blocked devices of c.
func replayAccess(rs relayState, c accessJ) (string, error) {
	st := rs.space.clone()
	for _, env := range c.Extra {
		r, err := parseRecord(env)
		if err != nil {
			return "", err
		}
		if code := st.checkRules(r, ""); code != "" {
			return "", fmt.Errorf("extra record refused: %s", code)
		}
		st.push(r)
	}
	rs.space = st
	rs.blocked = map[string]bool{}
	for _, id := range c.Blocked {
		rs.blocked[id] = true
	}
	return rs.verifyRequest(request{c.Method, c.Path, c.Query, c.Body, c.Headers}), nil
}

func buildAccess(h *httpJ, b *logBuilder, w *world, rs relayState, entriesPath, appendPath, statusPath string) error {
	m := &m7Builder{b: b, w: w, log: w.logIDText, base4: b.baseRaw(4)}
	A, B, C, R1, R2 := w.A, w.B, w.C, w.R1, w.R2
	removeB, _ := m.epoch(A, m.base4, 2, []*party{B}, []*party{A}, R1)
	recToR2, _ := m.recovery(R1, R2, m.base4, []int{1})
	if m.err != nil {
		return m.err
	}
	now := int64(httpNow)
	get := func(name string, sg *party) signedJ {
		return newSigned(name, sg, "GET", httpAuthority, entriesPath, "after=0&limit=2", "", now, now+300, nonceFor("access-"+name))
	}
	post := func(name string, sg *party, path, body string) signedJ {
		return newSigned(name, sg, "POST", httpAuthority, path, "", body, now, now+300, nonceFor("access-"+name))
	}
	type c struct {
		s       signedJ
		extra   []string
		blocked []*party
		want    string
	}
	cases := []c{
		{get("active-device", A), nil, nil, ""},
		{get("blocked-device", B), nil, []*party{B}, "blocked"},
		{get("other-device-blocked", A), nil, []*party{B}, ""},
		{get("blocked-before-removed", B), []string{removeB}, []*party{B}, "blocked"},
		{get("removed-device", B), []string{removeB}, nil, "removed"},
		{get("unknown-device", C), nil, nil, "unknown_device"},
		{get("recovery-id-fetch", R1), nil, nil, ""},
		// An exact retry of position 2, so the relay answers 200 and stores nothing.
		{post("recovery-id-append", R1, appendPath, `{"envelopes":[`+b.entries[1].Envelope+`]}`), nil, nil, ""},
		{post("recovery-id-status", R1, statusPath, `{"tip":`+m.base4+`,"fresh":false}`), nil, nil, "unknown_device"},
		{get("recovery-id-not-current", R2), nil, nil, "unknown_device"},
		{get("retired-recovery-id", R1), []string{recToR2}, nil, "unknown_device"},
		{get("new-recovery-id", R2), []string{recToR2}, nil, ""},
	}
	for _, x := range cases {
		var bl []string
		for _, p := range x.blocked {
			bl = append(bl, p.idText)
		}
		if bl == nil {
			bl = []string{}
		}
		extra := x.extra
		if extra == nil {
			extra = []string{}
		}
		a := accessJ{x.s.Name, x.s.Signer, extra, bl, x.s.Method, x.s.Path, x.s.Query, x.s.Body, x.s.Headers, x.want}
		got, err := replayAccess(rs, a)
		if err != nil {
			return fmt.Errorf("access %s: %w", a.Name, err)
		}
		if got != x.want {
			return fmt.Errorf("access %s: reference gives %q, expected %q", a.Name, got, x.want)
		}
		h.Access = append(h.Access, a)
	}
	return nil
}

// ---- 10.6 steps 14 and 15 (reserve) ----

type reserveJ struct {
	Name     string    `json:"name"`
	Signer   string    `json:"signer"`
	Reserve  int64     `json:"reserve"`
	SecCount int       `json:"security_today"`
	Body     string    `json:"body"`
	Results  []resultJ `json:"results"`
	Head     headJ     `json:"head"`
}

func replayReserve(sp *space, c reserveJ, keyid string, lim limitsJ) (reserveJ, error) {
	st := sp.clone()
	st.reserve = c.Reserve
	st.secCount[keyid] = c.SecCount
	res, err := st.appendBatch(keyid, c.Body, lim)
	if err != nil {
		return c, err
	}
	c.Results = nil
	for _, r := range res {
		c.Results = append(c.Results, resultJOf(r))
	}
	n := len(st.entries)
	c.Head = headJ{n, hx(st.digestAt(n))}
	return c, nil
}

func buildReserve(h *httpJ, b *logBuilder, w *world, sp *space, change changeFn) error {
	m := &m7Builder{b: b, w: w, log: w.logIDText, base4: b.baseRaw(4)}
	A, B, C, R1 := w.A, w.B, w.C, w.R1
	grantC := m.grant(A, C, 1, m.base4, []int{1})
	recGrantC := m.grant(R1, C, 1, m.base4, []int{1})
	newB := change(B, 50, m.base4, 1, w.logIDText, `{"op":"add","task":9}`)
	rot := func(base string) string { e, _ := m.epoch(A, base, 2, nil, []*party{A, B, C}, R1); return e }
	grantRh := recordHashOf(grantC)
	after := posRaw(5, digestN(b.digests[4], 5, entryHash("snailfish.grant.v1", nil, grantRh)))
	rotAfter := rot(after)
	if m.err != nil {
		return m.err
	}
	used := sp.secUsed
	n := func(env string) int64 { return int64(len(env)) }
	type rc struct {
		name   string
		signer *party
		res    int64
		count  int
		envs   []string
		want   []string
	}
	for _, c := range []rc{
		{"security-fits-exactly", A, used + n(grantC), 0, []string{grantC}, []string{"stored:5"}},
		{"security-one-byte-over", A, used + n(grantC) - 1, 0, []string{grantC}, []string{"refused:reserve"}},
		{"change-ignores-reserve", B, used, 0, []string{newB}, []string{"stored:5"}},
		{"security-limit-reached", A, defaultReserve, securityPerDay, []string{grantC}, []string{"refused:security_limit"}},
		{"security-limit-last-record", A, defaultReserve, securityPerDay - 1, []string{grantC, rotAfter}, []string{"stored:5", "refused:security_limit"}},
		{"security-limit-counts-the-request-keyid", B, defaultReserve, 0, []string{recGrantC}, []string{"stored:5"}},
		{"change-ignores-security-limit", B, defaultReserve, securityPerDay, []string{newB}, []string{"stored:5"}},
	} {
		body := `{"envelopes":[` + strings.Join(c.envs, ",") + `]}`
		got, err := replayReserve(sp, reserveJ{Name: c.name, Signer: c.signer.name, Reserve: c.res, SecCount: c.count, Body: body}, c.signer.idText, h.Limits)
		if err != nil {
			return fmt.Errorf("append_reserve %s: %w", c.name, err)
		}
		var g []string
		for _, r := range got.Results {
			if r.Error != nil {
				g = append(g, "refused:"+*r.Error)
			} else {
				g = append(g, fmt.Sprintf("%s:%d", r.Status, *r.Position))
			}
		}
		if strings.Join(g, " ") != strings.Join(c.want, " ") {
			return fmt.Errorf("append_reserve %s: reference gives %v, expected %v", c.name, g, c.want)
		}
		h.AppendReserve = append(h.AppendReserve, got)
	}
	return nil
}

func recordHashOf(env string) []byte {
	pe, _ := parseEnvelope(env)
	return recordHash(pe.ptype, pe.payload, pe.sig)
}
