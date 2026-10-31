package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// This file is a small reference relay: PROTOCOL.md 8.6 (request checks),
// 10.5 (genesis), 10.6 (append) and 10.7 (fetch). It keeps the space in memory.

type result struct {
	status string // stored, known, conflict, refused
	pos    int
	err    string // refusal code
}

type chgRef struct {
	rh  string
	pos int
}

type spEntry struct {
	rh, digest []byte
}

type space struct {
	logText    string
	logID      []byte
	entries    []spEntry
	active     map[string]ed25519.PublicKey // device ID text to signing key
	writeLevel int64
	changes    map[string]chgRef // change ID text to the stored change
}

func (sp *space) clone() *space {
	c := *sp
	c.entries = append([]spEntry{}, sp.entries...)
	c.active = map[string]ed25519.PublicKey{}
	for k, v := range sp.active {
		c.active[k] = v
	}
	c.changes = map[string]chgRef{}
	for k, v := range sp.changes {
		c.changes[k] = v
	}
	return &c
}

func (sp *space) digestAt(n int) []byte {
	if n == 0 {
		return sha(frame(s("snailfish.log-root.v1"), sp.logID))
	}
	return sp.entries[n-1].digest
}

// record is a parsed and signature-checked envelope.
type record struct {
	ptype        string
	payload, sig []byte
	m            map[string]any
	rh           []byte
}

func parseRecord(env string) (*record, error) {
	pe, err := parseEnvelope(env)
	if err != nil {
		return nil, err
	}
	if err := validatePayload(pe.ptype, pe.payload); err != nil {
		return nil, err
	}
	v, _ := parseStrict(pe.payload)
	m := v.(map[string]any)
	return &record{pe.ptype, pe.payload, pe.sig, m, recordHash(pe.ptype, pe.payload, pe.sig)}, nil
}

func (r *record) str(k string) string { x, _ := r.m[k].(string); return x }

func (r *record) base() (int, []byte) {
	b, _ := r.m["base"].(map[string]any)
	n, _ := b["position"].(int64)
	d, _ := decodeB64(fmt.Sprint(b["digest"]))
	return int(n), d
}

func (r *record) changeID() string {
	if r.ptype == "snailfish.change.v1" {
		return r.str("change_id")
	}
	return ""
}

func (r *record) device() (id string, sign ed25519.PublicKey, level int64) {
	d, _ := r.m["device"].(map[string]any)
	id, _ = d["id"].(string)
	sg, _ := decodeB64(fmt.Sprint(d["sign"]))
	level, _ = d["level"].(int64)
	return id, sg, level
}

func (sp *space) push(r *record) int {
	n := len(sp.entries) + 1
	var cid []byte
	if id := r.changeID(); id != "" {
		cid, _ = decodeID(id, "c_", 16)
		sp.changes[id] = chgRef{hx(r.rh), n}
	}
	eh := entryHash(r.ptype, cid, r.rh)
	sp.entries = append(sp.entries, spEntry{r.rh, digestN(sp.digestAt(n-1), n, eh)})
	switch r.ptype {
	case "snailfish.genesis.v1":
		id, sg, _ := r.device()
		sp.active[id] = sg
		sp.writeLevel, _ = r.m["level"].(int64)
	case "snailfish.grant.v1":
		id, sg, _ := r.device()
		sp.active[id] = sg
	}
	return n
}

// newSpaceFromEnvelopes replays a log of genesis and grant and change records
// with every check of 10.2, 10.5 and 10.6 that applies to a stored log.
func newSpaceFromEnvelopes(logText string, envs []string) (*space, error) {
	logID, err := decodeID(logText, "l_", 16)
	if err != nil {
		return nil, err
	}
	sp := &space{logText: logText, logID: logID, active: map[string]ed25519.PublicKey{}, changes: map[string]chgRef{}}
	for i, env := range envs {
		n := i + 1
		r, err := parseRecord(env)
		if err != nil {
			return nil, fmt.Errorf("position %d: %w", n, err)
		}
		if r.str("log") != logText {
			return nil, fmt.Errorf("position %d: wrong log", n)
		}
		bn, bd := r.base()
		author := r.str("author")
		var key ed25519.PublicKey
		if n == 1 {
			if r.ptype != "snailfish.genesis.v1" {
				return nil, errors.New("position 1 is not genesis")
			}
			rec := r.m["recovery"].(map[string]any)
			key, _ = decodeB64(fmt.Sprint(rec["sign"]))
		} else {
			if r.ptype == "snailfish.genesis.v1" {
				return nil, fmt.Errorf("position %d: second genesis", n)
			}
			if bn < 1 || bn >= n || !bytes.Equal(bd, sp.digestAt(bn)) {
				return nil, fmt.Errorf("position %d: bad base", n)
			}
			if key = sp.active[author]; key == nil {
				return nil, fmt.Errorf("position %d: author is not active", n)
			}
		}
		if !ed25519.Verify(key, pae(r.ptype, r.payload), r.sig) {
			return nil, fmt.Errorf("position %d: signature does not verify", n)
		}
		sp.push(r)
	}
	return sp, nil
}

// appendBatch is PROTOCOL.md 10.6. keyid is the signer of the request.
func (sp *space) appendBatch(keyid, body string, lim limitsJ) ([]result, error) {
	var req struct {
		Envelopes []json.RawMessage `json:"envelopes"`
	}
	dec := json.NewDecoder(strings.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return nil, fmt.Errorf("bad_request: %w", err)
	}
	if len(req.Envelopes) < 1 || len(req.Envelopes) > lim.MaxAppendEnvelopes {
		return nil, fmt.Errorf("bad_request: %d envelopes", len(req.Envelopes))
	}
	var out []result
	for _, raw := range req.Envelopes {
		out = append(out, sp.appendOne(keyid, string(raw), lim))
	}
	return out, nil
}

func refuse(code string) result { return result{status: "refused", err: code} }

func (sp *space) appendOne(keyid, env string, lim limitsJ) result {
	// 1
	r, err := parseRecord(env)
	if err != nil {
		return refuse("invalid_record")
	}
	// 2
	if id := r.changeID(); id != "" {
		if c, ok := sp.changes[id]; ok {
			if c.rh == hx(r.rh) {
				return result{status: "known", pos: c.pos}
			}
			return result{status: "conflict", pos: c.pos}
		}
	}
	// 3
	if r.ptype == "snailfish.change.v1" && len(r.payload) > lim.MaxChangeBytes {
		return refuse("too_large")
	}
	// 4
	if r.str("log") != sp.logText {
		return refuse("invalid_record")
	}
	author := r.str("author")
	// 5
	if author != keyid {
		return refuse("not_author")
	}
	// 6
	key := sp.active[author]
	if key == nil {
		return refuse("not_active")
	}
	// 7
	if !ed25519.Verify(key, pae(r.ptype, r.payload), r.sig) {
		return refuse("invalid_record")
	}
	// 8
	next := len(sp.entries) + 1
	if bn, bd := r.base(); bn < 1 || bn >= next || !bytes.Equal(bd, sp.digestAt(bn)) {
		return refuse("bad_base")
	}
	// 9
	if r.ptype != "snailfish.change.v1" && r.ptype != "snailfish.grant.v1" {
		return refuse("unsupported")
	}
	// 10
	if r.ptype == "snailfish.change.v1" {
		if e, _ := r.m["epoch"].(int64); e != 1 {
			return refuse("wrong_epoch")
		}
	}
	// 11
	if r.ptype == "snailfish.grant.v1" {
		id, _, level := r.device()
		if sp.active[id] != nil || level < sp.writeLevel {
			return refuse("invalid_record")
		}
	}
	// 12
	return result{status: "stored", pos: sp.push(r)}
}

// fetch is PROTOCOL.md 10.7: positions after+1 .. at most limit entries.
func (sp *space) fetch(after, limit int) (positions []int, head int, hasMore bool) {
	head = len(sp.entries)
	positions = []int{}
	for p := after + 1; p <= head && len(positions) < limit; p++ {
		positions = append(positions, p)
	}
	last := after
	if len(positions) > 0 {
		last = positions[len(positions)-1]
	}
	return positions, head, head > last && head > after
}

// ---- request checks (PROTOCOL.md 8.6) ----

type request struct {
	method, path, query, body string
	headers                   [][2]string
}

type relayState struct {
	authority string
	now       int64
	space     *space
	used      map[[2]string]bool
}

var paramsRe = regexp.MustCompile(`^\("@method" "@authority" "@path" "@query" "content-digest"\);created=([1-9][0-9]*);expires=([1-9][0-9]*);nonce="([0-9a-f]{32})";keyid="(d_[0-9a-f]{64})";alg="ed25519";tag="snailfish\.request\.v1"$`)

var digestRe = regexp.MustCompile(`^sha-256=:([A-Za-z0-9+/]{43}=):$`)

func headerValues(h [][2]string, name string) []string {
	var out []string
	for _, x := range h {
		if strings.EqualFold(x[0], name) {
			out = append(out, x[1])
		}
	}
	return out
}

type parsedParams struct {
	created, expires int64
	nonce, keyid     string
	line             string
}

func parseParams(line string) (*parsedParams, error) {
	m := paramsRe.FindStringSubmatch(line)
	if m == nil {
		return nil, errors.New("signature parameters break 8.2")
	}
	c, err1 := strconv.ParseInt(m[1], 10, 64)
	e, err2 := strconv.ParseInt(m[2], 10, 64)
	if err1 != nil || err2 != nil || c > maxInt || e > maxInt {
		return nil, errors.New("integer out of range")
	}
	if e <= c || e > c+300 {
		return nil, errors.New("expires outside (created, created+300]")
	}
	return &parsedParams{c, e, m[3], m[4], line}, nil
}

// verifyRequest returns the error code of the first failed check, or "" if the
// request passes. It does not store the nonce.
func (rs *relayState) verifyRequest(rq request) string {
	// 1
	if v := headerValues(rq.headers, "snailfish-authority"); len(v) == 1 && v[0] != rs.authority {
		return "wrong_authority"
	}
	// 2
	one := func(name string) (string, bool) {
		v := headerValues(rq.headers, name)
		if len(v) != 1 {
			return "", false
		}
		return v[0], true
	}
	cd, ok1 := one("content-digest")
	si, ok2 := one("signature-input")
	sg, ok3 := one("signature")
	au, ok4 := one("snailfish-authority")
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return "bad_signature"
	}
	_ = au
	if !digestRe.MatchString(cd) {
		return "bad_signature"
	}
	if !strings.HasPrefix(si, "sf=") || !strings.HasPrefix(sg, "sf=:") || !strings.HasSuffix(sg, ":") || len(sg) < 5 {
		return "bad_signature"
	}
	pp, err := parseParams(si[3:])
	if err != nil {
		return "bad_signature"
	}
	sig, err := decodeB64(sg[4 : len(sg)-1])
	if err != nil || len(sig) != 64 {
		return "bad_signature"
	}
	// 3
	if pp.expires < rs.now || pp.created > rs.now+60 {
		return "expired"
	}
	// 4
	if cd != digestHeader(rq.body) {
		return "bad_digest"
	}
	// 5
	key := rs.space.active[pp.keyid]
	if key == nil {
		return "unknown_device"
	}
	// 6
	base := sigBase(strings.ToUpper(rq.method), rs.authority, rq.path, rq.query, cd, pp.line)
	if !ed25519.Verify(key, []byte(base), sig) {
		return "bad_signature"
	}
	// 7
	if rs.used[[2]string{pp.keyid, pp.nonce}] {
		return "nonce_reused"
	}
	return ""
}
