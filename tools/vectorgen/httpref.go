package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

// This file is a small reference relay: PROTOCOL.md 8.6 (request checks),
// 10.5 (genesis), 10.6 (append), 10.7 (fetch), 10.8 (status reports), 10.9
// (repair sessions) and 10.10 (enrollment sessions). It keeps the space in
// memory.

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
	recovery   map[string]ed25519.PublicKey // the current recovery ID text to its signing key (10.2)
	writeLevel int64
	changes    map[string]chgRef // change ID text to the stored change
	inRequest  bool              // an append request runs, for the mutant quota-ignores-request
	lastSec    int               // position of the last security record (10.6 step 10)
	hold       bool              // restore hold ([LOG-14])
	reports    map[string]report // device ID text to its last status report (10.8)
	sess       *repairSession    // at most one repair session (10.9)
	quota      int64             // space quota in bytes (10.6 step 14). 0 means no quota.
	used       int64             // stored change bytes (10.6 step 14)
	// mut names a deliberate fault. Only the tests of http_test.go set it, to
	// show that the vectors detect the fault. The generator keeps it "".
	mut string
}

// isSecurity is the security record rule of PROTOCOL.md 10.2 ([VER-5]).
func isSecurity(ptype string) bool {
	for _, f := range []string{"snailfish.change.", "snailfish.snapshot.", "snailfish.accept."} {
		if strings.HasPrefix(ptype, f) {
			return false
		}
	}
	return true
}

func (sp *space) clone() *space {
	c := *sp
	c.entries = append([]spEntry{}, sp.entries...)
	c.active = map[string]ed25519.PublicKey{}
	for k, v := range sp.active {
		c.active[k] = v
	}
	c.recovery = map[string]ed25519.PublicKey{}
	for k, v := range sp.recovery {
		c.recovery[k] = v
	}
	c.changes = map[string]chgRef{}
	for k, v := range sp.changes {
		c.changes[k] = v
	}
	c.reports = map[string]report{}
	for k, v := range sp.reports {
		c.reports[k] = v
	}
	if sp.sess != nil {
		ss := *sp.sess
		ss.staged = append([]*record{}, sp.sess.staged...)
		c.sess = &ss
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
	envLen       int64 // byte length of the envelope JSON text as the request holds it
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
	return &record{pe.ptype, pe.payload, pe.sig, m, recordHash(pe.ptype, pe.payload, pe.sig), int64(len(env))}, nil
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
	if r.ptype == "snailfish.change.v1" && (sp.mut != "quota-ignores-request" || !sp.inRequest) {
		sp.used += r.envLen
	}
	eh := entryHash(r.ptype, cid, r.rh)
	sp.entries = append(sp.entries, spEntry{r.rh, digestN(sp.digestAt(n-1), n, eh)})
	if isSecurity(r.ptype) {
		sp.lastSec = n
	}
	switch r.ptype {
	case "snailfish.genesis.v1":
		id, sg, _ := r.device()
		sp.active[id] = sg
		sp.writeLevel, _ = r.m["level"].(int64)
		rec, _ := r.m["recovery"].(map[string]any)
		rk, _ := decodeB64(fmt.Sprint(rec["sign"]))
		sp.recovery = map[string]ed25519.PublicKey{r.str("author"): rk}
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
	sp := &space{logText: logText, logID: logID, active: map[string]ed25519.PublicKey{}, recovery: map[string]ed25519.PublicKey{},
		changes: map[string]chgRef{}, reports: map[string]report{}}
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
			if key = sp.authorKey(author); key == nil {
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
	sp.inRequest = true
	defer func() { sp.inRequest = false }()
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
	onHold := sp.hold && !isSecurity(r.ptype)
	if onHold && sp.mut == "hold-before-known" {
		return refuse("on_hold")
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
	if onHold && sp.mut != "no-hold" {
		return refuse("on_hold")
	}
	// 4
	if r.ptype == "snailfish.change.v1" && len(r.payload) > lim.MaxChangeBytes {
		return refuse("too_large")
	}
	// 5 to 13
	if code := sp.checkRules(r, keyid); code != "" {
		return refuse(code)
	}
	// 14
	if (r.ptype == "snailfish.change.v1" || sp.mut == "quota-checks-security") && sp.quota > 0 && sp.used+r.envLen > sp.quota && sp.mut != "no-quota" {
		return refuse("quota")
	}
	// 15
	return result{status: "stored", pos: sp.push(r)}
}

// checkRules is PROTOCOL.md 10.6 steps 5 to 13 against the state of sp. If
// keyid is "", it skips step 6, as for a fetched record or a repair entry.
func (sp *space) checkRules(r *record, keyid string) string {
	// 5
	if r.str("log") != sp.logText {
		return "invalid_record"
	}
	author := r.str("author")
	isRec := strings.HasPrefix(author, "r_")
	// 6
	if keyid != "" && author != keyid && (!isRec || sp.mut == "recovery-not-author") {
		return "not_author"
	}
	// 7
	key := sp.authorKey(author)
	if key == nil && !(isRec && sp.mut == "recovery-skip-active") {
		return "not_active"
	}
	// 8
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, pae(r.ptype, r.payload), r.sig) {
		return "invalid_record"
	}
	// 9
	next := len(sp.entries) + 1
	bn, bd := r.base()
	if bn < 1 || bn >= next || !bytes.Equal(bd, sp.digestAt(bn)) {
		return "bad_base"
	}
	// 10
	last := sp.lastSec
	if sp.mut == "stale-counts-changes" {
		last = len(sp.entries)
	}
	if isSecurity(r.ptype) && last > bn && sp.mut != "no-stale-base" {
		return "stale_base"
	}
	// 11
	if r.ptype != "snailfish.change.v1" && r.ptype != "snailfish.grant.v1" {
		return "unsupported"
	}
	// 12
	if r.ptype == "snailfish.change.v1" {
		if e, _ := r.m["epoch"].(int64); e != 1 {
			return "wrong_epoch"
		}
	}
	// 13
	if r.ptype == "snailfish.grant.v1" {
		id, _, level := r.device()
		if sp.active[id] != nil || level < sp.writeLevel {
			return "invalid_record"
		}
	}
	return ""
}

// authorKey is the signing key of an author of 10.6 steps 7 and 8: an active
// device, or the current recovery ID of the space (10.2). It is nil for each
// other author.
func (sp *space) authorKey(author string) ed25519.PublicKey {
	if strings.HasPrefix(author, "r_") {
		return sp.recovery[author]
	}
	return sp.active[author]
}

// fetch is PROTOCOL.md 10.7: positions after+1 .. at most limit entries.
func (sp *space) fetch(after, limit int) (positions []int, head int, hasMore, hold bool) {
	head = len(sp.entries)
	positions = []int{}
	for p := after + 1; p <= head && len(positions) < limit; p++ {
		positions = append(positions, p)
	}
	last := after
	if len(positions) > 0 {
		last = positions[len(positions)-1]
	}
	return positions, head, head > last && head > after, sp.hold && sp.mut != "fetch-no-hold"
}

// ---- status reports (PROTOCOL.md 10.8) ----

type report struct {
	pos    int
	digest []byte
	fresh  bool // stays true until the hold ends
	at     int64
}

// status is PROTOCOL.md 10.8 for the request signer keyid at relay time at.
// It returns the `hold` value of the response, or an error code.
func (sp *space) status(keyid string, at int64, body string) (bool, string) {
	v, err := parseStrict([]byte(body))
	if err != nil {
		return false, "bad_request"
	}
	r := newReader(v, "tip", "fresh")
	tip := r.pos("tip", 0)
	fresh, ok := r.m["fresh"].(bool)
	if !ok {
		r.fail("fresh is not a boolean")
	}
	if r.err != nil {
		return false, "bad_request"
	}
	if !sp.hold && sp.mut != "status-without-hold" {
		return false, ""
	}
	old := sp.reports[keyid]
	sp.reports[keyid] = report{int(tip.n), tip.d, fresh || old.fresh, at}
	return sp.hold, ""
}

// reported is the "reported" reading of 10.8: the log holds the stored tip
// position with the same digest now. ok is false if no report is stored.
func (sp *space) reported(keyid string) (reported, ok bool) {
	rp, ok := sp.reports[keyid]
	if !ok {
		return false, false
	}
	if rp.pos > len(sp.entries) {
		return false, true
	}
	return sp.mut == "reported-ignores-digest" || bytes.Equal(rp.digest, sp.digestAt(rp.pos)), true
}

// ---- repair sessions (PROTOCOL.md 10.9) ----

const (
	sessionTTL      = 86400 // seconds after the start or the last chunk
	repairAllowance = 1024  // bytes above max_request_bytes for a repair body
)

// errStatus is the HTTP status of each error code of 10.3 that the repair
// routes and the status route return.
var errStatus = map[string]int{
	"bad_request": 400, "bad_digest": 400, "unknown_device": 403, "repair_busy": 409, "bad_repair": 409,
	"invalid_record": 422, "uncovered_stub": 422, "too_large": 413,
	"unknown_session": 404, "session_exists": 409, "bad_step": 409, "session_closed": 409,
	"bad_signature": 401, "expired": 401, "nonce_reused": 401, "wrong_authority": 421,
	"bad_setup": 403, "space_exists": 409, "internal": 500,
}

type repairSession struct {
	id, device  string
	base        int // relay head position at the start
	baseDigest  []byte
	staged      []*record
	start, last int64 // time of the start, and of the start or the last chunk
}

func (sp *space) expired(ss *repairSession, at int64) bool {
	switch sp.mut {
	case "no-expiry":
		return false
	case "expiry-from-start":
		return at >= ss.start+sessionTTL
	}
	return at >= ss.last+sessionTTL
}

func (sp *space) headChanged(ss *repairSession) bool {
	n := len(sp.entries)
	return n != ss.base || !bytes.Equal(sp.digestAt(n), ss.baseDigest)
}

// repairEntry is one entry of a start or chunk body. env is the raw envelope
// text, or "" for a stub.
type repairEntry struct {
	pos  int
	env  string
	stub bool
}

var sessionRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// parseRepairBody reads the form of a start body (first is "base") or a chunk
// body (first is "session").
func parseRepairBody(body, first string, lim limitsJ) (*reader, []repairEntry, error) {
	v, err := parseStrict([]byte(body))
	if err != nil {
		return nil, nil, err
	}
	r := newReader(v, first, "entries")
	items := r.list("entries")
	if r.err == nil && (len(items) < 1 || len(items) > lim.MaxAppendEnvelopes) {
		r.fail("%d entries", len(items))
	}
	var raw struct {
		Entries []struct {
			Envelope json.RawMessage `json:"envelope"`
		} `json:"entries"`
	}
	if r.err == nil {
		if err := json.Unmarshal([]byte(body), &raw); err != nil || len(raw.Entries) != len(items) {
			r.fail("entries: %v", err)
		}
	}
	var out []repairEntry
	for i, it := range items {
		if r.err != nil {
			break
		}
		m, _ := it.(map[string]any)
		var e *reader
		ent := repairEntry{}
		if _, isStub := m["stub"]; isStub {
			e = newReader(it, "position", "stub")
			sm, _ := m["stub"].(map[string]any)
			typ, _ := sm["type"].(string)
			isChange := strings.HasPrefix(typ, "snailfish.change.")
			names := []string{"type", "hash"}
			if isChange {
				names = []string{"type", "change_id", "hash"}
			}
			st := e.sub("stub", names...)
			st.str("type")
			if isChange {
				st.id("change_id", "c_", 16)
			}
			st.bin("hash", 32, 0)
			if st.err != nil {
				e.fail("stub: %v", st.err)
			}
			ent.stub = true
		} else {
			e = newReader(it, "position", "envelope")
			if _, ok := e.m["envelope"].(map[string]any); !ok {
				e.fail("envelope is not an object")
			}
			ent.env = string(raw.Entries[i].Envelope)
		}
		ent.pos = int(e.num("position", 1, maxInt))
		if e.err != nil {
			r.fail("entry %d: %v", i, e.err)
		}
		out = append(out, ent)
	}
	return r, out, r.err
}

// overlay returns the state of the log after the staged entries of ss. If the
// relay head changed since the start, the staged entries no longer follow the
// log, and only their grants count (for 8.6 step 5).
func (sp *space) overlay(ss *repairSession) *space {
	o := sp.clone()
	o.sess = nil
	if ss == nil {
		return o
	}
	for _, r := range ss.staged {
		if !sp.headChanged(ss) {
			o.push(r)
		} else if r.ptype == "snailfish.grant.v1" {
			id, sg, _ := r.device()
			o.active[id] = sg
		}
	}
	return o
}

// chain is the chain check of 10.9 step 3 on o, the state after the base or
// the staged entries. It pushes each entry that passes onto o, and returns
// the passed records and the error of the first entry that fails, or "".
func (o *space) chain(entries []repairEntry, signer string) ([]*record, string) {
	var out []*record
	for _, e := range entries {
		if e.pos != len(o.entries)+1 {
			return out, "bad_repair"
		}
		if e.stub {
			if o.mut == "stub-invalid-record" {
				return out, "invalid_record"
			}
			return out, "uncovered_stub"
		}
		r, err := parseRecord(e.env)
		if err != nil {
			return out, "invalid_record"
		}
		if id := r.changeID(); id != "" && o.mut != "chain-allows-known" {
			if _, ok := o.changes[id]; ok {
				return out, "invalid_record"
			}
		}
		keyid := ""
		if o.mut == "chain-not-author" {
			keyid = signer
		}
		if code := o.checkRules(r, keyid); code != "" {
			return out, "invalid_record"
		}
		o.push(r)
		out = append(out, r)
	}
	return out, ""
}

// repairReply is the result of a repair request. next is for start and chunk,
// head for finish.
type repairReply struct {
	status     int
	session    string
	next, head int
	code       string
}

func repairErr(code string) repairReply { return repairReply{status: errStatus[code], code: code} }

// isActive is 8.6 step 5 for the repair routes: o holds the log and the
// staged or request entries ([LOG-12]).
func (sp *space) isActive(o *space, keyid string) bool {
	if sp.mut == "no-log12" {
		return sp.active[keyid] != nil
	}
	return o.active[keyid] != nil
}

// repairTooLarge is the body limit of the repair routes (10.9).
func (sp *space) repairTooLarge(body string, lim limitsJ) bool {
	allow := repairAllowance
	if sp.mut == "no-allowance" {
		allow = 0
	}
	return len(body) > lim.MaxRequestBytes+allow
}

// repairStart is the start route of 10.9 after 8.6 steps 1 to 4.
func (sp *space) repairStart(keyid string, at int64, body string, lim limitsJ) repairReply {
	if sp.repairTooLarge(body, lim) {
		return repairErr("too_large")
	}
	// 2
	r, entries, err := parseRepairBody(body, "base", lim)
	if err != nil {
		return repairErr("bad_request")
	}
	base := r.pos("base", 0)
	if r.err != nil {
		return repairErr("bad_request")
	}
	// 3
	n := len(sp.entries)
	atHead := int(base.n) == n && bytes.Equal(base.d, sp.digestAt(n))
	o := sp.overlay(nil)
	var passed []*record
	code := ""
	if atHead {
		passed, code = o.chain(entries, keyid)
	}
	// 4
	if !sp.isActive(o, keyid) {
		return repairErr("unknown_device")
	}
	// 5
	if !atHead {
		return repairErr("bad_repair")
	}
	// 6
	if ss := sp.sess; ss != nil && ss.device != keyid && !sp.expired(ss, at) && sp.mut != "no-busy" {
		return repairErr("repair_busy")
	}
	// 7
	if code != "" {
		return repairErr(code)
	}
	// 8
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return repairErr("internal")
	}
	sp.sess = &repairSession{id: hex.EncodeToString(id[:]), device: keyid, base: n, baseDigest: sp.digestAt(n),
		staged: passed, start: at, last: at}
	return repairReply{status: 201, session: sp.sess.id, next: len(o.entries) + 1}
}

// session returns the repair session that sid names, or nil.
func (sp *space) session(sid string) *repairSession {
	if sp.sess != nil && sp.sess.id == sid {
		return sp.sess
	}
	return nil
}

// continues is the session condition of the chunk step 5 and the finish
// step 1 of 10.9.
func (sp *space) continues(ss *repairSession, keyid string, at int64) bool {
	return ss != nil && !sp.expired(ss, at) && (ss.device == keyid || sp.mut == "chunk-any-signer") && !sp.headChanged(ss)
}

// repairChunk is the chunk route of 10.9 after 8.6 steps 1 to 4.
func (sp *space) repairChunk(keyid string, at int64, body string, lim limitsJ) repairReply {
	if sp.repairTooLarge(body, lim) {
		return repairErr("too_large")
	}
	// 2
	r, entries, err := parseRepairBody(body, "session", lim)
	if err != nil {
		return repairErr("bad_request")
	}
	sid := r.str("session")
	if r.err != nil || !sessionRe.MatchString(sid) {
		return repairErr("bad_request")
	}
	// 3: the chain continues the staged entries of the session.
	ss := sp.session(sid)
	o := sp.overlay(ss)
	var passed []*record
	code := ""
	if ss != nil && !sp.headChanged(ss) {
		passed, code = o.chain(entries, keyid)
	}
	// 4
	if !sp.isActive(o, keyid) {
		return repairErr("unknown_device")
	}
	// 5
	if !sp.continues(ss, keyid, at) {
		return repairErr("bad_repair")
	}
	// 7
	if code != "" {
		return repairErr(code)
	}
	// 8
	ss.staged = append(ss.staged, passed...)
	ss.last = at
	return repairReply{status: 200, next: len(o.entries) + 1}
}

// repairFinish is the finish route of 10.9 after 8.6 steps 1 to 4.
func (sp *space) repairFinish(keyid string, at int64, body string, lim limitsJ) repairReply {
	if sp.repairTooLarge(body, lim) {
		return repairErr("too_large")
	}
	v, err := parseStrict([]byte(body))
	if err != nil {
		return repairErr("bad_request")
	}
	r := newReader(v, "session", "tip")
	sid := r.str("session")
	tip := r.pos("tip", 0)
	if r.err != nil || !sessionRe.MatchString(sid) {
		return repairErr("bad_request")
	}
	ss := sp.session(sid)
	o := sp.overlay(ss)
	// 8.6 step 5 with the keys of the log and the staged entries
	if !sp.isActive(o, keyid) {
		return repairErr("unknown_device")
	}
	// 1
	if !sp.continues(ss, keyid, at) {
		return repairErr("bad_repair")
	}
	// 2
	last := len(o.entries)
	if (int(tip.n) != last || !bytes.Equal(tip.d, o.digestAt(last))) && sp.mut != "no-tip-check" {
		return repairErr("bad_repair")
	}
	// 3: M3 stages no stub. 4
	for _, rec := range ss.staged {
		sp.push(rec)
	}
	sp.sess = nil
	return repairReply{status: 200, head: len(sp.entries)}
}

// ---- enrollment sessions (PROTOCOL.md 10.10) ----

const enrollTTL = 600 // seconds after the open

// enrollSlots is the slot order of 10.10.
var enrollSlots = []string{"new.hello", "trusted.hello", "new.nonce", "trusted.nonce", "new.confirm", "trusted.done"}

type enrollSession struct {
	device  string // the device ID text of the device that opened it
	expires int64
	state   string         // open, done or cancelled
	slots   map[string]any // slot to the stored message value
	raw     map[string]string
}

// enrollRelay holds the enrollment sessions of one space of one tenant.
type enrollRelay struct {
	sp       *space
	tenant   string
	sessions map[string]*enrollSession // session ID text
	mut      string
}

// enrollReq is one request. keyid is "" for the unsigned routes. digestOK is
// false if content-digest differs from the body (8.6 step 4).
type enrollReq struct {
	route, keyid, session, body string
	at                          int64
	digestOK                    bool
}

type enrollReply struct {
	status int
	body   any
	code   string
}

func enrollErr(code string) enrollReply { return enrollReply{status: errStatus[code], code: code} }

// lookup returns the session sid if it has not expired. The relay deletes an
// expired session.
func (er *enrollRelay) lookup(sid string, at int64) *enrollSession {
	ss := er.sessions[sid]
	if ss != nil && at >= ss.expires && er.mut != "enroll-no-expiry" {
		delete(er.sessions, sid)
		return nil
	}
	return ss
}

func (ss *enrollSession) object(sid string) map[string]any {
	nw, tr := map[string]any{}, map[string]any{}
	for slot, v := range ss.slots {
		writer, name, _ := strings.Cut(slot, ".")
		if writer == "new" {
			nw[name] = v
		} else {
			tr[name] = v
		}
	}
	return map[string]any{"session": sid, "expires": ss.expires, "state": ss.state, "new": nw, "trusted": tr}
}

// decodeValue is the JSON value of a message as the relay stores it.
func decodeValue(body, key string) any {
	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil
	}
	return m[key]
}

// rawField returns the raw JSON text of m[key][sub], or of m[key] if sub is "".
func rawField(body, key, sub string) (string, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return "", err
	}
	if sub == "" {
		return string(m[key]), nil
	}
	var n map[string]json.RawMessage
	if err := json.Unmarshal(m[key], &n); err != nil {
		return "", err
	}
	return string(n[sub]), nil
}

// parseMessage is step 2 of a write: the body rules of 10.10 for the writer
// "new" or "trusted". It returns the slot of the message, or "cancel".
func (er *enrollRelay) parseMessage(writer, body string) (string, error) {
	lv, err := parseLenient([]byte(body))
	if err != nil {
		return "", err
	}
	top, ok := lv.(map[string]any)
	if !ok || len(top) != 1 {
		return "", errors.New("body must hold exactly one message")
	}
	var key string
	for k := range top {
		key = k
	}
	strict := func() *reader {
		v, err := parseStrict([]byte(body))
		if err != nil {
			return &reader{m: map[string]any{}, err: err}
		}
		return newReader(v, key)
	}
	switch {
	case key == "cancel":
		r := strict()
		if r.err == nil && r.m["cancel"] != true {
			return "", errors.New("cancel is not true")
		}
		return "cancel", r.err
	case key == "nonce":
		r := strict()
		r.bin("nonce", 32, 0)
		return writer + ".nonce", r.err
	case key == "hello" && writer == "new":
		r := strict()
		x := r.sub("hello", "device")
		if x.err == nil {
			deviceObj(x, "device")
			if x.err != nil {
				r.fail("hello: %v", x.err)
			}
		}
		return "new.hello", r.err
	case key == "hello" && writer == "trusted":
		r := strict()
		x := r.sub("hello", "keys", "commitment")
		if x.err == nil {
			keysObj(x, "keys")
			x.bin("commitment", 32, 0)
			if x.err != nil {
				r.fail("hello: %v", x.err)
			}
		}
		return "trusted.hello", r.err
	case key == "confirm" && writer == "new":
		env, err := rawField(body, "confirm", "")
		if err == nil {
			_, err = parseEnvelope(env)
		}
		return "new.confirm", err
	case key == "done" && writer == "trusted":
		r := newReader(top, "done")
		x := r.sub("done", "tenant", "checkpoint")
		tenant := x.str("tenant")
		if x.err != nil {
			return "", x.err
		}
		if tenant != er.tenant && er.mut != "enroll-no-tenant-check" {
			return "", errors.New("tenant differs from the path")
		}
		env, err := rawField(body, "done", "checkpoint")
		if err == nil {
			_, err = parseEnvelope(env)
		}
		return "trusted.done", err
	}
	return "", fmt.Errorf("the %s route takes no %q message", writer, key)
}

func (er *enrollRelay) handle(rq enrollReq) enrollReply {
	switch rq.route {
	case "open":
		return er.open(rq)
	case "trusted_write", "new_write":
		return er.write(rq)
	case "trusted_read", "new_read":
		return er.read(rq)
	}
	panic("route " + rq.route)
}

// open is the open route of 10.10.
func (er *enrollRelay) open(rq enrollReq) enrollReply {
	parse := func() (string, bool) {
		v, err := parseStrict([]byte(rq.body))
		if err != nil {
			return "", false
		}
		r := newReader(v, "session")
		sid, _ := r.id("session", "e_", 16)
		return sid, r.err == nil
	}
	var sid string
	var ok bool
	if er.mut == "enroll-body-before-digest" {
		if sid, ok = parse(); !ok {
			return enrollErr("bad_request")
		}
	}
	// 8.6 steps 1 to 4
	if !rq.digestOK {
		return enrollErr("bad_digest")
	}
	if sid, ok = parse(); !ok {
		return enrollErr("bad_request")
	}
	// 8.6 steps 5 to 7
	if er.sp.active[rq.keyid] == nil {
		return enrollErr("unknown_device")
	}
	if ss := er.lookup(sid, rq.at); ss != nil {
		if ss.device != rq.keyid {
			return enrollErr("session_exists")
		}
		exp := ss.expires
		if er.mut == "enroll-open-retry-new-expires" {
			exp = rq.at + enrollTTL
		}
		return enrollReply{status: 200, body: map[string]any{"expires": exp}}
	}
	ss := &enrollSession{device: rq.keyid, expires: rq.at + enrollTTL, state: "open", slots: map[string]any{}, raw: map[string]string{}}
	er.sessions[sid] = ss
	return enrollReply{status: 201, body: map[string]any{"expires": ss.expires}}
}

// write is the write check order of 10.10, steps 1 to 8.
func (er *enrollRelay) write(rq enrollReq) enrollReply {
	trusted := rq.route == "trusted_write"
	writer := "new"
	if trusted {
		writer = "trusted"
	}
	// 1
	if trusted && !rq.digestOK {
		return enrollErr("bad_digest")
	}
	// 2
	slot, err := er.parseMessage(writer, rq.body)
	if err != nil {
		return enrollErr("bad_request")
	}
	// 3
	if trusted && er.sp.active[rq.keyid] == nil {
		return enrollErr("unknown_device")
	}
	// 4
	ss := er.lookup(rq.session, rq.at)
	if ss == nil || (trusted && ss.device != rq.keyid && er.mut != "enroll-trusted-any-device") {
		return enrollErr("unknown_session")
	}
	ok := enrollReply{status: 200}
	var val any
	retry := slot == "cancel" && ss.state == "cancelled"
	if slot != "cancel" {
		_, key, _ := strings.Cut(slot, ".")
		val = decodeValue(rq.body, key)
		if old, full := ss.slots[slot]; full {
			retry = reflect.DeepEqual(old, val)
			if er.mut == "enroll-retry-bytes" {
				retry = ss.raw[slot] == rq.body
			}
		}
	}
	closed := ss.state != "open"
	if er.mut == "enroll-closed-before-retry" && closed {
		return enrollErr("session_closed")
	}
	// 5
	if retry {
		ok.body = ss.object(rq.session)
		return ok
	}
	// 6
	if closed {
		return enrollErr("session_closed")
	}
	// 7
	if slot == "cancel" {
		ss.state = "cancelled"
		ok.body = ss.object(rq.session)
		return ok
	}
	next := ""
	for _, x := range enrollSlots {
		if _, full := ss.slots[x]; !full {
			next = x
			break
		}
	}
	_, full := ss.slots[slot]
	if slot != next && (er.mut != "enroll-any-order" || full) {
		return enrollErr("bad_step")
	}
	// 8
	ss.slots[slot], ss.raw[slot] = val, rq.body
	if slot == "trusted.done" {
		ss.state = "done"
	}
	ok.body = ss.object(rq.session)
	return ok
}

// read is the read route of 10.10: write steps 1, 3 and 4.
func (er *enrollRelay) read(rq enrollReq) enrollReply {
	trusted := rq.route == "trusted_read"
	if trusted && !rq.digestOK {
		return enrollErr("bad_digest")
	}
	if trusted && er.sp.active[rq.keyid] == nil {
		return enrollErr("unknown_device")
	}
	ss := er.lookup(rq.session, rq.at)
	if ss == nil || (trusted && ss.device != rq.keyid && er.mut != "enroll-trusted-any-device") {
		return enrollErr("unknown_session")
	}
	return enrollReply{status: 200, body: ss.object(rq.session)}
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
	mut       string // a deliberate fault, as space.mut
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
	pp, sig, code := rs.checkHeaders(rq)
	if code != "" {
		return code
	}
	// 5
	key := rs.space.active[pp.keyid]
	if key == nil {
		return "unknown_device"
	}
	return rs.checkSignature(rq, pp, sig, key)
}

// checkHeaders is the cookie rule of PROTOCOL.md 10 and 8.6 steps 1 to 4.
// PROTOCOL.md gives no order for the cookie rule. The vectors hold no case
// that depends on it.
func (rs *relayState) checkHeaders(rq request) (*parsedParams, []byte, string) {
	if len(headerValues(rq.headers, "cookie")) > 0 {
		return nil, nil, "bad_request"
	}
	// 1
	if v := headerValues(rq.headers, "snailfish-authority"); len(v) == 1 && v[0] != rs.authority {
		return nil, nil, "wrong_authority"
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
		return nil, nil, "bad_signature"
	}
	_ = au
	if !digestRe.MatchString(cd) {
		return nil, nil, "bad_signature"
	}
	// 8.1: standard base64 with padding and no other form, so non-zero
	// trailing bits break the header form (step 2), not the digest (step 4).
	if _, err := decodeB64(cd[len("sha-256=:") : len(cd)-1]); err != nil {
		return nil, nil, "bad_signature"
	}
	if !strings.HasPrefix(si, "sf=") || !strings.HasPrefix(sg, "sf=:") || !strings.HasSuffix(sg, ":") || len(sg) < 5 {
		return nil, nil, "bad_signature"
	}
	pp, err := parseParams(si[3:])
	if err != nil {
		return nil, nil, "bad_signature"
	}
	sig, err := decodeB64(sg[4 : len(sg)-1])
	if err != nil || len(sig) != 64 {
		return nil, nil, "bad_signature"
	}
	// 3
	if pp.expires < rs.now || pp.created > rs.now+60 {
		return nil, nil, "expired"
	}
	// 4
	if cd != digestHeader(rq.body) {
		return nil, nil, "bad_digest"
	}
	return pp, sig, ""
}

// checkSignature is 8.6 steps 6 and 7 with the signing key of step 5.
func (rs *relayState) checkSignature(rq request, pp *parsedParams, sig []byte, key ed25519.PublicKey) string {
	cd := headerValues(rq.headers, "content-digest")[0]
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
