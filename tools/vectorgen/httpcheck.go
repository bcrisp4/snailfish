package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// checkHTTP verifies http.json with the reference relay of httpref.go. It does
// not trust any derived field of the file.
func checkHTTP(h *httpJ, w *world) error { return checkHTTPWith(h, w, "") }

// checkHTTPWith is checkHTTP with the relay fault mut (see space.mut).
func checkHTTPWith(h *httpJ, w *world, mut string) error {
	if h.Version != 1 || h.Authority != httpAuthority || h.Now != httpNow {
		return fmt.Errorf("bad header fields")
	}
	if h.LogID != w.logIDText || h.Tenant != httpTenant() || len(h.Tenant) != 34 || !strings.HasPrefix(h.Tenant, "t_") {
		return fmt.Errorf("bad tenant or log ID")
	}
	keys := map[string]*party{}
	for _, d := range h.Devices {
		p := w.byName[d.Name]
		if p == nil || hx(p.signSeed) != d.SignSeed || p.idText != d.ID {
			return fmt.Errorf("device %s differs from the world", d.Name)
		}
		keys[d.Name] = p
	}
	var envs []string
	for i, e := range h.Space.Log {
		if e.Position != i+1 {
			return fmt.Errorf("space.log position %d at index %d", e.Position, i)
		}
		envs = append(envs, e.Envelope)
	}
	if len(envs) == 0 || envs[0] != h.Space.Genesis {
		return fmt.Errorf("space.genesis is not log position 1")
	}
	sp, err := newSpaceFromEnvelopes(h.LogID, envs)
	if err != nil {
		return fmt.Errorf("space.log: %w", err)
	}
	sp.mut = mut
	for i, e := range h.Space.Log {
		pe, _ := parseEnvelope(e.Envelope)
		if hx(recordHash(pe.ptype, pe.payload, pe.sig)) != e.RecordHash || hx(sp.entries[i].digest) != e.Digest {
			return fmt.Errorf("space.log %d: record hash or digest differs", e.Position)
		}
	}
	if h.Space.GenesisDigest != h.Space.Log[0].Digest {
		return fmt.Errorf("genesis_digest differs")
	}
	used := map[[2]string]bool{}
	for _, u := range h.UsedNonces {
		used[u] = true
	}
	rs := &relayState{authority: h.Authority, now: h.Now, space: sp, used: used}

	for _, c := range h.Signed {
		sg := keys[c.Signer]
		if sg == nil {
			return fmt.Errorf("signed %s: unknown signer", c.Name)
		}
		if c.ContentDigest != digestHeader(c.Body) {
			return fmt.Errorf("signed %s: content_digest is not RFC 9530 sha-256 of the body", c.Name)
		}
		if c.Expires > c.Created+300 || c.Expires <= c.Created {
			return fmt.Errorf("signed %s: expires window", c.Name)
		}
		if c.SignatureParams != paramsLine(c.Created, c.Expires, c.Nonce, sg.idText) {
			return fmt.Errorf("signed %s: signature_params differ from 8.2", c.Name)
		}
		if c.SignatureBase != sigBase(c.Method, c.Authority, c.Path, c.Query, c.ContentDigest, c.SignatureParams) {
			return fmt.Errorf("signed %s: signature_base differs from 8.4", c.Name)
		}
		sig, err := hex.DecodeString(c.Sig)
		if err != nil || !ed25519.Verify(sg.signPk, []byte(c.SignatureBase), sig) {
			return fmt.Errorf("signed %s: signature does not verify", c.Name)
		}
		want := [][2]string{{"content-digest", c.ContentDigest}, {"signature-input", "sf=" + c.SignatureParams},
			{"signature", "sf=:" + b64(sig) + ":"}, {"snailfish-authority", c.Authority}}
		if fmt.Sprint(want) != fmt.Sprint(c.Headers) {
			return fmt.Errorf("signed %s: headers differ from 8.1", c.Name)
		}
		r := *rs
		r.authority = c.Authority
		verify := r.verifyRequest
		if c.Path == setupPath {
			verify = r.verifySetupRequest
		}
		if code := verify(request{c.Method, c.Path, c.Query, c.Body, c.Headers}); code != "" {
			return fmt.Errorf("signed %s: reference relay returns %s", c.Name, code)
		}
	}
	seen := map[string]bool{}
	for _, c := range h.Invalid {
		if seen[c.Name] {
			return fmt.Errorf("invalid %s: duplicate name", c.Name)
		}
		seen[c.Name] = true
		if code := rs.verifyRequest(request{c.Method, c.Path, c.Query, c.Body, c.Headers}); code != c.Error {
			return fmt.Errorf("invalid %s: reference relay returns %q, file says %q", c.Name, code, c.Error)
		}
	}
	for _, c := range h.Append {
		sg := keys[c.Signer]
		if sg == nil {
			return fmt.Errorf("append %s: unknown signer", c.Name)
		}
		st := sp.clone()
		res, err := st.appendBatch(sg.idText, c.Body, h.Limits)
		if err != nil {
			return fmt.Errorf("append %s: %w", c.Name, err)
		}
		var rj []resultJ
		for _, r := range res {
			rj = append(rj, resultJOf(r))
		}
		if err := compare("append "+c.Name, c.Results, rj); err != nil {
			return err
		}
		n := len(st.entries)
		if c.Head.Position != n || c.Head.Digest != hx(st.digestAt(n)) {
			return fmt.Errorf("append %s: head differs from the reference", c.Name)
		}
	}
	for _, c := range h.AppendHold {
		sg := keys[c.Signer]
		if sg == nil {
			return fmt.Errorf("append_hold %s: unknown signer", c.Name)
		}
		st := sp.clone()
		st.hold = true
		res, err := st.appendBatch(sg.idText, c.Body, h.Limits)
		if err != nil {
			return fmt.Errorf("append_hold %s: %w", c.Name, err)
		}
		var rj []resultJ
		for _, r := range res {
			rj = append(rj, resultJOf(r))
		}
		if err := compare("append_hold "+c.Name, c.Results, rj); err != nil {
			return err
		}
		n := len(st.entries)
		if c.Head.Position != n || c.Head.Digest != hx(st.digestAt(n)) {
			return fmt.Errorf("append_hold %s: head differs from the reference", c.Name)
		}
	}
	for _, c := range h.AppendQuota {
		sg := keys[c.Signer]
		if sg == nil {
			return fmt.Errorf("append_quota %s: unknown signer", c.Name)
		}
		got, err := replayQuota(sp, c, sg.idText, h.Limits)
		if err != nil {
			return fmt.Errorf("append_quota %s: %w", c.Name, err)
		}
		if err := compare("append_quota "+c.Name, c, got); err != nil {
			return err
		}
	}
	for _, c := range h.Fetch {
		st := sp.clone()
		st.hold = c.Hold
		pos, head, more, hold := st.fetch(c.After, c.Limit)
		if c.Limit < 1 || c.Limit > h.Limits.MaxFetchEntries {
			return fmt.Errorf("fetch %s: limit out of range", c.Name)
		}
		if fmt.Sprint(pos) != fmt.Sprint(c.Positions) || head != c.Head || more != c.HasMore || hold != c.Hold {
			return fmt.Errorf("fetch %s: reference gives %v head %d more %v hold %v", c.Name, pos, head, more, hold)
		}
	}
	for _, c := range h.Status {
		sg := keys[c.Signer]
		if sg == nil {
			return fmt.Errorf("status %s: unknown signer", c.Name)
		}
		if err := compare("status "+c.Name, c, replayStatus(sp, c, sg.idText, h.Now)); err != nil {
			return err
		}
	}
	for _, c := range h.Repair {
		got, err := replayRepair(envs, h.LogID, c, keys, h.Limits, mut)
		if err != nil {
			return fmt.Errorf("repair %s: %w", c.Name, err)
		}
		if err := compare("repair "+c.Name, c, got); err != nil {
			return err
		}
	}
	for _, c := range h.Enroll {
		got, err := replayEnroll(envs, h.LogID, h.Tenant, c, keys, mut)
		if err != nil {
			return fmt.Errorf("enroll %s: %w", c.Name, err)
		}
		if err := compare("enroll "+c.Name, c, got); err != nil {
			return err
		}
	}
	if err := checkSetup(h, w, mut); err != nil {
		return err
	}
	if err := checkHTTPCoverage(h); err != nil {
		return err
	}
	// every code and status that the README lists must occur
	for _, need := range []string{"bad_signature", "expired", "bad_digest", "unknown_device", "nonce_reused", "wrong_authority"} {
		found := false
		for _, c := range h.Invalid {
			found = found || c.Error == need
		}
		if !found {
			return fmt.Errorf("no invalid case with error %s", need)
		}
	}
	_ = bytes.Equal
	return nil
}

// checkHTTPCoverage requires each result that vectors/README.md lists for the
// M3 sections, so a file without a required witness fails.
func checkHTTPCoverage(h *httpJ) error {
	have := map[string]bool{}
	for _, c := range h.Append {
		for _, r := range c.Results {
			if r.Error != nil {
				have["append "+*r.Error] = true
			}
		}
	}
	for _, c := range h.AppendHold {
		for _, r := range c.Results {
			if r.Error != nil {
				have["append_hold "+*r.Error] = true
			} else {
				have["append_hold "+r.Status] = true
			}
		}
	}
	for _, c := range h.Fetch {
		have[fmt.Sprintf("fetch hold %v", c.Hold)] = true
	}
	for _, c := range h.Status {
		switch {
		case c.Error != nil:
			have["status "+*c.Error] = true
		case c.TipInLog == nil:
			have[fmt.Sprintf("status hold %v reported null", c.Response.Hold)] = true
		default:
			have[fmt.Sprintf("status hold %v reported %v", c.Response.Hold, *c.TipInLog)] = true
		}
	}
	for _, c := range h.AppendQuota {
		for _, r := range c.Results {
			if r.Error != nil {
				have["append_quota "+*r.Error] = true
			} else {
				have["append_quota "+r.Status] = true
			}
		}
	}
	for _, c := range h.Repair {
		for _, s := range c.Steps {
			if s.Error != nil {
				have["repair "+*s.Error] = true
			} else {
				have[fmt.Sprintf("repair %s %d", s.Route, s.Status)] = true
			}
		}
	}
	for _, c := range h.Enroll {
		for _, s := range c.Steps {
			if s.Error != nil {
				have["enroll "+*s.Error] = true
				continue
			}
			have[fmt.Sprintf("enroll %s %d", s.Route, s.Status)] = true
			if m, ok := s.Response.(map[string]any); ok && m["state"] != nil {
				have[fmt.Sprint("enroll state ", m["state"])] = true
			}
		}
	}
	for _, need := range []string{
		"append not_active", "append unsupported",
		"enroll open 201", "enroll open 200", "enroll new_read 200", "enroll new_write 200", "enroll trusted_read 200", "enroll trusted_write 200",
		"enroll state open", "enroll state done", "enroll state cancelled",
		"enroll bad_request", "enroll bad_digest", "enroll unknown_device",
		"enroll unknown_session", "enroll session_exists", "enroll bad_step", "enroll session_closed",
		"append stale_base",
		"append_quota quota", "append_quota stored", "append_quota known",
		"append_hold on_hold", "append_hold known", "append_hold stored", "append_hold stale_base",
		"fetch hold true", "fetch hold false",
		"status bad_request", "status hold true reported true", "status hold true reported false", "status hold false reported null",
		"repair start 201", "repair chunk 200", "repair finish 200",
		"repair bad_request", "repair unknown_device", "repair bad_repair", "repair repair_busy", "repair invalid_record", "repair uncovered_stub", "repair too_large",
	} {
		if !have[need] {
			return fmt.Errorf("no case with %s", need)
		}
	}
	return nil
}

// statusWant is the short form of a status case result.
func statusWant(c statusJ) string {
	if c.Error != nil {
		return "error:" + *c.Error
	}
	rep := "null"
	if c.TipInLog != nil {
		rep = fmt.Sprint(*c.TipInLog)
	}
	return fmt.Sprintf("hold:%v reported:%s", c.Response.Hold, rep)
}

// replayStatus runs a status case on a copy of sp and returns the case with
// the result fields of the reference relay.
func replayStatus(sp *space, c statusJ, keyid string, at int64) statusJ {
	st := sp.clone()
	st.hold = c.Hold
	hold, code := st.status(keyid, at, c.Body)
	out := statusJ{Name: c.Name, Signer: c.Signer, Hold: c.Hold, Body: c.Body}
	if code != "" {
		out.Error = ptr(code)
	} else {
		out.Response = &statusRespJ{hold}
	}
	if rep, ok := st.reported(keyid); ok {
		out.TipInLog = ptr(rep)
	}
	return out
}

// stepWant is the short form of a repair step result.
func stepWant(s repairStepJ) string {
	switch {
	case s.Error != nil:
		return fmt.Sprintf("%d %s", s.Status, *s.Error)
	case s.Head != nil:
		return fmt.Sprintf("%d head %d", s.Status, s.Head.Position)
	case s.Next != nil:
		return fmt.Sprintf("%d next %d", s.Status, *s.Next)
	}
	return fmt.Sprintf("%d", s.Status)
}

// replayRepair runs the steps of a repair case on the reference relay, from
// positions 1..log_prefix of envs. It keeps route, signer, at and body, and
// takes every other field from the reference relay.
func replayRepair(envs []string, logID string, c repairJ, keys map[string]*party, lim limitsJ, mut string) (repairJ, error) {
	out := repairJ{Name: c.Name, LogPrefix: c.LogPrefix, Hold: c.Hold, Log: []string{}}
	if c.LogPrefix < 1 || c.LogPrefix > len(envs) {
		return out, fmt.Errorf("log_prefix %d out of range", c.LogPrefix)
	}
	if len(c.Steps) == 0 {
		return out, fmt.Errorf("no steps")
	}
	sp, err := newSpaceFromEnvelopes(logID, envs[:c.LogPrefix])
	if err != nil {
		return out, err
	}
	sp.hold = c.Hold
	sp.mut = mut
	session := ""
	for i, s := range c.Steps {
		sg := keys[s.Signer]
		if sg == nil {
			return out, fmt.Errorf("step %d: unknown signer", i+1)
		}
		if strings.Contains(s.Body, "{{session}}") && session == "" {
			return out, fmt.Errorf("step %d: {{session}} before a start that returned 201", i+1)
		}
		body := strings.ReplaceAll(s.Body, "{{session}}", session)
		var rp repairReply
		switch s.Route {
		case "start":
			rp = sp.repairStart(sg.idText, s.At, body, lim)
		case "chunk":
			rp = sp.repairChunk(sg.idText, s.At, body, lim)
		case "finish":
			rp = sp.repairFinish(sg.idText, s.At, body, lim)
		default:
			return out, fmt.Errorf("step %d: route %q", i+1, s.Route)
		}
		ns := repairStepJ{Route: s.Route, Signer: s.Signer, At: s.At, Body: s.Body, Status: rp.status}
		switch {
		case rp.code != "":
			ns.Error = ptr(rp.code)
		case s.Route == "finish":
			ns.Head = &headJ{rp.head, hx(sp.digestAt(rp.head))}
		default:
			ns.Next = ptr(rp.next)
		}
		if s.Route == "start" && rp.status == 201 {
			session = rp.session
		}
		out.Steps = append(out.Steps, ns)
	}
	for _, e := range sp.entries {
		out.Log = append(out.Log, hx(e.rh))
	}
	return out, nil
}

// enrollWant is the short form of an enroll step result.
func enrollWant(s enrollStepJ) string {
	if s.Error != nil {
		return fmt.Sprintf("%d %s", s.Status, *s.Error)
	}
	m, _ := s.Response.(map[string]any)
	if _, ok := m["state"]; !ok {
		return fmt.Sprintf("%d expires %v", s.Status, m["expires"])
	}
	slots := func(w string) string {
		o, _ := m[w].(map[string]any)
		var names []string
		for _, x := range enrollSlots {
			writer, name, _ := strings.Cut(x, ".")
			if _, ok := o[name]; ok && writer == w {
				names = append(names, name)
			}
		}
		return strings.Join(names, ",")
	}
	return fmt.Sprintf("%d %v n:%s t:%s", s.Status, m["state"], slots("new"), slots("trusted"))
}

var (
	openPathRe    = regexp.MustCompile(`^/v1/t/(t_[0-9a-f]{32})/s/(l_[0-9a-f]{32})/enroll$`)
	trustedPathRe = regexp.MustCompile(`^/v1/t/(t_[0-9a-f]{32})/s/(l_[0-9a-f]{32})/enroll/(e_[0-9a-f]{32})$`)
	newPathRe     = regexp.MustCompile(`^/v1/e/(e_[0-9a-f]{32})$`)
)

// replayEnroll runs the steps of an enroll case on the reference relay, from
// the whole space log envs with no session. It keeps route, signer, at,
// method, path, body and digest_body, and takes every other field from the
// reference relay.
func replayEnroll(envs []string, logID, tenant string, c enrollCaseJ, keys map[string]*party, mut string) (enrollCaseJ, error) {
	out := enrollCaseJ{Name: c.Name}
	if len(c.Steps) == 0 {
		return out, fmt.Errorf("no steps")
	}
	sp, err := newSpaceFromEnvelopes(logID, envs)
	if err != nil {
		return out, err
	}
	er := &enrollRelay{sp: sp, tenant: tenant, sessions: map[string]*enrollSession{}, mut: mut}
	var last int64
	for i, s := range c.Steps {
		fail := func(f string, a ...any) (enrollCaseJ, error) {
			return out, fmt.Errorf("step %d: %s", i+1, fmt.Sprintf(f, a...))
		}
		if s.At < last {
			return fail("relay time goes back")
		}
		last = s.At
		signed := s.Route == "open" || strings.HasPrefix(s.Route, "trusted_")
		method := "POST"
		if strings.HasSuffix(s.Route, "_read") {
			method = "GET"
		}
		if s.Method != method || (method == "GET" && s.Body != "") {
			return fail("method %s or body does not fit route %s", s.Method, s.Route)
		}
		var m []string
		switch s.Route {
		case "open":
			m = openPathRe.FindStringSubmatch(s.Path)
		case "trusted_read", "trusted_write":
			m = trustedPathRe.FindStringSubmatch(s.Path)
		case "new_read", "new_write":
			m = newPathRe.FindStringSubmatch(s.Path)
		default:
			return fail("route %q", s.Route)
		}
		if m == nil || (signed && (m[1] != tenant || m[2] != logID)) {
			return fail("path %q does not fit route %s", s.Path, s.Route)
		}
		rq := enrollReq{route: s.Route, session: m[len(m)-1], body: s.Body, at: s.At, digestOK: s.DigestBody == nil}
		if s.Route == "open" {
			rq.session = ""
		}
		if signed {
			sg := keys[s.Signer]
			if sg == nil {
				return fail("unknown signer %q", s.Signer)
			}
			rq.keyid = sg.idText
			if s.DigestBody != nil && *s.DigestBody == s.Body {
				return fail("digest_body equals body")
			}
		} else if s.Signer != "" || s.DigestBody != nil {
			return fail("unsigned route with a signer or digest_body")
		}
		rp := er.handle(rq)
		ns := enrollStepJ{Route: s.Route, Signer: s.Signer, At: s.At, Method: s.Method, Path: s.Path, Body: s.Body, DigestBody: s.DigestBody, Status: rp.status}
		if rp.code != "" {
			ns.Error = ptr(rp.code)
		} else {
			ns.Response = rp.body
		}
		out.Steps = append(out.Steps, ns)
	}
	return out, nil
}

// replayQuota runs an append_quota case on a copy of sp with the quota of the
// case. It keeps name, signer, quota and body, and takes used, the results and
// the head from the reference relay.
func replayQuota(sp *space, c quotaJ, keyid string, lim limitsJ) (quotaJ, error) {
	st := sp.clone()
	st.quota = c.Quota
	out := quotaJ{Name: c.Name, Signer: c.Signer, Quota: c.Quota, Used: st.used, Body: c.Body}
	if c.Quota < 1 {
		return out, fmt.Errorf("quota %d", c.Quota)
	}
	res, err := st.appendBatch(keyid, c.Body, lim)
	if err != nil {
		return out, err
	}
	for _, r := range res {
		out.Results = append(out.Results, resultJOf(r))
	}
	n := len(st.entries)
	out.Head = headJ{n, hx(st.digestAt(n))}
	return out, nil
}
