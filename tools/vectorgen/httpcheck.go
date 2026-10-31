package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
)

// checkHTTP verifies http.json with the reference relay of httpref.go. It does
// not trust any derived field of the file.
func checkHTTP(h *httpJ, w *world) error {
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
		if code := r.verifyRequest(request{c.Method, c.Path, c.Query, c.Body, c.Headers}); code != "" {
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
	for _, c := range h.Fetch {
		pos, head, more := sp.fetch(c.After, c.Limit)
		if c.Limit < 1 || c.Limit > h.Limits.MaxFetchEntries {
			return fmt.Errorf("fetch %s: limit out of range", c.Name)
		}
		if fmt.Sprint(pos) != fmt.Sprint(c.Positions) || head != c.Head || more != c.HasMore {
			return fmt.Errorf("fetch %s: reference gives %v head %d more %v", c.Name, pos, head, more)
		}
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
