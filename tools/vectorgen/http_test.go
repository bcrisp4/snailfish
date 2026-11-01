package main

import (
	"bytes"
	"strings"
	"testing"
)

func testHTTP(t *testing.T) (*httpJ, *world) {
	t.Helper()
	w, err := newWorld()
	if err != nil {
		t.Fatal(err)
	}
	fixed := func(entry, index int, pk, info, pt []byte) ([]byte, error) {
		return append(bytes.Repeat([]byte{1}, 1120), make([]byte, len(pt)+16)...), nil
	}
	h, err := buildHTTP(w, fixed)
	if err != nil {
		t.Fatal(err)
	}
	return h, w
}

func relayOf(t *testing.T, h *httpJ) *relayState {
	t.Helper()
	var envs []string
	for _, e := range h.Space.Log {
		envs = append(envs, e.Envelope)
	}
	sp, err := newSpaceFromEnvelopes(h.LogID, envs)
	if err != nil {
		t.Fatal(err)
	}
	used := map[[2]string]bool{}
	for _, u := range h.UsedNonces {
		used[u] = true
	}
	return &relayState{authority: h.Authority, now: h.Now, space: sp, used: used}
}

func TestHTTPSignedCasesPass(t *testing.T) {
	h, _ := testHTTP(t)
	rs := relayOf(t, h)
	for _, c := range h.Signed {
		r := *rs
		r.authority = c.Authority
		if code := r.verifyRequest(request{c.Method, c.Path, c.Query, c.Body, c.Headers}); code != "" {
			t.Errorf("%s: %s", c.Name, code)
		}
	}
}

func TestHTTPInvalidCasesFailWithTheNamedCheck(t *testing.T) {
	h, _ := testHTTP(t)
	rs := relayOf(t, h)
	codes := map[string]bool{}
	for _, c := range h.Invalid {
		if got := rs.verifyRequest(request{c.Method, c.Path, c.Query, c.Body, c.Headers}); got != c.Error {
			t.Errorf("%s: got %q want %q", c.Name, got, c.Error)
		}
		codes[c.Error] = true
	}
	for _, e := range []string{"bad_signature", "expired", "bad_digest", "unknown_device", "nonce_reused", "wrong_authority"} {
		if !codes[e] {
			t.Errorf("no case for %s", e)
		}
	}
}

func TestHTTPVerifierRefusesMutations(t *testing.T) {
	h, _ := testHTTP(t)
	rs := relayOf(t, h)
	c := h.Signed[0]
	ok := func(hd [][2]string, body, query string) string {
		return rs.verifyRequest(request{c.Method, c.Path, query, body, hd})
	}
	if got := ok(c.Headers, c.Body, c.Query); got != "" {
		t.Fatalf("base case: %s", got)
	}
	if got := ok(c.Headers, c.Body, c.Query+"&x=1"); got != "bad_signature" {
		t.Errorf("query change: %q", got)
	}
	if got := ok(c.Headers, "x", c.Query); got != "bad_digest" {
		t.Errorf("body change: %q", got)
	}
	if got := ok(withHdr(c.Headers, "snailfish-authority", "evil.example"), c.Body, c.Query); got != "wrong_authority" {
		t.Errorf("authority: %q", got)
	}
	if got := ok(append(append([][2]string{}, c.Headers...), c.Headers[0]), c.Body, c.Query); got != "bad_signature" {
		t.Errorf("duplicate header: %q", got)
	}
	// case-insensitive header names, case-sensitive values
	up := append([][2]string{}, c.Headers...)
	up[0][0] = "Content-Digest"
	if got := ok(up, c.Body, c.Query); got != "" {
		t.Errorf("header name case: %q", got)
	}
	// a used nonce is refused only after the signature verifies
	rs.used[[2]string{h.UsedNonces[0][0], c.Nonce}] = true
	if got := ok(c.Headers, c.Body, c.Query); got != "nonce_reused" {
		t.Errorf("nonce: %q", got)
	}
}

func TestHTTPAppendOrder(t *testing.T) {
	h, _ := testHTTP(t)
	for _, c := range h.Append {
		switch c.Name {
		case "known-before-not-author":
			if c.Results[0].Status != "known" {
				t.Errorf("known must win over not_author: %+v", c.Results[0])
			}
		case "author-not-request-signer":
			if c.Results[0].Error == nil || *c.Results[0].Error != "not_author" {
				t.Errorf("want not_author: %+v", c.Results[0])
			}
		case "too-large-change":
			if c.Results[0].Error == nil || *c.Results[0].Error != "too_large" {
				t.Errorf("want too_large: %+v", c.Results[0])
			}
		}
		if strings.HasPrefix(c.Name, "new-") && c.Head.Position != 5 {
			t.Errorf("%s: head %d", c.Name, c.Head.Position)
		}
	}
}

func TestHTTPFetchHasMore(t *testing.T) {
	h, _ := testHTTP(t)
	rs := relayOf(t, h)
	for _, tc := range []struct {
		after, limit int
		n            int
		more         bool
	}{{0, 2, 2, true}, {0, 4, 4, false}, {2, 500, 2, false}, {4, 5, 0, false}} {
		pos, head, more, _ := rs.space.fetch(tc.after, tc.limit)
		if len(pos) != tc.n || more != tc.more || head != 4 {
			t.Errorf("after %d limit %d: %v %d %v", tc.after, tc.limit, pos, head, more)
		}
	}
}

// Each relay fault of the M3 and M4 rules must change the result of a named case, so
// a relay with the fault cannot pass the vectors.
func TestHTTPVectorsDetectRelayFaults(t *testing.T) {
	h, w := testHTTP(t)
	if err := checkHTTPWith(h, w, ""); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	for _, tc := range []struct{ mut, firstCase string }{
		{"no-hold", "append_hold change-on-hold"},
		{"hold-before-known", "append_hold exact-retry-on-hold"},
		{"no-stale-base", "append grant-stale-base"},
		{"stale-counts-changes", "append grant-base-before-change"},
		{"fetch-no-hold", "fetch hold-after-0-limit-2"},
		{"status-without-hold", "status no-hold"},
		{"reported-ignores-digest", "status hold-tip-other-digest"},
		{"chain-not-author", "repair one-start"},
		{"no-log12", "repair signer-granted-in-entries"},
		{"chain-allows-known", "repair known-change-id-in-entries"},
		{"stub-invalid-record", "repair stub"},
		{"no-tip-check", "repair wrong-tip"},
		{"no-busy", "repair second-device-busy"},
		{"no-expiry", "repair session-after-expiry"},
		{"expiry-from-start", "repair chunk-extends-session"},
		{"chunk-any-signer", "repair chunk-from-other-device"},
		{"no-allowance", "repair body-at-allowance"},
		{"recovery-not-author", "append recovery-grant"},
		{"recovery-skip-active", "append recovery-grant-not-current"},
		{"enroll-no-expiry", "enroll expiry"},
		{"enroll-retry-bytes", "enroll slot-exact-retry"},
		{"enroll-any-order", "enroll wrong-order"},
		{"enroll-trusted-any-device", "enroll trusted-route-other-device"},
		{"enroll-closed-before-retry", "enroll write-after-done"},
		{"enroll-open-retry-new-expires", "enroll open-exact-retry"},
		{"enroll-no-tenant-check", "enroll done-other-tenant"},
		{"enroll-body-before-digest", "enroll check-order"},
	} {
		err := checkHTTPWith(h, w, tc.mut)
		if err == nil {
			t.Errorf("%s: the vectors pass", tc.mut)
		} else if !strings.HasPrefix(err.Error(), tc.firstCase+":") {
			t.Errorf("%s: first failure is %q, want case %q", tc.mut, err, tc.firstCase)
		}
	}
}
