package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// This file is the reference of the M5 rules: the token text forms of
// PROTOCOL.md 2.2, the sign-in rules of 12.2 and 12.3, the space creation of
// 10.5, the device status of 10.11 and the webhooks of 12.5.

const (
	setupPath     = "/v1/setup/token"
	setupTokenTTL = 600 // seconds after the token request (12.3 step 6)
	maxURIBytes   = 512 // redirect URI (12.2) and webhook URL (12.5)
)

// tokenPrefix is the text prefix of each 32-byte token kind of 2.2.
var tokenPrefix = map[string]string{"invite": "it_", "code": "ac_", "setup": "st_"}

// tokenHash is the stored value of a token (12.1, 12.2, 12.3): SHA-256 of
// the 32 token bytes, not of the text.
func tokenHash(text, kind string) ([]byte, error) {
	b, err := decodeID(text, tokenPrefix[kind], 32)
	if err != nil {
		return nil, err
	}
	return sha(b), nil
}

func unreserved(x string) bool {
	for i := 0; i < len(x); i++ {
		c := x[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("-._~", c) >= 0) {
			return false
		}
	}
	return true
}

// checkVerifier is the code_verifier rule of 12.2 (RFC 7636 section 4.1).
func checkVerifier(v string) error {
	if len(v) < 43 || len(v) > 128 || !unreserved(v) {
		return fmt.Errorf("code_verifier %q breaks 12.2", v)
	}
	return nil
}

// challengeOf is BASE64URL(SHA-256(ASCII(code_verifier))) without padding.
func challengeOf(v string) string { return base64.RawURLEncoding.EncodeToString(sha([]byte(v))) }

// checkChallenge accepts only the unpadded base64url text of 32 bytes, in its
// one canonical form.
func checkChallenge(c string) error {
	b, err := base64.RawURLEncoding.Strict().DecodeString(c)
	if err != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != c {
		return fmt.Errorf("code_challenge %q breaks 12.2", c)
	}
	return nil
}

func checkState(x string) error {
	if len(x) < 1 || len(x) > 128 || !unreserved(x) {
		return fmt.Errorf("state %q breaks 12.2", x)
	}
	return nil
}

var (
	loopbackRe   = regexp.MustCompile(`^http://(?:127\.0\.0\.1|\[::1\]):([0-9]+)(/.*)$`)
	privateUseRe = regexp.MustCompile(`^([a-z][a-z0-9+.\-]*):/(.*)$`)
)

// checkURIPath is the <path> character rule of 12.2.
func checkURIPath(p string) error {
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '%' {
			if i+2 >= len(p) || !isUpperHex(p[i+1]) || !isUpperHex(p[i+2]) {
				return errors.New("bad percent-encoding")
			}
			i += 2
			continue
		}
		if !unreserved(string(c)) && c != '/' {
			return fmt.Errorf("character %q in path", c)
		}
	}
	return nil
}

func isUpperHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'A' && c <= 'F' }

// checkRedirectURI is the redirect URI rule of 12.2, on the decoded URI.
func checkRedirectURI(u string) error {
	if len(u) > maxURIBytes {
		return fmt.Errorf("redirect URI has %d bytes", len(u))
	}
	if m := loopbackRe.FindStringSubmatch(u); m != nil {
		port, err := strconv.Atoi(m[1])
		if err != nil || m[1][0] == '0' || port < 1 || port > 65535 {
			return fmt.Errorf("port %q", m[1])
		}
		return checkURIPath(m[2])
	}
	m := privateUseRe.FindStringSubmatch(u)
	if m == nil {
		return fmt.Errorf("redirect URI %q has no form of 12.2", u)
	}
	if !strings.Contains(m[1], ".") {
		return fmt.Errorf("scheme %q has no dot", m[1])
	}
	if strings.HasPrefix(m[2], "/") {
		return errors.New("private-use path starts with /")
	}
	return checkURIPath(m[2])
}

// pctDecode decodes a query name or value once, as
// application/x-www-form-urlencoded (12.2): '+' is a space. It refuses a '%'
// without two hex digits.
func pctDecode(v string) (string, error) {
	var out []byte
	for i := 0; i < len(v); i++ {
		if v[i] == '+' {
			out = append(out, ' ')
			continue
		}
		if v[i] != '%' {
			out = append(out, v[i])
			continue
		}
		if i+2 >= len(v) {
			return "", errors.New("short percent-encoding")
		}
		n, err := strconv.ParseUint(v[i+1:i+3], 16, 8)
		if err != nil {
			return "", errors.New("bad percent-encoding")
		}
		out = append(out, byte(n))
		i += 2
	}
	return string(out), nil
}

var authorizeParams = []string{"response_type", "code_challenge", "code_challenge_method", "redirect_uri", "state"}

// checkAuthorize is the query rule of GET /u/authorize (12.2). query has no "?".
func checkAuthorize(query string) error {
	got := map[string]string{}
	for _, part := range strings.Split(query, "&") {
		rk, v, ok := strings.Cut(part, "=")
		if !ok {
			return fmt.Errorf("parameter %q has no value", part)
		}
		k, err := pctDecode(rk)
		if err != nil {
			return err
		}
		dv, err := pctDecode(v)
		if err != nil {
			return err
		}
		if _, dup := got[k]; dup {
			return fmt.Errorf("parameter %s occurs twice", k)
		}
		got[k] = dv
	}
	for _, k := range authorizeParams {
		if _, ok := got[k]; !ok {
			return fmt.Errorf("missing parameter %s", k)
		}
	}
	if len(got) != len(authorizeParams) {
		return errors.New("unknown parameter")
	}
	if got["response_type"] != "code" || got["code_challenge_method"] != "S256" {
		return errors.New("response_type or code_challenge_method")
	}
	if err := checkChallenge(got["code_challenge"]); err != nil {
		return err
	}
	if err := checkRedirectURI(got["redirect_uri"]); err != nil {
		return err
	}
	return checkState(got["state"])
}

// ---- POST /v1/setup/token (12.3) ----

type setupBody struct {
	code, verifier, redirect string
	deviceID                 string
	sign                     ed25519.PublicKey
}

// parseSetupBody is step 2 of 12.3.
func parseSetupBody(body string) (*setupBody, error) {
	v, err := parseStrict([]byte(body))
	if err != nil {
		return nil, err
	}
	r := newReader(v, "code", "code_verifier", "redirect_uri", "device")
	code, _ := r.id("code", "ac_", 32)
	verifier := r.str("code_verifier")
	redirect := r.str("redirect_uri")
	sign, seal, _ := keysObj(r, "device")
	if r.err != nil {
		return nil, r.err
	}
	if err := checkVerifier(verifier); err != nil {
		return nil, err
	}
	if err := checkRedirectURI(redirect); err != nil {
		return nil, err
	}
	id := "d_" + hx(sha(frame(s("snailfish.device-id.v1"), sign, seal)))
	return &setupBody{code, verifier, redirect, id, sign}, nil
}

// setupToken runs a token request of 12.3 against the codes that the relay
// holds. It returns the HTTP status and the error code or the response.
func (rs *relayState) setupToken(rq request, codes []setupCodeJ) (int, *setupRespJ, string) {
	fail := func(code string) (int, *setupRespJ, string) { return errStatus[code], nil, code }
	// 1
	pp, sig, code := rs.checkHeaders(rq)
	if code != "" {
		return fail(code)
	}
	// 2
	sb, err := parseSetupBody(rq.body)
	if err != nil {
		return fail("bad_request")
	}
	// 3: step 5 accepts only the device of the body.
	if pp.keyid != sb.deviceID && rs.mut != "setup-any-keyid" {
		return fail("unknown_device")
	}
	if code := rs.checkSignature(rq, pp, sig, sb.sign); code != "" {
		return fail(code)
	}
	// 4
	var held *setupCodeJ
	for i := range codes {
		if codes[i].Code == sb.code {
			held = &codes[i]
		}
	}
	if held == nil || held.Used || (rs.now >= held.Expires && rs.mut != "setup-expiry-after") {
		return fail("bad_setup")
	}
	// 5
	if sb.redirect != held.RedirectURI || (challengeOf(sb.verifier) != held.Challenge && rs.mut != "setup-no-pkce") {
		return fail("bad_setup")
	}
	// 6
	return 200, &setupRespJ{held.Tenant, rs.now + setupTokenTTL}, ""
}

// verifySetupRequest is 12.3 steps 1 to 3, for a signed case on the setup route.
func (rs *relayState) verifySetupRequest(rq request) string {
	pp, sig, code := rs.checkHeaders(rq)
	if code != "" {
		return code
	}
	sb, err := parseSetupBody(rq.body)
	if err != nil {
		return "bad_request"
	}
	if pp.keyid != sb.deviceID {
		return "unknown_device"
	}
	return rs.checkSignature(rq, pp, sig, sb.sign)
}

// ---- PUT /v1/t/{tenant}/s/{log} (10.5) ----

var spacePathRe = regexp.MustCompile(`^/v1/t/(t_[0-9a-f]{32})/s/(l_[0-9a-f]{32})$`)

// putSpace is 10.5 after 8.6 steps 1 to 4. keyid is the request signer.
// existing is the genesis envelope of the space, or "" if no space exists.
func putSpace(keyid, path, body, existing string, tokens []heldTokenJ, devices map[string]string, now int64, mut string) (int, *headJ, string) {
	fail := func(code string) (int, *headJ, string) { return errStatus[code], nil, code }
	m := spacePathRe.FindStringSubmatch(path)
	if m == nil {
		return fail("bad_request")
	}
	tenant, logText := m[1], m[2]
	lv, err := parseLenient([]byte(body))
	top, ok := lv.(map[string]any)
	if err != nil || !ok || len(top) != 2 || top["genesis"] == nil {
		return fail("bad_request")
	}
	setup, ok := top["setup"].(string)
	if !ok {
		return fail("bad_request")
	}
	if _, err := decodeID(setup, "st_", 32); err != nil && mut != "put-setup-any-text" {
		return fail("bad_request")
	}
	genesis, err := rawField(body, "genesis", "")
	if err != nil {
		return fail("bad_request")
	}
	sp, err := newSpaceFromEnvelopes(logText, []string{genesis})
	if err != nil {
		return fail("invalid_record")
	}
	// 8.6 step 5: the device of the genesis record.
	if sp.active[keyid] == nil {
		return fail("unknown_device")
	}
	head := &headJ{1, hx(sp.digestAt(1))}
	if existing != "" {
		old, err := newSpaceFromEnvelopes(logText, []string{existing})
		if err != nil {
			return fail("internal")
		}
		// 1
		if bytes.Equal(old.entries[0].rh, sp.entries[0].rh) {
			return 200, head, ""
		}
		// 2
		return fail("space_exists")
	}
	// 3
	h, _ := tokenHash(setup, "setup")
	var held *heldTokenJ
	for i := range tokens {
		if th, _ := tokenHash(tokens[i].Token, "setup"); bytes.Equal(th, h) {
			held = &tokens[i]
		}
	}
	if held == nil || (now >= held.Expires && mut != "put-expiry-after") || devices[held.Device] != keyid ||
		(held.Tenant != tenant && mut != "put-any-tenant") {
		return fail("bad_setup")
	}
	// 6
	return 201, head, ""
}

// ---- POST /v1/t/{tenant}/s/{log}/device-status (10.11) ----

func checkDeviceStatus(body string) error {
	v, err := parseStrict([]byte(body))
	if err != nil {
		return err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return errors.New("not an object")
	}
	oldest, hasOldest := m["oldest"]
	if !hasOldest {
		return errors.New("missing field oldest")
	}
	rest := map[string]any{}
	for k, x := range m {
		if k != "oldest" {
			rest[k] = x
		}
	}
	r := newReader(rest, "state", "outbox", "applied", "epoch")
	st := r.str("state")
	outbox := r.num("outbox", 0, maxInt)
	r.num("applied", 0, maxInt)
	r.num("epoch", 1, maxInt)
	if r.err != nil {
		return r.err
	}
	if len(st) < 1 || len(st) > 64 {
		return fmt.Errorf("state has %d bytes", len(st))
	}
	for i := 0; i < len(st); i++ {
		if st[i] < 0x20 || st[i] > 0x7e {
			return fmt.Errorf("state byte %#x is not printable ASCII", st[i])
		}
	}
	if oldest != nil {
		n, ok := oldest.(int64)
		if !ok || n < 0 {
			return errors.New("oldest is not an integer from 0")
		}
	}
	if (oldest == nil) != (outbox == 0) {
		return errors.New("oldest must be null exactly when outbox is 0")
	}
	return nil
}

// ---- webhooks (12.5) ----

var (
	webhookRe     = regexp.MustCompile(`^https?://(\[[^\]]*\]|[^/:\[\]]*)(?::([0-9]+))?(/.*)$`)
	domainRe      = regexp.MustCompile(`^[a-z0-9.\-]+$`)
	ipv4LiteralRe = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){3}$`)
)

// checkWebhook is the URL rule of 12.5 with the allowlist of the relay.
func checkWebhook(u string, allow []string) error {
	if len(u) > maxURIBytes {
		return fmt.Errorf("URL has %d bytes", len(u))
	}
	m := webhookRe.FindStringSubmatch(u)
	if m == nil {
		return fmt.Errorf("URL %q breaks 12.5", u)
	}
	host := m[1]
	switch {
	case strings.HasPrefix(host, "["):
		inner := host[1 : len(host)-1]
		a, err := netip.ParseAddr(inner)
		if err != nil || !a.Is6() || a.Zone() != "" || a.String() != inner {
			return fmt.Errorf("IPv6 literal %q is not in its shortest lowercase form", inner)
		}
		host = inner
	case ipv4LiteralRe.MatchString(host):
		a, err := netip.ParseAddr(host)
		if err != nil || !a.Is4() {
			return fmt.Errorf("IPv4 literal %q", host)
		}
	case !domainRe.MatchString(host):
		return fmt.Errorf("host %q", host)
	}
	if m[2] != "" {
		port, err := strconv.Atoi(m[2])
		if err != nil || m[2][0] == '0' || port < 1 || port > 65535 {
			return fmt.Errorf("port %q", m[2])
		}
	}
	for i := 0; i < len(m[3]); i++ {
		c := m[3][i]
		if c < 0x21 || c > 0x7e || strings.IndexByte("#\"<>\\^`{|}", c) >= 0 {
			return fmt.Errorf("byte %#x in the target", c)
		}
	}
	for _, h := range allow {
		if h == host {
			return nil
		}
	}
	return fmt.Errorf("host %q is not in the allowlist", host)
}

// webhookBody is the message body of 12.5. It escapes '"', '\' and the
// control characters, and writes every other character as UTF-8.
func webhookBody(text string) string {
	var sb strings.Builder
	sb.WriteString(`{"text":"`)
	for _, c := range text {
		switch {
		case c == '"':
			sb.WriteString(`\"`)
		case c == '\\':
			sb.WriteString(`\\`)
		case c == '\n':
			sb.WriteString(`\n`)
		case c == '\r':
			sb.WriteString(`\r`)
		case c == '\t':
			sb.WriteString(`\t`)
		case c < 0x20:
			fmt.Fprintf(&sb, `\u%04x`, c)
		default:
			sb.WriteRune(c)
		}
	}
	sb.WriteString(`"}`)
	return sb.String()
}
