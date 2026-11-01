package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

// This file builds the M5 parts of vectors/http.json: token texts (PROTOCOL.md
// 2.2), sign-in (12.2, 12.3), space creation with a setup token (10.5), device
// status (10.11) and webhooks (12.5). Each expected value is written by hand
// and asserted against the reference of setupref.go.

type tokenCaseJ struct {
	Name  string  `json:"name"`
	Kind  string  `json:"kind"`
	Text  string  `json:"text"`
	Valid bool    `json:"valid"`
	Hash  *string `json:"hash"`
}

type pkceValidJ struct {
	Name      string `json:"name"`
	Verifier  string `json:"verifier"`
	Challenge string `json:"challenge"`
}

type pkceInvalidJ struct {
	Name     string `json:"name"`
	Verifier string `json:"verifier"`
}

type pkceJ struct {
	Valid   []pkceValidJ   `json:"valid"`
	Invalid []pkceInvalidJ `json:"invalid"`
}

type textCaseJ struct {
	Name  string `json:"name"`
	Text  string `json:"text"`
	Valid bool   `json:"valid"`
}

type setupCodeJ struct {
	Code        string `json:"code"`
	Challenge   string `json:"challenge"`
	RedirectURI string `json:"redirect_uri"`
	Tenant      string `json:"tenant"`
	Expires     int64  `json:"expires"`
	Used        bool   `json:"used"`
}

type setupRespJ struct {
	Tenant  string `json:"tenant"`
	Expires int64  `json:"expires"`
}

type setupTokenJ struct {
	Name     string      `json:"name"`
	Signer   string      `json:"signer"`
	Body     string      `json:"body"`
	Headers  [][2]string `json:"headers"`
	Status   int         `json:"status"`
	Response *setupRespJ `json:"response"`
	Error    *string     `json:"error"`
}

type heldTokenJ struct {
	Token   string `json:"token"`
	Device  string `json:"device"`
	Tenant  string `json:"tenant"`
	Expires int64  `json:"expires"`
}

type putJ struct {
	Name   string  `json:"name"`
	Signer string  `json:"signer"`
	Path   string  `json:"path"`
	Body   string  `json:"body"`
	Exists string  `json:"existing"`
	Status int     `json:"status"`
	Head   *headJ  `json:"head"`
	Error  *string `json:"error"`
}

type quotaJ struct {
	Name    string    `json:"name"`
	Signer  string    `json:"signer"`
	Quota   int64     `json:"quota"`
	Used    int64     `json:"used"`
	Body    string    `json:"body"`
	Results []resultJ `json:"results"`
	Head    headJ     `json:"head"`
}

type deviceStatusJ struct {
	Name  string  `json:"name"`
	Body  string  `json:"body"`
	Error *string `json:"error"`
}

type webhookMsgJ struct {
	Text string `json:"text"`
	Body string `json:"body"`
}

type webhookJ struct {
	Allowlist []string      `json:"allowlist"`
	URLs      []textCaseJ   `json:"urls"`
	Messages  []webhookMsgJ `json:"messages"`
}

const (
	rfcVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" // RFC 7636 appendix B
	signinURI    = "http://127.0.0.1:49152/callback"
)

func tokenText(kind, name string) string {
	return tokenPrefix[kind] + hx(testSeed("token-"+kind, name))
}

func verifierFor(name string) string {
	return strings.TrimRight(b64url(testSeed("verifier", name)), "=")
}

func b64url(b []byte) string { return strings.NewReplacer("+", "-", "/", "_").Replace(b64(b)) }

// textCases asserts the hand-written verdict of each case against check.
func textCases(section string, cases []textCaseJ, check func(string) error) ([]textCaseJ, error) {
	for _, c := range cases {
		if err := check(c.Text); (err == nil) != c.Valid {
			return nil, fmt.Errorf("%s %s: reference gives %v, expected valid %v", section, c.Name, err, c.Valid)
		}
	}
	return cases, nil
}

// buildSetup writes the M5 sections of http.json. It runs after the space,
// so h.Space and h.Tenant are set.
func buildSetup(h *httpJ, b *logBuilder, w *world) error {
	now := int64(httpNow)
	var err error

	// ---- token texts (2.2, 12.1 to 12.3) ----
	hex64 := hx(testSeed("token-setup", "1"))
	for _, c := range []struct {
		name, kind, text string
		valid            bool
	}{
		{"invite", "invite", tokenText("invite", "1"), true},
		{"code", "code", tokenText("code", "1"), true},
		{"setup", "setup", tokenText("setup", "1"), true},
		{"setup-all-zero", "setup", "st_" + strings.Repeat("0", 64), true},
		{"setup-with-code-prefix", "setup", "ac_" + hex64, false},
		{"code-with-invite-prefix", "code", "it_" + hex64, false},
		{"invite-with-setup-prefix", "invite", "st_" + hex64, false},
		{"setup-uppercase-hex", "setup", "st_" + strings.ToUpper(hex64), false},
		{"setup-uppercase-prefix", "setup", "ST_" + hex64, false},
		{"setup-63-digits", "setup", "st_" + hex64[:63], false},
		{"setup-65-digits", "setup", "st_" + hex64 + "0", false},
		{"setup-no-prefix", "setup", hex64, false},
		{"setup-non-hex", "setup", "st_" + hex64[:63] + "g", false},
	} {
		th, e := tokenHash(c.text, c.kind)
		if (e == nil) != c.valid {
			return fmt.Errorf("token %s: reference gives %v", c.name, e)
		}
		tc := tokenCaseJ{Name: c.name, Kind: c.kind, Text: c.text, Valid: c.valid}
		if c.valid {
			tc.Hash = ptr(hx(th))
		}
		h.Tokens = append(h.Tokens, tc)
	}

	// ---- PKCE (12.2) ----
	if challengeOf(rfcVerifier) != rfcChallenge {
		return fmt.Errorf("pkce: RFC 7636 appendix B challenge differs")
	}
	full := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	v128 := (full + full)[:128]
	for _, c := range []struct{ name, v string }{
		{"rfc7636-appendix-b", rfcVerifier},
		{"engine-form-43", verifierFor("engine")},
		{"128-every-character", v128},
	} {
		if checkVerifier(c.v) != nil {
			return fmt.Errorf("pkce %s: verifier refused", c.name)
		}
		h.PKCE.Valid = append(h.PKCE.Valid, pkceValidJ{c.name, c.v, challengeOf(c.v)})
	}
	for _, c := range []struct{ name, v string }{
		{"42-characters", rfcVerifier[:42]},
		{"129-characters", v128 + "a"},
		{"empty", ""},
		{"plus", rfcVerifier[:42] + "+"},
		{"padding", rfcVerifier + "="},
		{"slash", rfcVerifier[:42] + "/"},
	} {
		if checkVerifier(c.v) == nil {
			return fmt.Errorf("pkce %s: verifier accepted", c.name)
		}
		h.PKCE.Invalid = append(h.PKCE.Invalid, pkceInvalidJ{c.name, c.v})
	}

	// ---- redirect URIs (12.2) ----
	long := func(n int) string {
		p := "http://127.0.0.1:8080/"
		return p + strings.Repeat("a", n-len(p))
	}
	if h.RedirectURIs, err = textCases("redirect_uri", []textCaseJ{
		{"loopback-v4", signinURI, true},
		{"loopback-v6", "http://[::1]:49152/callback", true},
		{"loopback-port-1", "http://127.0.0.1:1/", true},
		{"loopback-port-65535", "http://127.0.0.1:65535/cb", true},
		{"loopback-percent-encoded", "http://127.0.0.1:8080/a%2Fb", true},
		{"private-use", "com.example.tasks:/callback", true},
		{"private-use-empty-path", "com.example.tasks:/", true},
		{"private-use-scheme-characters", "com.example-app+v2.x:/oauth/cb", true},
		{"512-bytes", long(512), true},
		{"513-bytes", long(513), false},
		{"port-0", "http://127.0.0.1:0/cb", false},
		{"port-leading-zero", "http://127.0.0.1:08080/cb", false},
		{"port-65536", "http://127.0.0.1:65536/cb", false},
		{"no-port", "http://127.0.0.1/cb", false},
		{"no-path", "http://127.0.0.1:8080", false},
		{"localhost", "http://localhost:8080/cb", false},
		{"other-loopback-address", "http://127.0.0.2:8080/cb", false},
		{"https-loopback", "https://127.0.0.1:8080/cb", false},
		{"query", "http://127.0.0.1:8080/cb?x=1", false},
		{"fragment", "http://127.0.0.1:8080/cb#x", false},
		{"user-part", "http://user@127.0.0.1:8080/cb", false},
		{"scheme-without-dot", "myapp:/cb", false},
		{"uppercase-scheme", "Com.example.tasks:/cb", false},
		{"scheme-starts-with-digit", "1com.example:/cb", false},
		{"private-use-authority", "com.example.app://host/cb", false},
		{"percent-lowercase-hex", "http://127.0.0.1:8080/a%2fb", false},
		{"percent-not-hex", "http://127.0.0.1:8080/a%G1", false},
		{"percent-truncated", "http://127.0.0.1:8080/a%2", false},
		{"bad-path-character", "http://127.0.0.1:8080/cb!", false},
	}, checkRedirectURI); err != nil {
		return err
	}

	// ---- state (12.2) ----
	if h.States, err = textCases("state", []textCaseJ{
		{"one-character", "a", true},
		{"every-character-class", "AZaz09-._~", true},
		{"128-characters", strings.Repeat("s", 128), true},
		{"empty", "", false},
		{"129-characters", strings.Repeat("s", 129), false},
		{"space", "a b", false},
		{"plus", "a+b", false},
		{"percent", "a%41", false},
	}, checkState); err != nil {
		return err
	}

	// ---- authorize queries (12.2) ----
	challenge := challengeOf(rfcVerifier)
	qv := func(kv ...string) string {
		var parts []string
		for i := 0; i < len(kv); i += 2 {
			parts = append(parts, kv[i]+"="+kv[i+1])
		}
		return strings.Join(parts, "&")
	}
	enc := url.QueryEscape
	std := func(over ...string) string {
		vals := []string{"response_type", "code", "code_challenge", challenge, "code_challenge_method", "S256",
			"redirect_uri", enc(signinURI), "state", "xyz"}
		for i := 0; i < len(over); i += 2 {
			found := false
			for j := 0; j < len(vals); j += 2 {
				if vals[j] == over[i] {
					vals[j+1], found = over[i+1], true
				}
			}
			if !found {
				panic("no parameter " + over[i])
			}
		}
		return qv(vals...)
	}
	// The last symbol of a 43-symbol base64url text holds 2 unused bits.
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	nonCanon := challenge[:42] + string(alpha[strings.IndexByte(alpha, challenge[42])|1])
	if h.Authorize, err = textCases("authorize", []textCaseJ{
		{"valid", std(), true},
		{"valid-other-order", qv("state", "xyz", "redirect_uri", enc(signinURI), "code_challenge_method", "S256", "code_challenge", challenge, "response_type", "code"), true},
		{"valid-private-use", std("redirect_uri", enc("com.example.tasks:/callback")), true},
		{"valid-percent-in-path", std("redirect_uri", enc("http://127.0.0.1:8080/a%2Fb")), true},
		{"missing-state", qv("response_type", "code", "code_challenge", challenge, "code_challenge_method", "S256", "redirect_uri", enc(signinURI)), false},
		{"duplicate-state", std() + "&state=xyz", false},
		{"extra-parameter", std() + "&scope=openid", false},
		{"parameter-without-value", std() + "&scope", false},
		{"response-type-token", std("response_type", "token"), false},
		{"method-plain", std("code_challenge_method", "plain"), false},
		{"challenge-42-characters", std("code_challenge", challenge[:42]), false},
		{"challenge-non-canonical", std("code_challenge", nonCanon), false},
		{"challenge-padded", std("code_challenge", challenge+"%3D"), false},
		{"redirect-localhost", std("redirect_uri", enc("http://localhost:8080/cb")), false},
		{"redirect-encoded-twice", std("redirect_uri", enc(enc(signinURI))), false},
		{"state-empty", std("state", ""), false},
		{"state-plus-is-space", std("state", "a+b"), false},
	}, checkAuthorize); err != nil {
		return err
	}

	// ---- setup token requests (12.3) ----
	C, A := w.C, w.A
	codeOK, codeUsed, codeExpired := tokenText("code", "ok"), tokenText("code", "used"), tokenText("code", "expired")
	verifier := verifierFor("signin")
	h.SetupCodes = []setupCodeJ{
		{codeOK, challengeOf(verifier), signinURI, h.Tenant, now + 30, false},
		{codeUsed, challengeOf(verifier), signinURI, h.Tenant, now + 30, true},
		{codeExpired, challengeOf(verifier), signinURI, h.Tenant, now, false},
	}
	tokBody := func(code, ver, redirect, device string) string {
		return obj("code", q(code), "code_verifier", q(ver), "redirect_uri", q(redirect), "device", device)
	}
	okBody := tokBody(codeOK, verifier, signinURI, keysRaw(C))
	shortSeal := obj("sign", q(b64(C.signPk)), "seal", q(b64(C.sealPk[:1215])))
	type tc struct {
		name   string
		signer *party
		body   string
		digest string // the text whose digest the headers carry, "" for the body
		extra  [][2]string
		want   string // "200" or "<status> <code>"
	}
	for _, c := range []tc{
		{"exchange", C, okBody, "", nil, "200"},
		{"extra-field", C, okBody[:len(okBody)-1] + `,"x":1}`, "", nil, "400 bad_request"},
		{"missing-field", C, obj("code", q(codeOK), "code_verifier", q(verifier), "device", keysRaw(C)), "", nil, "400 bad_request"},
		{"duplicate-key", C, `{"code":"` + codeOK + `",` + okBody[1:], "", nil, "400 bad_request"},
		{"nested-duplicate-key", C, tokBody(codeOK, verifier, signinURI, keysRaw(C)[:len(keysRaw(C))-1]+`,"sign":"`+b64(C.signPk)+`"}`), "", nil, "400 bad_request"},
		{"verifier-42-characters", C, tokBody(codeOK, verifier[:42], signinURI, keysRaw(C)), "", nil, "400 bad_request"},
		{"verifier-bad-character", C, tokBody(codeOK, verifier[:42]+"+", signinURI, keysRaw(C)), "", nil, "400 bad_request"},
		{"redirect-uri-breaks-12-2", C, tokBody(codeOK, verifier, "http://localhost:49152/callback", keysRaw(C)), "", nil, "400 bad_request"},
		{"code-uppercase-hex", C, tokBody("ac_"+strings.ToUpper(codeOK[3:]), verifier, signinURI, keysRaw(C)), "", nil, "400 bad_request"},
		{"seal-1215-bytes", C, tokBody(codeOK, verifier, signinURI, shortSeal), "", nil, "400 bad_request"},
		{"bad-digest-before-body", C, `{"code":`, okBody, nil, "400 bad_digest"},
		{"keyid-not-device", A, okBody, "", nil, "403 unknown_device"},
		{"cookie-header", C, okBody, "", [][2]string{{"cookie", "sf_session=x"}}, "400 bad_request"},
		{"unknown-code", C, tokBody(tokenText("code", "unknown"), verifier, signinURI, keysRaw(C)), "", nil, "403 bad_setup"},
		{"used-code", C, tokBody(codeUsed, verifier, signinURI, keysRaw(C)), "", nil, "403 bad_setup"},
		{"code-at-expiry", C, tokBody(codeExpired, verifier, signinURI, keysRaw(C)), "", nil, "403 bad_setup"},
		{"other-redirect-uri", C, tokBody(codeOK, verifier, "http://127.0.0.1:49153/callback", keysRaw(C)), "", nil, "403 bad_setup"},
		{"redirect-uri-other-encoding", C, tokBody(codeOK, verifier, "http://127.0.0.1:49152/c%61llback", keysRaw(C)), "", nil, "403 bad_setup"},
		{"other-verifier", C, tokBody(codeOK, verifierFor("other"), signinURI, keysRaw(C)), "", nil, "403 bad_setup"},
	} {
		sg := newSigned(c.name, c.signer, "POST", httpAuthority, setupPath, "", c.body, now, now+300, nonceFor("setup-"+c.name))
		hdr := sg.Headers
		if c.digest != "" {
			hdr = newSigned(c.name, c.signer, "POST", httpAuthority, setupPath, "", c.digest, now, now+300, nonceFor("setup-"+c.name)).Headers
		}
		hdr = append(append([][2]string{}, hdr...), c.extra...)
		st := setupTokenJ{Name: c.name, Signer: c.signer.name, Body: c.body, Headers: hdr}
		got := replaySetupToken(h, st, "")
		if g := setupWant(got); g != c.want {
			return fmt.Errorf("setup_token %s: reference gives %q, expected %q", c.name, g, c.want)
		}
		h.SetupToken = append(h.SetupToken, got)
	}

	// ---- PUT with a setup token (10.5) ----
	tokA := tokenText("setup", "A")
	h.SetupTokens = []heldTokenJ{
		{tokA, "A", h.Tenant, now + 600},
		{tokenText("setup", "B"), "B", h.Tenant, now + 600},
		{tokenText("setup", "A-other-tenant"), "A", "t_" + hx(testSeed("tenant", "other")[:16]), now + 600},
		{tokenText("setup", "A-expired"), "A", h.Tenant, now},
	}
	gen := h.Space.Genesis
	putBody := func(genesis, setup string) string { return `{"genesis":` + genesis + `,"setup":"` + setup + `"}` }
	gf := splitFields(string(b.payload[1]))
	otherGen, _, _ := signEnv(w.R1, "snailfish.genesis.v1", gf.set("device", deviceRaw(w.A, "Laptop 2", 2)).render())
	spacePath := "/v1/t/" + h.Tenant + "/s/" + h.LogID
	otherLogPath := "/v1/t/" + h.Tenant + "/s/l_" + hx(testSeed("log", "other")[:16])
	type pc struct {
		name   string
		signer *party
		path   string
		body   string
		exists string
		want   string
	}
	for _, c := range []pc{
		{"create", A, spacePath, putBody(gen, tokA), "", "201"},
		{"exact-retry-unknown-token", A, spacePath, putBody(gen, tokenText("setup", "unknown")), gen, "200"},
		{"exact-retry-expired-token", A, spacePath, putBody(gen, tokenText("setup", "A-expired")), gen, "200"},
		{"other-genesis-exists", A, spacePath, putBody(otherGen, tokA), gen, "409 space_exists"},
		{"missing-setup", A, spacePath, `{"genesis":` + gen + `}`, "", "400 bad_request"},
		{"setup-uppercase-hex", A, spacePath, putBody(gen, "st_"+strings.ToUpper(tokA[3:])), "", "400 bad_request"},
		{"setup-code-prefix", A, spacePath, putBody(gen, "ac_"+tokA[3:]), "", "400 bad_request"},
		{"setup-not-string", A, spacePath, `{"genesis":` + gen + `,"setup":1}`, "", "400 bad_request"},
		{"extra-field", A, spacePath, `{"genesis":` + gen + `,"setup":"` + tokA + `","x":1}`, "", "400 bad_request"},
		{"genesis-not-envelope", A, spacePath, putBody(`{"payloadType":"snailfish.genesis.v1","payload":"AA==","signatures":[]}`, tokA), "", "422 invalid_record"},
		{"genesis-string", A, spacePath, `{"genesis":"x","setup":"` + tokA + `"}`, "", "422 invalid_record"},
		{"duplicate-setup", A, spacePath, `{"genesis":` + gen + `,"setup":"` + tokA + `","setup":"` + tokA + `"}`, "", "400 bad_request"},
		{"unknown-token", A, spacePath, putBody(gen, tokenText("setup", "unknown")), "", "403 bad_setup"},
		{"token-of-other-device", A, spacePath, putBody(gen, tokenText("setup", "B")), "", "403 bad_setup"},
		{"token-of-other-tenant", A, spacePath, putBody(gen, tokenText("setup", "A-other-tenant")), "", "403 bad_setup"},
		{"token-at-expiry", A, spacePath, putBody(gen, tokenText("setup", "A-expired")), "", "403 bad_setup"},
		{"signer-not-genesis-device", w.B, spacePath, putBody(gen, tokenText("setup", "B")), "", "403 unknown_device"},
		{"genesis-of-other-log", A, otherLogPath, putBody(gen, tokA), "", "422 invalid_record"},
	} {
		pj := putJ{Name: c.name, Signer: c.signer.name, Path: c.path, Body: c.body, Exists: c.exists}
		got := replayPut(h, pj, w, "")
		if g := putWant(got); g != c.want {
			return fmt.Errorf("put %s: reference gives %q, expected %q", c.name, g, c.want)
		}
		h.Put = append(h.Put, got)
	}

	// ---- device status (10.11) ----
	ds := func(state, outbox, oldest, applied, epoch string) string {
		return obj("state", state, "outbox", outbox, "oldest", oldest, "applied", applied, "epoch", epoch)
	}
	for _, c := range []struct {
		name, body string
		valid      bool
	}{
		{"ok", ds(`"ok"`, "0", "null", "4", "1"), true},
		{"outbox-with-oldest", ds(`"paused: quota"`, "2", "1767225000", "12", "1"), true},
		{"state-64-bytes", ds(q(strings.Repeat("x", 64)), "0", "null", "0", "1"), true},
		{"state-space-and-tilde", ds(`" ~"`, "0", "null", "0", "1"), true},
		{"other-key-order", `{"epoch":1,"applied":0,"oldest":null,"outbox":0,"state":"ok"}`, true},
		{"state-empty", ds(`""`, "0", "null", "0", "1"), false},
		{"state-65-bytes", ds(q(strings.Repeat("x", 65)), "0", "null", "0", "1"), false},
		{"state-control-byte", ds(`"ok\u0007"`, "0", "null", "0", "1"), false},
		{"state-delete-byte", ds(`"ok\u007f"`, "0", "null", "0", "1"), false},
		{"state-non-ascii", ds(`"ok é"`, "0", "null", "0", "1"), false},
		{"oldest-null-with-outbox", ds(`"ok"`, "1", "null", "0", "1"), false},
		{"oldest-set-with-empty-outbox", ds(`"ok"`, "0", "1767225000", "0", "1"), false},
		{"oldest-missing", obj("state", `"ok"`, "outbox", "0", "applied", "0", "epoch", "1"), false},
		{"epoch-0", ds(`"ok"`, "0", "null", "0", "0"), false},
		{"extra-field", ds(`"ok"`, "0", "null", "0", "1")[:len(ds(`"ok"`, "0", "null", "0", "1"))-1] + `,"x":1}`, false},
		{"outbox-negative", ds(`"ok"`, "-1", "1767225000", "0", "1"), false},
		{"applied-negative", ds(`"ok"`, "0", "null", "-1", "1"), false},
		{"applied-fraction", ds(`"ok"`, "0", "null", "1.5", "1"), false},
		{"applied-1.0", ds(`"ok"`, "0", "null", "1.0", "1"), false},
		{"outbox-string", ds(`"ok"`, `"0"`, "null", "0", "1"), false},
		{"duplicate-key", `{"state":"ok","state":"ok","outbox":0,"oldest":null,"applied":0,"epoch":1}`, false},
	} {
		if (checkDeviceStatus(c.body) == nil) != c.valid {
			return fmt.Errorf("device_status %s: reference gives %v", c.name, checkDeviceStatus(c.body))
		}
		h.DeviceStatus = append(h.DeviceStatus, deviceStatusOf(c.name, c.body))
	}

	// ---- webhooks (12.5) ----
	h.Webhook.Allowlist = []string{"hooks.example.com", "192.0.2.10", "::1"}
	wlong := func(n int) string {
		p := "https://hooks.example.com/"
		return p + strings.Repeat("a", n-len(p))
	}
	allow := func(u string) error { return checkWebhook(u, h.Webhook.Allowlist) }
	if h.Webhook.URLs, err = textCases("webhook", []textCaseJ{
		{"https", "https://hooks.example.com/services/T000/B000/XXXX", true},
		{"http-ip-literal-port", "http://192.0.2.10:8080/hook", true},
		{"root-path", "https://hooks.example.com/", true},
		{"512-bytes", wlong(512), true},
		{"513-bytes", wlong(513), false},
		{"host-not-on-list", "https://evil.example.net/hook", false},
		{"subdomain-not-on-list", "https://a.hooks.example.com/hook", false},
		{"uppercase-host", "https://HOOKS.example.com/hook", false},
		{"user-part", "https://user@hooks.example.com/hook", false},
		{"fragment", "https://hooks.example.com/hook#x", false},
		{"ftp-scheme", "ftp://hooks.example.com/hook", false},
		{"no-path", "https://hooks.example.com", false},
		{"port-0", "https://hooks.example.com:0/hook", false},
		{"query", "https://hooks.example.com/hook?token=abc&x=1", true},
		{"https-default-port", "https://hooks.example.com:443/hook", true},
		{"http-default-port", "http://192.0.2.10:80/hook", true},
		{"port-65535", "https://hooks.example.com:65535/hook", true},
		{"port-65536", "https://hooks.example.com:65536/hook", false},
		{"port-leading-zero", "https://hooks.example.com:0443/hook", false},
		{"ipv6-literal", "http://[::1]:9000/h", true},
		{"ipv6-not-shortest", "http://[::01]:9000/h", false},
		{"ipv6-full-form", "http://[0:0:0:0:0:0:0:1]:9000/h", false},
		{"ipv6-without-brackets", "http://::1:9000/h", false},
		{"target-space", "https://hooks.example.com/a b", false},
		{"target-backslash", "https://hooks.example.com/a\\b", false},
	}, allow); err != nil {
		return err
	}
	for _, t := range []string{
		`Snailfish: device "Sam's phone" in com.example.tasks is stalled: no sync for 7 days.`,
		"Snailfish: space com.example.tasks is at 80% of its quota.",
		"back\\slash, tab\tand new\nline",
		"non-ASCII: café, 東京, 🐌",
	} {
		h.Webhook.Messages = append(h.Webhook.Messages, webhookMsgJ{t, webhookBody(t)})
	}
	return nil
}

func setupWant(c setupTokenJ) string {
	if c.Error != nil {
		return fmt.Sprintf("%d %s", c.Status, *c.Error)
	}
	return fmt.Sprint(c.Status)
}

func putWant(c putJ) string {
	if c.Error != nil {
		return fmt.Sprintf("%d %s", c.Status, *c.Error)
	}
	return fmt.Sprint(c.Status)
}

// replaySetupToken runs one setup_token case on the reference relay. It keeps
// name, signer, body and headers, and takes the result from the reference.
func replaySetupToken(h *httpJ, c setupTokenJ, mut string) setupTokenJ {
	rs := &relayState{authority: h.Authority, now: h.Now, used: map[[2]string]bool{}, mut: mut}
	status, resp, code := rs.setupToken(request{"POST", setupPath, "", c.Body, c.Headers}, h.SetupCodes)
	out := setupTokenJ{Name: c.Name, Signer: c.Signer, Body: c.Body, Headers: c.Headers, Status: status, Response: resp}
	if code != "" {
		out.Error = ptr(code)
	}
	return out
}

func replayPut(h *httpJ, c putJ, w *world, mut string) putJ {
	devices := map[string]string{}
	for _, d := range h.Devices {
		devices[d.Name] = d.ID
	}
	keyid := devices[c.Signer]
	status, head, code := putSpace(keyid, c.Path, c.Body, c.Exists, h.SetupTokens, devices, h.Now, mut)
	out := putJ{Name: c.Name, Signer: c.Signer, Path: c.Path, Body: c.Body, Exists: c.Exists, Status: status, Head: head}
	if code != "" {
		out.Error = ptr(code)
	}
	return out
}

func deviceStatusOf(name, body string) deviceStatusJ {
	d := deviceStatusJ{Name: name, Body: body}
	if checkDeviceStatus(body) != nil {
		d.Error = ptr("bad_request")
	}
	return d
}

// checkSetup verifies the M5 sections of http.json with the reference. It
// does not trust any derived field of the file.
func checkSetup(h *httpJ, w *world, mut string) error {
	for _, c := range h.Tokens {
		if _, ok := tokenPrefix[c.Kind]; !ok {
			return fmt.Errorf("tokens %s: kind %q", c.Name, c.Kind)
		}
		th, err := tokenHash(c.Text, c.Kind)
		want := tokenCaseJ{Name: c.Name, Kind: c.Kind, Text: c.Text, Valid: err == nil}
		if err == nil {
			want.Hash = ptr(hx(th))
		}
		if e := compare("tokens "+c.Name, c, want); e != nil {
			return e
		}
	}
	if len(h.PKCE.Valid) == 0 || h.PKCE.Valid[0].Verifier != rfcVerifier || h.PKCE.Valid[0].Challenge != rfcChallenge {
		return fmt.Errorf("pkce: the first valid case is not RFC 7636 appendix B")
	}
	for _, c := range h.PKCE.Valid {
		if checkVerifier(c.Verifier) != nil || challengeOf(c.Verifier) != c.Challenge || checkChallenge(c.Challenge) != nil {
			return fmt.Errorf("pkce %s: verifier or challenge differs from the reference", c.Name)
		}
	}
	for _, c := range h.PKCE.Invalid {
		if checkVerifier(c.Verifier) == nil {
			return fmt.Errorf("pkce %s: the reference accepts the verifier", c.Name)
		}
	}
	for _, sec := range []struct {
		name  string
		cases []textCaseJ
		check func(string) error
	}{
		{"redirect_uris", h.RedirectURIs, checkRedirectURI},
		{"states", h.States, checkState},
		{"authorize", h.Authorize, checkAuthorize},
		{"webhook", h.Webhook.URLs, func(u string) error { return checkWebhook(u, h.Webhook.Allowlist) }},
	} {
		for _, c := range sec.cases {
			if (sec.check(c.Text) == nil) != c.Valid {
				return fmt.Errorf("%s %s: the reference gives valid %v", sec.name, c.Name, !c.Valid)
			}
		}
	}
	for _, c := range h.SetupToken {
		if err := compare("setup_token "+c.Name, c, replaySetupToken(h, c, mut)); err != nil {
			return err
		}
	}
	for _, c := range h.Put {
		if err := compare("put "+c.Name, c, replayPut(h, c, w, mut)); err != nil {
			return err
		}
	}
	for _, c := range h.DeviceStatus {
		if err := compare("device_status "+c.Name, c, deviceStatusOf(c.Name, c.Body)); err != nil {
			return err
		}
	}
	for _, m := range h.Webhook.Messages {
		var got map[string]any
		if err := json.Unmarshal([]byte(m.Body), &got); err != nil || len(got) != 1 || got["text"] != m.Text {
			return fmt.Errorf("webhook message %q: body does not decode to the text", m.Text)
		}
		// Every non-ASCII character is UTF-8 in the body, not a \u escape.
		for _, r := range m.Text {
			if r >= utf8.RuneSelf && !strings.ContainsRune(m.Body, r) {
				return fmt.Errorf("webhook message %q: %q is escaped", m.Text, r)
			}
		}
		if m.Body != webhookBody(m.Text) {
			return fmt.Errorf("webhook message %q: body differs from the reference", m.Text)
		}
	}
	// every required witness must occur
	have := map[string]bool{}
	for _, c := range h.SetupToken {
		have["setup_token "+setupWant(c)] = true
	}
	for _, c := range h.Put {
		have["put "+putWant(c)] = true
	}
	for _, need := range []string{
		"setup_token 200", "setup_token 400 bad_request", "setup_token 403 unknown_device", "setup_token 403 bad_setup",
		"put 201", "put 200", "put 400 bad_request", "put 403 bad_setup", "put 409 space_exists",
	} {
		if !have[need] {
			return fmt.Errorf("no case with %s", need)
		}
	}
	return nil
}
