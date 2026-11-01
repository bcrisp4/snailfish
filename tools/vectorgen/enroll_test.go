package main

import (
	"strings"
	"testing"
)

func testEnroll(t *testing.T) (*enrollJ, *world) {
	t.Helper()
	w, err := newWorld()
	if err != nil {
		t.Fatal(err)
	}
	e, err := buildEnroll(w)
	if err != nil {
		t.Fatal(err)
	}
	return e, w
}

// 11.2 reads the first 8 bytes of digits as a big-endian integer. A
// little-endian or 4-byte reading gives another code.
func TestEnrollCodeReduction(t *testing.T) {
	for _, tc := range []struct {
		digits string
		code   string
	}{
		{"00000000000f4240" + strings.Repeat("ff", 24), "000000"},
		{"ffffffffffffffff" + strings.Repeat("00", 24), "551615"},
		{"0000000000000007" + strings.Repeat("ab", 24), "000007"},
		{"0100000000000000" + strings.Repeat("00", 24), "927936"},
	} {
		if got := codeOf(unhex(tc.digits)); got != tc.code {
			t.Errorf("digits %s: code %s, want %s", tc.digits[:16], got, tc.code)
		}
	}
}

// A file with a wrong derived value or a wrong verdict must fail -check.
func TestEnrollCheckRefusesTamperedFile(t *testing.T) {
	e, w := testEnroll(t)
	if err := checkEnrollOracle(e, w); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	for name, edit := range map[string]func(e *enrollJ){
		"code":          func(e *enrollJ) { e.Transcripts[0].Code = "000000" },
		"commitment":    func(e *enrollJ) { e.Transcripts[1].Commitment = e.Transcripts[2].Commitment },
		"symbols":       func(e *enrollJ) { e.Codes[0].Symbols = e.Codes[1].Symbols },
		"payload role":  func(e *enrollJ) { e.Codes[0].PayloadT = e.Codes[0].PayloadN },
		"typed session": func(e *enrollJ) { e.Typed.Valid[0].Session = e.Codes[1].Session },
		"invalid typed": func(e *enrollJ) { e.Typed.Invalid[0].Text = e.Codes[0].Display },
		"invalid payload": func(e *enrollJ) {
			e.Payloads.Invalid[0].Text = e.Codes[0].PayloadT
		},
		"confirm verdict": func(e *enrollJ) { e.Confirmations[len(e.Confirmations)-1].Valid = true },
		"confirm rule":    func(e *enrollJ) { e.Confirmations[2].Rule = "11.2" },
	} {
		c, _ := testEnroll(t)
		edit(c)
		if err := checkEnrollOracle(c, w); err == nil {
			t.Errorf("%s: tampered file passes", name)
		}
	}
}

// The trusted device must refuse a confirmation for another transcript, and
// a reader must refuse a session code with the recovery key check label.
func TestEnrollCrossChecks(t *testing.T) {
	e, _ := testEnroll(t)
	if err := acceptConfirm(e.Confirmations[0].Envelope, e.Transcripts[1]); err == nil {
		t.Error("confirmation accepted for another transcript")
	}
	if _, err := parseSessionCode(e.Typed.Invalid[1].Text); err == nil || e.Typed.Invalid[1].Name != "recovery-check-label" {
		t.Errorf("recovery check label: %v", err)
	}
	if _, err := parseRecoveryKey(e.Typed.Invalid[1].Text); err != nil {
		t.Errorf("the recovery-check-label case is not a valid recovery key text: %v", err)
	}
}
