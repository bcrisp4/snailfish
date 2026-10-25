package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestFrameVector(t *testing.T) {
	got := hex.EncodeToString(frame([]byte("ab"), nil))
	want := "0000000000000002" + "6162" + "0000000000000000"
	if got != want {
		t.Fatalf("frame(ab, empty) = %s, want %s", got, want)
	}
}

func TestPAEVector(t *testing.T) {
	got := string(pae("http://example.com/HelloWorld", []byte("hello world")))
	want := "DSSEv1 29 http://example.com/HelloWorld 11 hello world"
	if got != want {
		t.Fatalf("PAE = %q, want %q", got, want)
	}
}

func TestCrockfordRoundTrip(t *testing.T) {
	for i := 0; i < 200; i++ {
		secret := testSeed("rt", string(rune('a'+i%26))+string(rune(i)))[:16]
		sym := recoverySymbols(secret)
		if len(sym) != 32 {
			t.Fatalf("got %d symbols", len(sym))
		}
		raw, err := crockfordDecode(sym)
		if err != nil || !bytes.Equal(raw, append(append([]byte{}, secret...), recoveryCheck(secret)...)) {
			t.Fatalf("round trip failed for %x: %v", secret, err)
		}
		back, err := parseRecoveryKey(recoveryDisplay(secret))
		if err != nil || !bytes.Equal(back, secret) {
			t.Fatalf("display round trip failed for %x: %v", secret, err)
		}
	}
}

func TestCrockfordKnown(t *testing.T) {
	// 5 bytes 0x00 0x44 0x32 0x14 0xC7 are the symbols 0 1 2 3 4 5 6 7 (RFC-style base32 grouping).
	if got := crockfordEncode([]byte{0x00, 0x44, 0x32, 0x14, 0xC7}); got != "01234567" {
		t.Fatalf("got %s", got)
	}
}

func TestSignPAEVerifies(t *testing.T) {
	p, err := newParty("T", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"a":1}`)
	sig := ed25519.Sign(p.signPriv, pae("snailfish.change.v1", body))
	if !ed25519.Verify(p.signPk, pae("snailfish.change.v1", body), sig) {
		t.Fatal("signature does not verify")
	}
	if ed25519.Verify(p.signPk, pae("snailfish.change.v2", body), sig) {
		t.Fatal("signature verifies under another payload type")
	}
}

func TestRecoveryReader(t *testing.T) {
	secret := testSeed("R", "recovery-secret")[:16]
	d := recoveryDisplay(secret)
	if _, err := parseRecoveryKey(d); err != nil {
		t.Fatal(err)
	}
	if _, err := parseRecoveryKey("U" + d[1:]); err == nil {
		t.Fatal("U accepted")
	}
}

func TestGenerateIsDeterministicExceptSealed(t *testing.T) {
	w, _ := newWorld()
	fixed := func(entry, index int, pk, info, pt []byte) ([]byte, error) {
		return append(bytes.Repeat([]byte{1}, 1120), make([]byte, len(pt)+16)...), nil
	}
	a, _, err := buildProtocol(w, fixed)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := buildProtocol(w, fixed)
	if err != nil {
		t.Fatal(err)
	}
	if err := compare("x", a, b); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRustAcceptsGoSealed(t *testing.T) {
	w, _ := newWorld()
	logID := w.logID
	pt := append(append([]byte{}, w.appKeys[1]...), w.appKeys[2]...)
	sealed, err := freshSealer(0, 0, w.R2.sealPk, keysetInfo(logID, w.R2.id, []int{1, 2}), pt)
	if err != nil {
		t.Fatal(err)
	}
	doc := `{"key_sets":[{"seal_seed":"` + hx(w.R2.sealSeed) + `","to":"` + w.R2.idText + `","log_id":"` + w.logIDText +
		`","epochs":[1,2],"sealed":"` + hx(sealed) + `","plaintext":"` + hx(pt) + `"}]}`
	path := t.TempDir() + "/r.json"
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runOpenRust(path); err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(doc, `"epochs":[1,2]`, `"epochs":[1]`, 1)
	if err := os.WriteFile(path, []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runOpenRust(path); err == nil {
		t.Fatal("wrong epochs (wrong info) opened")
	}
}
