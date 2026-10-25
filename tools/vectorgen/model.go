package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

const appName = "com.example.tasks"

func hx(b []byte) string  { return hex.EncodeToString(b) }
func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// testSeed is the fixed-label seed rule of the task: SHA-256(frame(label, name, purpose)).
func testSeed(name, purpose string) []byte {
	return sha(frame(s("snailfish.test-seed.v1"), s(name), s(purpose)))
}

type party struct {
	name               string
	secret             []byte // recovery keys only
	signSeed, sealSeed []byte
	signPriv           ed25519.PrivateKey
	signPk, sealPk     []byte
	id                 []byte
	idText             string
	isRecovery         bool
}

func kem() hpke.KEM { return hpke.MLKEM768X25519() }

func sealPublic(sealSeed []byte) ([]byte, error) {
	k, err := kem().NewPrivateKey(sealSeed)
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

func newParty(name string, recovery bool, secret []byte) (*party, error) {
	p := &party{name: name, isRecovery: recovery, secret: secret}
	if recovery {
		prk, err := hkdf.Extract(sha256.New, secret, s("snailfish.recovery.v1"))
		if err != nil {
			return nil, err
		}
		if p.signSeed, err = hkdf.Expand(sha256.New, prk, "snailfish.recovery.sign.v1", 32); err != nil {
			return nil, err
		}
		if p.sealSeed, err = hkdf.Expand(sha256.New, prk, "snailfish.recovery.seal.v1", 32); err != nil {
			return nil, err
		}
	} else {
		p.signSeed, p.sealSeed = testSeed(name, "sign"), testSeed(name, "seal")
	}
	p.signPriv = ed25519.NewKeyFromSeed(p.signSeed)
	p.signPk = p.signPriv.Public().(ed25519.PublicKey)
	var err error
	if p.sealPk, err = sealPublic(p.sealSeed); err != nil {
		return nil, err
	}
	if len(p.sealPk) != 1216 {
		return nil, fmt.Errorf("seal pk has %d bytes", len(p.sealPk))
	}
	label, prefix := "snailfish.device-id.v1", "d_"
	if recovery {
		label, prefix = "snailfish.recovery-id.v1", "r_"
	}
	p.id = sha(frame(s(label), p.signPk, p.sealPk))
	p.idText = prefix + hx(p.id)
	return p, nil
}

func newRecoveryFromLabel(name string) (*party, error) {
	return newParty(name, true, testSeed(name, "recovery-secret")[:16])
}

// sealer makes the HPKE sealed value of one key set. Go hpke has no fixed ephemeral key.
type sealer func(entry, index int, pk, info, plaintext []byte) ([]byte, error)

func freshSealer(entry, index int, pk, info, plaintext []byte) ([]byte, error) {
	k, err := kem().NewPublicKey(pk)
	if err != nil {
		return nil, err
	}
	return hpke.Seal(k, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info, plaintext)
}

func keysetInfo(logID, recipient []byte, epochs []int) []byte {
	parts := [][]byte{s("snailfish.keyset.v1"), logID, recipient}
	for _, e := range epochs {
		parts = append(parts, u64(uint64(e)))
	}
	return frame(parts...)
}

func openKeySet(seed, info, sealed []byte) ([]byte, error) {
	k, err := kem().NewPrivateKey(seed)
	if err != nil {
		return nil, err
	}
	return hpke.Open(k, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info, sealed)
}

// ---- output types (field order is output order) ----

type frameJ struct {
	Parts []string `json:"parts"`
	Frame string   `json:"frame"`
}
type deviceJ struct {
	Name     string `json:"name"`
	SignSeed string `json:"sign_seed"`
	SealSeed string `json:"seal_seed"`
	SignPk   string `json:"sign_pk"`
	SealPk   string `json:"seal_pk"`
	ID       string `json:"id"`
}
type recoveryJ struct {
	Name     string `json:"name"`
	Secret   string `json:"secret"`
	Display  string `json:"display"`
	SignSeed string `json:"sign_seed"`
	SealSeed string `json:"seal_seed"`
	SignPk   string `json:"sign_pk"`
	SealPk   string `json:"seal_pk"`
	ID       string `json:"id"`
}
type entryJ struct {
	Position    int    `json:"position"`
	Name        string `json:"name"`
	PayloadType string `json:"payload_type"`
	Payload     string `json:"payload"`
	Envelope    string `json:"envelope"`
	Signer      string `json:"signer"`
	Sig         string `json:"sig"`
	RecordHash  string `json:"record_hash"`
	ChangeID    string `json:"change_id"`
	EntryHash   string `json:"entry_hash"`
	Digest      string `json:"digest"`
}
type logJ struct {
	LogID       string            `json:"log_id"`
	App         string            `json:"app"`
	Digest0     string            `json:"digest0"`
	AppKeys     map[string]string `json:"app_keys"`
	Commitments map[string]string `json:"commitments"`
	Entries     []entryJ          `json:"entries"`
}
type statementJ struct {
	Name        string `json:"name"`
	PayloadType string `json:"payload_type"`
	Payload     string `json:"payload"`
	Envelope    string `json:"envelope"`
	Signer      string `json:"signer"`
	Sig         string `json:"sig"`
	RecordHash  string `json:"record_hash"`
}
type keySetJ struct {
	Entry     int    `json:"entry"`
	Index     int    `json:"index"`
	To        string `json:"to"`
	Epochs    []int  `json:"epochs"`
	Info      string `json:"info"`
	Plaintext string `json:"plaintext"`
}
type cipherJ struct {
	Entry     int    `json:"entry"`
	AAD       string `json:"aad"`
	Nonce     string `json:"nonce"`
	Plaintext string `json:"plaintext"`
}
type envelopeJ struct {
	Name       string `json:"name"`
	Envelope   string `json:"envelope"`
	Valid      bool   `json:"valid"`
	RecordHash string `json:"record_hash"`
}
type protocolJ struct {
	Version     int          `json:"version"`
	Frames      []frameJ     `json:"frames"`
	Devices     []deviceJ    `json:"devices"`
	Recovery    []recoveryJ  `json:"recovery"`
	Log         logJ         `json:"log"`
	Statements  []statementJ `json:"statements"`
	KeySets     []keySetJ    `json:"key_sets"`
	Ciphertexts []cipherJ    `json:"ciphertexts"`
	Envelopes   []envelopeJ  `json:"envelopes"`
}

type strictCase struct {
	Name        string  `json:"name"`
	Rule        string  `json:"rule"`
	PayloadType string  `json:"payload_type"`
	Payload     *string `json:"payload"`
	PayloadHex  *string `json:"payload_hex"`
	Valid       bool    `json:"valid"`
}
type strictJ struct {
	Version int          `json:"version"`
	Cases   []strictCase `json:"cases"`
}
type recValid struct {
	Text   string `json:"text"`
	Secret string `json:"secret"`
}
type recInvalid struct {
	Name string `json:"name"`
	Text string `json:"text"`
}
type recoveryKeyJ struct {
	Version int          `json:"version"`
	Valid   []recValid   `json:"valid"`
	Invalid []recInvalid `json:"invalid"`
}

// ---- payload writing ----

func q(x string) string { return `"` + x + `"` }

func posRaw(n int, d []byte) string {
	return fmt.Sprintf(`{"position":%d,"digest":"%s"}`, n, b64(d))
}

func obj(kv ...string) string {
	var sb strings.Builder
	sb.WriteByte('{')
	for i := 0; i < len(kv); i += 2 {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(q(kv[i]) + ":" + kv[i+1])
	}
	sb.WriteByte('}')
	return sb.String()
}

func list(items ...string) string { return "[" + strings.Join(items, ",") + "]" }

func intList(e []int) string {
	var x []string
	for _, n := range e {
		x = append(x, fmt.Sprint(n))
	}
	return list(x...)
}

func keysRaw(p *party) string {
	return obj("sign", q(b64(p.signPk)), "seal", q(b64(p.sealPk)))
}

func deviceRaw(p *party, name string, level int) string {
	return obj("id", q(p.idText), "sign", q(b64(p.signPk)), "seal", q(b64(p.sealPk)),
		"name", q(name), "level", fmt.Sprint(level))
}

func commitment(logID []byte, epoch int, key []byte) []byte {
	return sha(frame(s("snailfish.key-commitment.v1"), logID, u64(uint64(epoch)), key))
}

// sortParties orders recipients by the bytes of their 32-byte ID (task instruction).
func sortParties(ps []*party) []*party {
	out := append([]*party{}, ps...)
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].id, out[j].id) < 0 })
	return out
}

func aeadSeal(key, nonce, aad, pt []byte) ([]byte, error) {
	c, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return append(append([]byte{}, nonce...), c.Seal(nil, nonce, pt, aad)...), nil
}

func envelopeJSON(ptype string, payload, sig []byte, keyid string) string {
	return fmt.Sprintf(`{"payloadType":%q,"payload":"%s","signatures":[{"keyid":"%s","sig":"%s"}]}`,
		ptype, b64(payload), keyid, b64(sig))
}

func recordHash(ptype string, payload, sig []byte) []byte {
	return sha(frame(s("snailfish.record-hash.v1"), s(ptype), payload, sig))
}

func entryHash(ptype string, changeID, rh []byte) []byte {
	return sha(frame(s("snailfish.entry-hash.v1"), s(ptype), changeID, rh))
}

func digestN(prev []byte, n int, eh []byte) []byte {
	return sha(frame(s("snailfish.log-digest.v1"), prev, u64(uint64(n)), eh))
}
