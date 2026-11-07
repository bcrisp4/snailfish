package main

// Export file vectors (PROTOCOL.md section 15). The cases come from the
// committed log of protocol.json, so each run writes the same bytes. The
// reader below is a second implementation of section 15: the form checks,
// the genesis record at position 1 and the digest chain. The Rust reader
// also runs the full chain check of 10.13.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type exportCase struct {
	Name      string `json:"name"`
	File      string `json:"file"`
	ValidForm bool   `json:"valid_form"`
	ValidLog  bool   `json:"valid_log"`
}

type exportJ struct {
	Version int          `json:"version"`
	Cases   []exportCase `json:"cases"`
}

// exportEntries is the number of protocol.json log entries in a valid file:
// genesis, grant, change, snapshot, accept. All are level 1 records.
const exportEntries = 5

func exportHeader(logID, app string, pos int, digest []byte) string {
	return fmt.Sprintf(`{"type":"snailfish.export.v1","log":"%s","app":"%s","head":{"position":%d,"digest":"%s"}}`,
		logID, app, pos, b64(digest))
}

func envLine(pos int, env string) string {
	return fmt.Sprintf(`{"position":%d,"envelope":%s}`, pos, env)
}

func stubLine(e entryJ) (string, error) {
	rh, err := hex.DecodeString(e.RecordHash)
	if err != nil {
		return "", err
	}
	if e.ChangeID != "" {
		return fmt.Sprintf(`{"position":%d,"stub":{"type":"%s","change_id":"c_%s","hash":"%s"}}`,
			e.Position, e.PayloadType, e.ChangeID, b64(rh)), nil
	}
	return fmt.Sprintf(`{"position":%d,"stub":{"type":"%s","hash":"%s"}}`, e.Position, e.PayloadType, b64(rh)), nil
}

func joinLines(lines []string) string { return strings.Join(lines, "\n") + "\n" }

func buildExport(p *protocolJ) (*exportJ, error) {
	es := p.Log.Entries
	if len(es) < exportEntries {
		return nil, errors.New("protocol.json log is too short")
	}
	last, err := hex.DecodeString(es[exportEntries-1].Digest)
	if err != nil {
		return nil, err
	}
	head := exportHeader(p.Log.LogID, p.Log.App, exportEntries, last)
	body := make([]string, exportEntries)
	for i := 0; i < exportEntries; i++ {
		body[i] = envLine(es[i].Position, es[i].Envelope)
	}
	full := append([]string{head}, body...)
	stub3, err := stubLine(es[2])
	if err != nil {
		return nil, err
	}
	stub4, err := stubLine(es[3])
	if err != nil {
		return nil, err
	}
	with := func(i int, line string) []string {
		out := append([]string{}, full...)
		out[i] = line
		return out
	}
	without := func(i int) []string {
		out := append([]string{}, full[:i]...)
		return append(out, full[i+1:]...)
	}
	d4, err := hex.DecodeString(es[3].Digest)
	if err != nil {
		return nil, err
	}
	tampered := strings.Replace(es[2].Envelope, `"payload":"`, `"payload":"A`, 1)
	cases := []exportCase{
		{"full", joinLines(full), true, true},
		{"change-and-snapshot-stubs", joinLines([]string{head, body[0], body[1], stub3, stub4, body[4]}), true, true},
		{"head-digest-wrong", joinLines(with(0, exportHeader(p.Log.LogID, p.Log.App, exportEntries, d4))), true, false},
		{"head-position-short", joinLines(with(0, exportHeader(p.Log.LogID, p.Log.App, exportEntries-1, d4))), false, false},
		{"gap", joinLines(without(3)), false, false},
		{"no-final-lf", strings.TrimSuffix(joinLines(full), "\n"), false, false},
		{"empty-line", strings.Replace(joinLines(full), "\n", "\n\n", 1), false, false},
		{"header-unknown-field", joinLines(with(0, strings.Replace(head, `"app":`, `"x":1,"app":`, 1))), false, false},
		{"header-duplicate-key", joinLines(with(0, strings.Replace(head, `"app":`, `"app":"x","app":`, 1))), false, false},
		{"header-type-v2", joinLines(with(0, strings.Replace(head, "export.v1", "export.v2", 1))), false, false},
		{"header-wrong-app", joinLines(with(0, strings.Replace(head, p.Log.App, "com.example.other", 1))), true, false},
		{"entry-unknown-field", joinLines(with(2, strings.Replace(body[1], `{"position":2,`, `{"position":2,"x":1,`, 1))), false, false},
		{"entry-envelope-and-stub", joinLines(with(3, strings.TrimSuffix(envLine(3, es[2].Envelope), "}")+`,"stub":`+strings.SplitN(stub3, `"stub":`, 2)[1])), false, false},
		{"first-not-genesis", joinLines(append([]string{head}, envLine(1, es[1].Envelope), body[1], body[2], body[3], body[4])), true, false},
		{"tampered-payload", joinLines(with(3, envLine(3, tampered))), true, false},
	}
	return &exportJ{Version: 1, Cases: cases}, nil
}

// readExport is the section 15 reader. formErr is a form fault, logErr a
// fault of the genesis record or the digest chain.
func readExport(file string) (formErr, logErr error) {
	if !strings.HasSuffix(file, "\n") {
		return errors.New("no final LF"), nil
	}
	lines := strings.Split(strings.TrimSuffix(file, "\n"), "\n")
	for _, l := range lines {
		if l == "" {
			return errors.New("empty line"), nil
		}
	}
	hv, err := parseStrict([]byte(lines[0]))
	if err != nil {
		return fmt.Errorf("header: %w", err), nil
	}
	hr := newReader(hv, "type", "log", "app", "head")
	typ := hr.str("type")
	_, logID := hr.id("log", "l_", 16)
	app := hr.str("app")
	head := hr.pos("head", 1)
	if hr.err != nil {
		return fmt.Errorf("header: %w", hr.err), nil
	}
	if typ != "snailfish.export.v1" {
		return errors.New("header: type"), nil
	}
	type item struct {
		pos  int64
		env  string
		stub map[string]any
	}
	var items []item
	for i, l := range lines[1:] {
		var raw map[string]json.RawMessage
		dec := json.NewDecoder(strings.NewReader(l))
		if err := dec.Decode(&raw); err != nil {
			return fmt.Errorf("entry %d: %w", i+1, err), nil
		}
		for k := range raw {
			if k != "position" && k != "envelope" && k != "stub" {
				return fmt.Errorf("entry %d: unknown field %q", i+1, k), nil
			}
		}
		var pos int64
		if err := json.Unmarshal(raw["position"], &pos); err != nil {
			return fmt.Errorf("entry %d: position", i+1), nil
		}
		if pos != int64(i+1) {
			return fmt.Errorf("entry %d: position %d", i+1, pos), nil
		}
		env, hasEnv := raw["envelope"]
		st, hasStub := raw["stub"]
		if hasEnv == hasStub {
			return fmt.Errorf("entry %d: one of envelope and stub", i+1), nil
		}
		it := item{pos: pos}
		if hasEnv {
			it.env = string(env)
		} else if err := json.Unmarshal(st, &it.stub); err != nil {
			return fmt.Errorf("entry %d: stub", i+1), nil
		}
		items = append(items, it)
	}
	if int64(len(items)) != head.n {
		return errors.New("last position differs from head.position"), nil
	}
	// Genesis at position 1, signed by its recovery key, with the header log and app.
	if items[0].env == "" {
		return nil, errors.New("position 1 is a stub")
	}
	g, err := parseEnvelope(items[0].env)
	if err != nil || g.ptype != "snailfish.genesis.v1" {
		return nil, errors.New("position 1 is not a genesis envelope")
	}
	gv, err := parseStrict(g.payload)
	if err != nil {
		return nil, err
	}
	gm, _ := gv.(map[string]any)
	rec, _ := gm["recovery"].(map[string]any)
	signB64, _ := rec["sign"].(string)
	signPk, err := decodeB64(signB64)
	if err != nil || len(signPk) != 32 || !ed25519.Verify(signPk, pae(g.ptype, g.payload), g.sig) {
		return nil, errors.New("genesis signature")
	}
	if gm["log"] != "l_"+hex.EncodeToString(logID) || gm["app"] != app {
		return nil, errors.New("genesis log or app differs from the header")
	}
	d := sha(frame(s("snailfish.log-root.v1"), logID))
	for _, it := range items {
		var eh []byte
		if it.env != "" {
			e, err := parseEnvelope(it.env)
			if err != nil {
				return nil, err
			}
			var cid []byte
			if e.ptype == "snailfish.change.v1" {
				pv, err := parseStrict(e.payload)
				if err != nil {
					return nil, err
				}
				pm, _ := pv.(map[string]any)
				t, _ := pm["change_id"].(string)
				if cid, err = decodeID(t, "c_", 16); err != nil {
					return nil, err
				}
			}
			eh = entryHash(e.ptype, cid, recordHash(e.ptype, e.payload, e.sig))
		} else {
			typ, _ := it.stub["type"].(string)
			hs, _ := it.stub["hash"].(string)
			rh, err := decodeB64(hs)
			if err != nil || len(rh) != 32 {
				return nil, errors.New("stub hash")
			}
			var cid []byte
			if t, ok := it.stub["change_id"].(string); ok {
				if cid, err = decodeID(t, "c_", 16); err != nil {
					return nil, err
				}
			}
			eh = entryHash(typ, cid, rh)
		}
		d = digestN(d, int(it.pos), eh)
	}
	if !bytes.Equal(d, head.d) {
		return nil, errors.New("last digest differs from head.digest")
	}
	return nil, nil
}

func checkExport(p *protocolJ, e *exportJ) error {
	rebuilt, err := buildExport(p)
	if err != nil {
		return err
	}
	if err := compare("export.json", e, rebuilt); err != nil {
		return err
	}
	for _, c := range e.Cases {
		formErr, logErr := readExport(c.File)
		if (formErr == nil) != c.ValidForm {
			return fmt.Errorf("export case %s: form verdict %v, want %v", c.Name, formErr, c.ValidForm)
		}
		if formErr == nil && (logErr == nil) != c.ValidLog {
			return fmt.Errorf("export case %s: log verdict %v, want %v", c.Name, logErr, c.ValidLog)
		}
	}
	return nil
}
