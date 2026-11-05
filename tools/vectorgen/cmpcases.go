package main

// The compaction cases of http.json: PROTOCOL.md section 14 through the
// append and repair routes. Each case starts from space.log. Each step is an
// append request, a cut of the relay log to its first n entries (a relay
// restore from a backup before the stubs), or a repair request. After each
// step the case names the stubs of the relay log and the stored bytes.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type cmpStubJ struct {
	Position int    `json:"position"`
	Stub     string `json:"stub"`
}

type cmpStepJ struct {
	Kind    string     `json:"kind"` // append, cut, start, chunk or finish
	Signer  string     `json:"signer,omitempty"`
	Body    string     `json:"body,omitempty"`
	N       int        `json:"n,omitempty"`
	Results []resultJ  `json:"results,omitempty"`
	Want    string     `json:"want,omitempty"` // repair: "<status> next <n>", "<status> head <n>" or "<status> <code>"
	Head    headJ      `json:"head"`
	Stubs   []cmpStubJ `json:"stubs"`
	Used    int64      `json:"used"`
}

type cmpCaseJ struct {
	Name  string     `json:"name"`
	Quota int64      `json:"quota"` // 0 means no quota
	Steps []cmpStepJ `json:"steps"`
}

// replayCompaction runs the steps of c on a copy of base and fills in the
// expected results. With check true, it compares them with the stored ones.
func replayCompaction(base *space, envs []string, c *cmpCaseJ, keys map[string]*party, lim limitsJ, check bool) error {
	sp := base.clone()
	sp.quota = c.Quota
	at := int64(httpNow)
	for i := range c.Steps {
		st := &c.Steps[i]
		why := fmt.Sprintf("%s step %d", c.Name, i)
		var got cmpStepJ
		got.Kind = st.Kind
		switch st.Kind {
		case "append":
			sg := keys[st.Signer]
			if sg == nil {
				return fmt.Errorf("%s: signer %q", why, st.Signer)
			}
			rs, err := sp.appendBatch(sg.idText, st.Body, lim)
			if err != nil {
				return fmt.Errorf("%s: %w", why, err)
			}
			for _, r := range rs {
				got.Results = append(got.Results, resultJOf(r))
			}
		case "cut":
			cut, err := newSpaceFromEnvelopes(sp.logText, envs[:st.N])
			if err != nil {
				return fmt.Errorf("%s: %w", why, err)
			}
			cut.quota, cut.mut = sp.quota, sp.mut
			sp = cut
		case "start", "chunk", "finish":
			sg := keys[st.Signer]
			at += 10
			var rp repairReply
			switch st.Kind {
			case "start":
				rp = sp.repairStart(sg.idText, at, st.Body, lim)
			case "chunk":
				rp = sp.repairChunk(sg.idText, at, strings.ReplaceAll(st.Body, "{{session}}", sp.sessID()), lim)
			default:
				rp = sp.repairFinish(sg.idText, at, strings.ReplaceAll(st.Body, "{{session}}", sp.sessID()), lim)
			}
			got.Want = repairWant(rp)
		default:
			return fmt.Errorf("%s: kind %q", why, st.Kind)
		}
		n := len(sp.entries)
		got.Head = headJ{n, b64(sp.digestAt(n))}
		got.Stubs = []cmpStubJ{}
		for _, p := range sp.stubs() {
			got.Stubs = append(got.Stubs, cmpStubJ{p, sp.stubJSON(p)})
		}
		got.Used = sp.used
		if !check {
			st.Results, st.Want, st.Head, st.Stubs, st.Used = got.Results, got.Want, got.Head, got.Stubs, got.Used
			continue
		}
		if jsonText(got.Results) != jsonText(st.Results) && st.Kind == "append" {
			return fmt.Errorf("%s: results %v, stored %v", why, got.Results, st.Results)
		}
		if got.Want != st.Want || got.Head != st.Head || got.Used != st.Used || fmt.Sprint(got.Stubs) != fmt.Sprint(st.Stubs) {
			return fmt.Errorf("%s: reference gives %q head %v stubs %v used %d, stored %q head %v stubs %v used %d",
				why, got.Want, got.Head, got.Stubs, got.Used, st.Want, st.Head, st.Stubs, st.Used)
		}
	}
	return nil
}

func (sp *space) sessID() string {
	if sp.sess == nil {
		return "00000000000000000000000000000000"
	}
	return sp.sess.id
}

func repairWant(rp repairReply) string {
	switch {
	case rp.code != "":
		return fmt.Sprintf("%d %s", rp.status, rp.code)
	case rp.status == 201 || (rp.status == 200 && rp.head == 0):
		return fmt.Sprintf("%d next %d", rp.status, rp.next)
	}
	return fmt.Sprintf("%d head %d", rp.status, rp.head)
}

// cmpBuilder signs the records of one case. It tracks the digests and record
// hashes of a reference replay, so each step can name a base and a snapshot.
type cmpBuilder struct {
	w   *world
	m   *m7Builder
	sp  *space
	lim limitsJ
	err error
}

func (cb *cmpBuilder) fail(err error) {
	if err != nil && cb.err == nil {
		cb.err = err
	}
}

func (cb *cmpBuilder) base(n int) string { return posRaw(n, cb.sp.digestAt(n)) }

func (cb *cmpBuilder) snapshot(au *party, baseN, state, epoch int, plain string) string {
	nonce := sha(frame(s("snailfish.test-seed.v1"), s("cmp"), s(fmt.Sprintf("snap-%d-%d-%s", baseN, state, plain))))[:24]
	ct, err := aeadSeal(cb.w.appKeys[epoch], nonce, snapshotAAD(cb.w, epoch, au, state, cb.sp.digestAt(state)), []byte(plain))
	cb.fail(err)
	env, _, _ := signEnv(au, "snailfish.snapshot.v1", obj(
		"log", q(cb.w.logIDText), "author", q(au.idText), "base", cb.base(baseN),
		"epoch", fmt.Sprint(epoch), "state", cb.base(state), "ciphertext", q(b64(append(nonce, ct...)))))
	return env
}

func (cb *cmpBuilder) accept(au *party, baseN, snap int, hash []byte, applied int) string {
	env, _, _ := signEnv(au, "snailfish.accept.v1", obj(
		"log", q(cb.w.logIDText), "author", q(au.idText), "base", cb.base(baseN),
		"snapshot", obj("position", fmt.Sprint(snap), "hash", q(b64(hash))), "applied", cb.base(applied)))
	return env
}

func (cb *cmpBuilder) rh(p int) []byte { return cb.sp.entries[p-1].rh }

// step applies an append step to the builder replay and returns it.
func (cb *cmpBuilder) appendStep(signer *party, envs ...string) cmpStepJ {
	body := `{"envelopes":[` + strings.Join(envs, ",") + `]}`
	if _, err := cb.sp.appendBatch(signer.idText, body, cb.lim); err != nil {
		cb.fail(err)
	}
	return cmpStepJ{Kind: "append", Signer: signer.name, Body: body}
}

func buildCompaction(h *httpJ, b *logBuilder, w *world, base *space, envs []string, change changeFn) error {
	keys := map[string]*party{w.A.name: w.A, w.B.name: w.B, w.C.name: w.C, w.R1.name: w.R1}
	A, B, C := w.A, w.B, w.C
	newCB := func(quota int64) *cmpBuilder {
		sp := base.clone()
		sp.quota = quota
		return &cmpBuilder{w: w, m: &m7Builder{b: b, w: w, log: w.logIDText}, sp: sp, lim: h.Limits}
	}
	var cases []cmpCaseJ
	var errs []error
	add := func(name string, quota int64, cb *cmpBuilder, steps ...cmpStepJ) {
		errs = append(errs, cb.err, cb.m.err)
		cases = append(cases, cmpCaseJ{Name: name, Quota: quota, Steps: steps})
	}
	state := `{"tasks":[{"id":1,"title":"Buy milk","done":true}]}`

	// [CMP-5] [CMP-6] [CMP-12] [CMP-19] specs/compaction/test.qnt::compactTest:
	// after both accepts the relay makes stubs of the changes at 2 and 4. The
	// snapshot and the accept records stay in full. A retry of the change at 2
	// is `known` from its stub ([DLV-5]).
	{
		cb := newCB(0)
		s1 := cb.appendStep(A, cb.snapshot(A, 4, 4, 1, state))
		s2 := cb.appendStep(A, cb.accept(A, 5, 5, cb.rh(5), 4))
		s3 := cb.appendStep(B, cb.accept(B, 6, 5, cb.rh(5), 4))
		s4 := cb.appendStep(A, change(A, 30, cb.base(7), 1, w.logIDText, `{"op":"add","task":9}`), envs[1])
		add("compact", 0, cb, s1, s2, s3, s4)
	}
	// [CMP-6] [CMP-7] specs/compaction/test.qnt::blockedTest: one accept is
	// not enough. An accept with an applied position before the state
	// position does not count.
	{
		cb2 := newCB(0)
		t1 := cb2.appendStep(A, cb2.snapshot(A, 4, 4, 1, state))
		t2 := cb2.appendStep(A, cb2.accept(A, 5, 5, cb2.rh(5), 4))
		t3 := cb2.appendStep(B, cb2.accept(B, 6, 5, cb2.rh(5), 3))
		t4 := cb2.appendStep(B, cb2.accept(B, 7, 5, cb2.rh(5), 4))
		add("blocked-then-counted", 0, cb2, t1, t2, t3, t4)
	}
	// [CMP-6] A grant after the acceptance does not end it: one request
	// holds the last accept and a grant, and the relay makes the stubs.
	{
		cb := newCB(0)
		s1 := cb.appendStep(A, cb.snapshot(A, 4, 4, 1, state))
		s2 := cb.appendStep(A, cb.accept(A, 5, 5, cb.rh(5), 4))
		s3 := cb.appendStep(B, cb.accept(B, 6, 5, cb.rh(5), 4), cb.m.grant(B, C, 1, cb.base(6), []int{1}))
		add("grant-after-accept", 0, cb, s1, s2, s3)
	}
	// 10.6 step 13 for snapshots and accept records ([CMP-3], decision D7).
	{
		cb := newCB(0)
		big := strings.Repeat("x", h.Limits.MaxSnapshotBytes)
		s1 := cb.appendStep(A,
			cb.snapshot(A, 4, 2, 2, state), // epoch 2 is not current: wrong_epoch
			cb.snapshot(A, 4, 4, 1, big),   // too_large
			cb.wrongStateDigest(A, 4, 3, state),
			cb.accept(A, 4, 4, cb.rh(4), 4), // position 4 is a change
		)
		s2 := cb.appendStep(A, cb.snapshot(A, 4, 3, 1, state))
		s3 := cb.appendStep(A,
			cb.accept(A, 5, 5, cb.rh(4), 3), // wrong snapshot hash
			cb.accept(A, 4, 5, cb.rh(5), 5), // applied after the base
			cb.accept(A, 5, 5, cb.rh(5), 3), // valid
		)
		add("snapshot-and-accept-checks", 0, cb, s1, s2, s3)
	}
	// [CMP-7] [CMP-9] [CMP-4] [CMP-10] [CMP-11] [CMP-20]
	// specs/compaction/test.qnt::removalTest and sealNeededTest: B never
	// accepts. A removes B, which makes the snapshot of A accepted. A grant to
	// C must hold epoch 1, because the usable snapshot uses it. After a new
	// snapshot at the same state position, the old snapshot is a stub, and a
	// grant with epoch 2 alone is valid.
	{
		cb := newCB(0)
		s1 := cb.appendStep(A, cb.snapshot(A, 4, 4, 1, state))
		s2 := cb.appendStep(A, cb.accept(A, 5, 5, cb.rh(5), 4))
		ep, _ := cb.m.epoch(A, cb.base(6), 2, []*party{B}, []*party{A}, w.R1)
		s3 := cb.appendStep(A, ep)
		s4 := cb.appendStep(A, cb.m.grant(A, C, 1, cb.base(7), []int{2}))
		s5 := cb.appendStep(A, cb.snapshot(A, 7, 4, 2, state))
		s6 := cb.appendStep(A, cb.accept(A, 8, 8, cb.rh(8), 4))
		s7 := cb.appendStep(A, cb.m.grant(A, C, 1, cb.base(9), []int{2}))
		add("removal-ends-block", 0, cb, s1, s2, s3, s4, s5, s6, s7)
	}
	// [CMP-18] [CMP-19] specs/compaction/test.qnt::quotaTest: at a full quota
	// the reserve takes the snapshot and the accept records. After the stubs,
	// a queued change is stored.
	{
		quota := int64(3100)
		cb := newCB(quota)
		s1 := cb.appendStep(A,
			change(A, 31, cb.base(4), 1, w.logIDText, `{"op":"add","task":10}`),
			change(A, 32, cb.base(4), 1, w.logIDText, `{"op":"add","task":11}`))
		c33 := change(A, 33, cb.base(6), 1, w.logIDText, `{"op":"add","task":12}`)
		s2 := cb.appendStep(A, c33)
		s3 := cb.appendStep(A, cb.snapshot(A, 6, 6, 1, state))
		s4 := cb.appendStep(A, cb.accept(A, 7, 7, cb.rh(7), 6))
		s5 := cb.appendStep(B, cb.accept(B, 8, 7, cb.rh(7), 6))
		s6 := cb.appendStep(A, c33)
		add("reserve", quota, cb, s1, s2, s3, s4, s5, s6)
	}
	// [LOG-11] [CMP-17] specs/compaction/test.qnt::repairStubsTest and
	// badRepairTest: after a restore to position 1, a device repairs the log
	// with its stubs. The finish refuses a staged stub that no usable snapshot
	// of the staged range covers.
	{
		cb := newCB(0)
		s0 := cb.appendStep(A, cb.snapshot(A, 4, 4, 1, state))
		s1 := cb.appendStep(A, cb.accept(A, 5, 5, cb.rh(5), 4))
		s2 := cb.appendStep(B, cb.accept(B, 6, 5, cb.rh(5), 4))
		full := cb.sp
		ent := func(p int) string {
			if full.cmp[p-1].stub {
				return fmt.Sprintf(`{"position":%d,"stub":%s}`, p, full.stubJSON(p))
			}
			return fmt.Sprintf(`{"position":%d,"envelope":%s}`, p, cb.envAt(p))
		}
		start := func(es ...string) string {
			return `{"base":` + posRaw(1, full.digestAt(1)) + `,"entries":[` + strings.Join(es, ",") + `]}`
		}
		chunk := func(es ...string) string {
			return `{"session":"{{session}}","entries":[` + strings.Join(es, ",") + `]}`
		}
		finish := func(n int) string { return `{"session":"{{session}}","tip":` + posRaw(n, full.digestAt(n)) + `}` }
		steps := []cmpStepJ{s0, s1, s2,
			{Kind: "cut", N: 1},
			{Kind: "start", Signer: A.name, Body: start(ent(2), ent(3), ent(4))},
			{Kind: "finish", Signer: A.name, Body: finish(4)},
			{Kind: "start", Signer: A.name, Body: start(ent(2), ent(3), ent(4))},
			{Kind: "chunk", Signer: A.name, Body: chunk(ent(5), ent(6), ent(7))},
			{Kind: "finish", Signer: A.name, Body: finish(7)},
		}
		add("repair-stubs", 0, cb, steps...)
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	for i := range cases {
		if err := replayCompaction(base, envs, &cases[i], keys, h.Limits, false); err != nil {
			return err
		}
	}
	h.Compaction = cases
	return nil
}

// envAt is the stored envelope at p of the builder replay.
func (cb *cmpBuilder) envAt(p int) string { return cb.sp.envs[p-1] }

// wrongStateDigest is a snapshot whose state digest is the digest of the
// position after its state position.
func (cb *cmpBuilder) wrongStateDigest(au *party, baseN, state int, plain string) string {
	nonce := sha(frame(s("snailfish.test-seed.v1"), s("cmp"), s("wrong-digest")))[:24]
	d := cb.sp.digestAt(state + 1)
	ct, err := aeadSeal(cb.w.appKeys[1], nonce, snapshotAAD(cb.w, 1, au, state, d), []byte(plain))
	cb.fail(err)
	env, _, _ := signEnv(au, "snailfish.snapshot.v1", obj(
		"log", q(cb.w.logIDText), "author", q(au.idText), "base", cb.base(baseN),
		"epoch", "1", "state", posRaw(state, d), "ciphertext", q(b64(append(nonce, ct...)))))
	return env
}

func jsonText(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
