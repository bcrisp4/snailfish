package main

// Compaction in the reference relay: PROTOCOL.md section 14.

import (
	"bytes"
	"fmt"
	"strings"
)

// cmpInfo is what section 14 needs of one log entry. A stub keeps only its
// type and change ID, so the other fields of a stub are zero.
type cmpInfo struct {
	ptype    string
	author   string
	epoch    int64
	statePos int
	snapPos  int
	snapHash []byte
	applied  int
	stub     bool
	envLen   int64
	act      map[string]bool // the active devices after this entry (10.2)
}

// stubRecord is a repair entry that is a stub: the type, the change ID and
// the record hash ([CMP-1]).
func stubRecord(ptype, changeID string, rh []byte) *record {
	m := map[string]any{}
	if changeID != "" {
		m["change_id"] = changeID
	}
	return &record{ptype: ptype, m: m, rh: rh, stub: true}
}

func countsBytes(ptype string) bool {
	return ptype == "snailfish.change.v1" || ptype == "snailfish.snapshot.v1" || ptype == "snailfish.accept.v1"
}

// cmpOf is the cmpInfo of r after sp.push has applied it.
func (sp *space) cmpOf(r *record) cmpInfo {
	c := cmpInfo{ptype: r.ptype, stub: r.stub, act: map[string]bool{}}
	for id := range sp.active {
		c.act[id] = true
	}
	if r.stub {
		return c
	}
	c.author = r.str("author")
	c.envLen = r.envLen
	c.epoch, _ = r.m["epoch"].(int64)
	switch r.ptype {
	case "snailfish.snapshot.v1":
		st, _ := r.m["state"].(map[string]any)
		n, _ := st["position"].(int64)
		c.statePos = int(n)
	case "snailfish.accept.v1":
		sn, _ := r.m["snapshot"].(map[string]any)
		n, _ := sn["position"].(int64)
		c.snapPos = int(n)
		c.snapHash, _ = decodeB64(fmt.Sprint(sn["hash"]))
		ap, _ := r.m["applied"].(map[string]any)
		a, _ := ap["position"].(int64)
		c.applied = int(a)
	}
	return c
}

// accepted is 14.1 rule 3 for the snapshot at p.
func (sp *space) accepted(p int) bool {
	sp0 := sp.cmp[p-1].statePos
	got := map[string]bool{}
	for r := p + 1; r <= len(sp.cmp); r++ {
		a := sp.cmp[r-1]
		if a.ptype == "snailfish.accept.v1" && !a.stub && a.snapPos == p && (a.applied >= sp0 || sp.mut == "cmp-any-applied") {
			got[a.author] = true
		}
		act := a.act
		if sp.mut == "cmp-count-now" {
			act = sp.cmp[len(sp.cmp)-1].act
		}
		all := true
		for id := range act {
			if !got[id] {
				all = false
			}
		}
		if all {
			return true
		}
	}
	return false
}

// usable is 14.1 rules 4 and 5: the position of the usable snapshot, or 0.
func (sp *space) usable() int {
	u := 0
	for p := 1; p <= len(sp.cmp); p++ {
		e := sp.cmp[p-1]
		if e.ptype != "snailfish.snapshot.v1" || e.stub || !sp.accepted(p) {
			continue
		}
		if u == 0 || e.statePos >= sp.cmp[u-1].statePos {
			u = p
		}
	}
	return u
}

func (sp *space) frontier(u int) int {
	if u == 0 {
		return 0
	}
	return sp.cmp[u-1].statePos
}

// covers is 14.2.
func (sp *space) covers(u, p int) bool {
	if u == 0 {
		return false
	}
	f, e := sp.frontier(u), sp.cmp[p-1]
	switch e.ptype {
	case "snailfish.change.v1":
		return p <= f
	case "snailfish.snapshot.v1":
		return p != u && (e.statePos < f || (e.statePos == f && p < u && sp.mut != "cmp-keep-ties"))
	case "snailfish.accept.v1":
		return sp.mut == "cmp-stub-accept" && p < u
	}
	return sp.mut == "cmp-stub-security" && p <= f
}

// stubValid is the stub check of 14.3 for the stub at p.
func (sp *space) stubValid(u, p int) bool {
	switch sp.cmp[p-1].ptype {
	case "snailfish.change.v1":
		return u > 0 && p <= sp.frontier(u)
	case "snailfish.snapshot.v1":
		return u > 0 && p != u
	}
	return false
}

// compact is 14.4: replace each covered record with a stub.
func (sp *space) compact() {
	if sp.mut == "cmp-no-stubs" {
		return
	}
	u := sp.usable()
	for p := 1; p <= len(sp.cmp); p++ {
		if !sp.cmp[p-1].stub && sp.covers(u, p) {
			if countsBytes(sp.cmp[p-1].ptype) {
				sp.used -= sp.cmp[p-1].envLen
			}
			sp.cmp[p-1].stub = true
		}
	}
}

// stubs is the positions of the stubs of the log.
func (sp *space) stubs() []int {
	out := []int{}
	for p, e := range sp.cmp {
		if e.stub {
			out = append(out, p+1)
		}
	}
	return out
}

// needed is 14.5: the needed epochs of a grant or recovery record at the
// next position.
func (sp *space) needed() map[int64]bool {
	out := map[int64]bool{sp.epoch: true}
	if sp.mut == "cmp-seal-current" {
		return out
	}
	u := sp.usable()
	for p, e := range sp.cmp {
		if (e.ptype == "snailfish.change.v1" || e.ptype == "snailfish.snapshot.v1") && !e.stub && !sp.covers(u, p+1) {
			out[e.epoch] = true
		}
	}
	return out
}

// keySetOK is the key set rule of 10.6 step 13 for a grant or recovery
// record: one key set with each needed epoch and no epoch above the current.
func (sp *space) keySetOK(epochs [][]int64) bool {
	if len(epochs) != 1 {
		return false
	}
	have := map[int64]bool{}
	for _, e := range epochs[0] {
		if e > sp.epoch {
			return false
		}
		have[e] = true
	}
	for e := range sp.needed() {
		if !have[e] {
			return false
		}
	}
	return true
}

// snapshotOK is the snapshot rule of 10.6 step 13.
func (sp *space) snapshotOK(r *record) bool {
	st, _ := r.m["state"].(map[string]any)
	n, _ := st["position"].(int64)
	d, _ := decodeB64(fmt.Sprint(st["digest"]))
	next := len(sp.entries) + 1
	return n >= 1 && int(n) < next && bytes.Equal(d, sp.digestAt(int(n)))
}

// acceptOK is the accept rule of 10.6 step 13.
func (sp *space) acceptOK(r *record) bool {
	c := sp.cmpOf(r)
	if c.snapPos < 1 || c.snapPos > len(sp.cmp) {
		return false
	}
	if sp.cmp[c.snapPos-1].ptype != "snailfish.snapshot.v1" || !bytes.Equal(sp.entries[c.snapPos-1].rh, c.snapHash) {
		return false
	}
	ap, _ := r.m["applied"].(map[string]any)
	ad, _ := decodeB64(fmt.Sprint(ap["digest"]))
	bn, _ := r.base()
	return c.applied <= bn && bytes.Equal(ad, sp.digestAt(c.applied))
}

// stubJSON is the stub object of 10.7.
func (sp *space) stubJSON(p int) string {
	e := sp.cmp[p-1]
	if e.ptype == "snailfish.change.v1" {
		return obj("type", q(e.ptype), "change_id", q(sp.changeAt[p]), "hash", q(b64(sp.entries[p-1].rh)))
	}
	return obj("type", q(e.ptype), "hash", q(b64(sp.entries[p-1].rh)))
}

// isCompactionType is true for the types that section 14 can make stubs of.
func isCompactionType(ptype string) bool {
	return strings.HasPrefix(ptype, "snailfish.change.") || strings.HasPrefix(ptype, "snailfish.snapshot.")
}
