//! Log compaction (`PROTOCOL.md` section 14, DESIGN.md "Log compaction",
//! `specs/compaction`).
//!
//! [`Compaction`] holds what section 14 needs of a log, and the relay and the
//! engine update it with each entry in position order. Acceptance is
//! monotone, so one pass gives the result of the definition of 14.1, which
//! looks for the first position where every active device has accepted
//! ([CMP-6]). The functions do no I/O.

use std::collections::{BTreeMap, BTreeSet};

use crate::encoding::Hash32;
use crate::records::{Body, Record};

/// What section 14 reads of one log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A change record in full.
    Change {
        /// Its epoch.
        epoch: u64,
    },
    /// A snapshot record in full.
    Snapshot {
        /// The state position.
        state: u64,
        /// Its epoch.
        epoch: u64,
    },
    /// An accept record.
    Accept {
        /// The position of the snapshot that it names.
        snapshot: u64,
        /// The applied position of its author.
        applied: u64,
        /// Its author.
        author: Hash32,
    },
    /// Each other record, and a stub ([CMP-1]). A stub holds no epoch and
    /// no state position, so it never moves the usable snapshot (14.1). A
    /// removal changes the active devices, which the caller passes with the
    /// entry.
    Other,
}

/// One snapshot record in full.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// The state position.
    pub state: u64,
    /// The epoch of its key.
    pub epoch: u64,
    /// The devices with an accept record that counts for it (14.1 rule 2).
    pub accepters: BTreeSet<Hash32>,
    /// True after it is accepted ([CMP-6]). It stays accepted.
    pub accepted: bool,
}

/// The section 14 state of a log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Compaction {
    /// Each snapshot record in full, by position.
    pub snapshots: BTreeMap<u64, Snapshot>,
    /// The position of the usable snapshot ([CMP-8]).
    pub usable: Option<u64>,
    /// The position of the last change record of each epoch.
    pub last_change: BTreeMap<u64, u64>,
}

/// True if a snapshot `(state, position)` wins over the usable snapshot
/// `(state, position)`: a higher state position, or the same state position
/// at a higher log position ([CMP-8], [CMP-10]).
#[must_use]
pub fn better(candidate: (u64, u64), usable: Option<(u64, u64)>) -> bool {
    usable.is_none_or(|u| candidate > u)
}

/// True if the usable snapshot covers a change at `position` ([CMP-11]).
#[must_use]
pub fn covers_change(position: u64, frontier: u64) -> bool {
    frontier > 0 && position <= frontier
}

/// True if the usable snapshot at `usable` with the frontier `frontier`
/// covers another snapshot at `position` with the state position `state`
/// ([CMP-11], finding C1).
#[must_use]
pub fn covers_snapshot(position: u64, state: u64, usable: u64, frontier: u64) -> bool {
    (state, position) < (frontier, usable)
}

/// The stub check of 14.3 ([CMP-15]). `usable` is 0 if the log has no usable
/// snapshot.
#[must_use]
pub fn stub_valid(change: bool, position: u64, usable: u64, frontier: u64) -> bool {
    if change {
        covers_change(position, frontier)
    } else {
        usable > 0 && position != usable
    }
}

/// The key set rule of 10.6 step 13 for a grant or a recovery record
/// ([CMP-20]): it holds each needed epoch and no epoch above `current`.
#[must_use]
pub fn epochs_ok(epochs: &[u64], needed: &BTreeSet<u64>, current: u64) -> bool {
    epochs.iter().all(|e| *e <= current) && needed.iter().all(|n| epochs.contains(n))
}

/// The [`Kind`] of a record in full.
#[must_use]
pub fn kind(record: &Record) -> Kind {
    match &record.body {
        Body::Change { epoch, .. } => Kind::Change { epoch: *epoch },
        Body::Snapshot { epoch, state, .. } => Kind::Snapshot {
            state: state.position,
            epoch: *epoch,
        },
        Body::Accept {
            snapshot_position,
            applied,
            ..
        } => Kind::Accept {
            snapshot: *snapshot_position,
            applied: applied.position,
            author: *record.author.id(),
        },
        _ => Kind::Other,
    }
}

/// An SQL condition on a `payload_type` column: the rows that [`replay`]
/// takes, the security, snapshot and accept records. It is a list, so the
/// index on the payload type of a store serves it.
#[must_use]
pub fn replay_sql() -> String {
    let mut list: Vec<String> = crate::records::SECURITY_TYPES
        .iter()
        .map(|t| format!("'{t}'"))
        .collect();
    list.push("'snailfish.snapshot.v1'".into());
    list.push("'snailfish.accept.v1'".into());
    format!("payload_type IN ({})", list.join(", "))
}

/// The compaction state of a log from its records that are not changes, in
/// position order: `(position, envelope JSON)`, with an empty envelope for
/// a stub. Changes do not move the usable snapshot, so the
/// caller leaves them out. Returns the state and the first position of each
/// epoch, `(epoch, position)`, from which the caller fills
/// [`Compaction::last_change`].
///
/// # Errors
///
/// The parse error of a stored record.
pub fn replay<'a>(
    rows: impl IntoIterator<Item = (u64, &'a str)>,
) -> Result<(Compaction, Vec<(u64, u64)>), String> {
    let mut state = crate::space::State::default();
    let mut cmp = Compaction::default();
    let mut starts = vec![(1, 1)];
    for (position, env) in rows {
        let kind = if env.is_empty() {
            Kind::Other
        } else {
            let e = crate::envelope::Envelope::parse(env.as_bytes()).map_err(|e| e.to_string())?;
            let record = crate::records::parse_payload(&e.payload_type, &e.payload)
                .map_err(|e| e.to_string())?;
            state.apply(&record);
            if let Body::Epoch { epoch, .. } = record.body {
                starts.push((epoch, position));
            }
            kind(&record)
        };
        let active = state.devices.keys().copied().collect();
        cmp.apply(position, kind, &active);
    }
    Ok((cmp, starts))
}

impl Compaction {
    /// The frontier: the state position of the usable snapshot, or 0.
    #[must_use]
    pub fn frontier(&self) -> u64 {
        self.usable
            .and_then(|u| self.snapshots.get(&u))
            .map_or(0, |s| s.state)
    }

    /// Take the entry at `position` (the next position). `active` is the set
    /// of active devices after the entry (`PROTOCOL.md` 10.2).
    pub fn apply(&mut self, position: u64, kind: Kind, active: &BTreeSet<Hash32>) {
        match kind {
            Kind::Change { epoch } => {
                self.last_change.insert(epoch, position);
            }
            Kind::Snapshot { state, epoch } => {
                self.snapshots.insert(
                    position,
                    Snapshot {
                        state,
                        epoch,
                        ..Snapshot::default()
                    },
                );
            }
            Kind::Accept {
                snapshot,
                applied,
                author,
            } => {
                if let Some(s) = self.snapshots.get_mut(&snapshot)
                    && applied >= s.state
                {
                    s.accepters.insert(author);
                }
            }
            Kind::Other => {}
        }
        // 14.1 rule 3 at this position: each snapshot with an accept from
        // every device that is active here is accepted.
        let mut usable = self
            .usable
            .and_then(|u| self.snapshots.get(&u).map(|s| (s.state, u)));
        for (p, s) in &mut self.snapshots {
            if !s.accepted && !active.is_empty() && active.is_subset(&s.accepters) {
                s.accepted = true;
                if better((s.state, *p), usable) {
                    usable = Some((s.state, *p));
                }
            }
        }
        self.usable = usable.map(|(_, p)| p);
    }

    /// True if the usable snapshot covers the record at `position` of kind
    /// `kind` (14.2). A security record or an accept record never is
    /// ([CMP-20]).
    #[must_use]
    pub fn covers(&self, position: u64, kind: &Kind) -> bool {
        let u = self.usable.unwrap_or(0);
        let f = self.frontier();
        match kind {
            Kind::Change { .. } => covers_change(position, f),
            Kind::Snapshot { state, .. } => covers_snapshot(position, *state, u, f),
            Kind::Accept { .. } | Kind::Other => false,
        }
    }

    /// The stub check of 14.3 for a stub at `position`.
    #[must_use]
    pub fn stub_valid(&self, change: bool, position: u64) -> bool {
        stub_valid(change, position, self.usable.unwrap_or(0), self.frontier())
    }

    /// The needed epochs of a grant or recovery record after the last entry
    /// (14.5): `current`, the epoch of each change after the frontier, and
    /// the epoch of each snapshot that the usable snapshot does not cover.
    #[must_use]
    pub fn needed_epochs(&self, current: u64) -> BTreeSet<u64> {
        let u = self.usable.unwrap_or(0);
        let f = self.frontier();
        let mut out: BTreeSet<u64> = self
            .last_change
            .iter()
            .filter(|(_, last)| !covers_change(**last, f))
            .map(|(e, _)| *e)
            .collect();
        out.extend(
            self.snapshots
                .iter()
                .filter(|(p, s)| !covers_snapshot(**p, s.state, u, f))
                .map(|(_, s)| s.epoch),
        );
        out.insert(current);
        out
    }

    /// The positions of the snapshots that the usable snapshot covers. The
    /// covered changes are the changes at or before [`Compaction::frontier`].
    #[must_use]
    pub fn covered_snapshots(&self) -> Vec<u64> {
        let u = self.usable.unwrap_or(0);
        let f = self.frontier();
        self.snapshots
            .iter()
            .filter(|(p, s)| covers_snapshot(**p, s.state, u, f))
            .map(|(p, _)| *p)
            .collect()
    }

    /// The valid snapshot in full at the highest position that is not
    /// accepted: the one that the user page names for "blocks compaction"
    /// ([CMP-7]).
    #[must_use]
    pub fn pending(&self) -> Option<(u64, &Snapshot)> {
        self.snapshots
            .iter()
            .rev()
            .find(|(_, s)| !s.accepted)
            .map(|(p, s)| (*p, s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn dev(n: u8) -> Hash32 {
        [n; 32]
    }

    /// One entry of a test log: the kind and the active devices after it.
    type Entry = (Kind, BTreeSet<Hash32>);

    /// The definition of 14.1, by search over all positions: the reference
    /// for the one-pass [`Compaction`].
    fn reference_usable(log: &[Entry]) -> Option<u64> {
        let numbered: Vec<(u64, &Entry)> = (1u64..).zip(log).collect();
        let mut best: Option<(u64, u64)> = None;
        for (p, (k, _)) in &numbered {
            let Kind::Snapshot { state, .. } = k else {
                continue;
            };
            let later: Vec<&(u64, &Entry)> = numbered.iter().filter(|(q, _)| q > p).collect();
            let counted = |q: u64, d: &Hash32| {
                later
                    .iter()
                    .take_while(|(r, _)| *r <= q)
                    .any(|(_, (k, _))| {
                        matches!(k, Kind::Accept { snapshot, applied, author }
                        if snapshot == p && applied >= state && author == d)
                    })
            };
            let accepted = later
                .iter()
                .any(|(q, (_, act))| !act.is_empty() && act.iter().all(|d| counted(*q, d)));
            if accepted && better((*state, *p), best) {
                best = Some((*state, *p));
            }
        }
        best.map(|(_, p)| p)
    }

    fn arb_log() -> impl Strategy<Value = Vec<Entry>> {
        // Devices 1 and 2 are active from the start. A grant adds 3, a
        // removal takes 2 out.
        let step = prop_oneof![
            (1u64..3).prop_map(|epoch| (0u8, epoch, 0u64, 0u8)),
            (1u64..8, 1u64..3).prop_map(|(state, epoch)| (1, epoch, state, 0)),
            (1u64..12, 0u64..10, 1u8..4).prop_map(|(snap, applied, d)| (2, snap, applied, d)),
            Just((3, 0, 0, 0)),
            Just((4, 0, 0, 0)),
        ];
        proptest::collection::vec(step, 1..14).prop_map(|steps| {
            let mut act: BTreeSet<Hash32> = [dev(1), dev(2)].into();
            let mut out = Vec::new();
            for (t, a, b, d) in steps {
                let kind = match t {
                    0 => Kind::Change { epoch: a },
                    1 => Kind::Snapshot { state: b, epoch: a },
                    2 => Kind::Accept {
                        snapshot: a,
                        applied: b,
                        author: dev(d),
                    },
                    3 => {
                        act.insert(dev(3));
                        Kind::Other
                    }
                    _ => {
                        act.remove(&dev(2));
                        Kind::Other
                    }
                };
                out.push((kind, act.clone()));
            }
            out
        })
    }

    fn run(log: &[Entry]) -> Compaction {
        let mut c = Compaction::default();
        for (p, (k, act)) in (1u64..).zip(log) {
            c.apply(p, *k, act);
        }
        c
    }

    proptest! {
        /// [CMP-6] [CMP-8]: the one-pass state gives the usable snapshot of
        /// the definition of 14.1 for every log of up to 13 entries with
        /// grants and removals.
        #[test]
        fn one_pass_matches_the_definition(log in arb_log()) {
            prop_assert_eq!(run(&log).usable, reference_usable(&log));
        }

        /// [CMP-6]: an accepted snapshot stays accepted, so the frontier
        /// never goes back as the log grows.
        #[test]
        fn frontier_never_goes_back(log in arb_log()) {
            let mut c = Compaction::default();
            let mut last = 0;
            for (p, (k, act)) in (1u64..).zip(&log) {
                c.apply(p, *k, act);
                prop_assert!(c.frontier() >= last);
                last = c.frontier();
            }
        }

        /// [CMP-20]: the needed epochs hold the current epoch and the epoch
        /// of each change after the frontier.
        #[test]
        fn needed_epochs_hold_uncovered_changes(log in arb_log(), current in 1u64..4) {
            let c = run(&log);
            let need = c.needed_epochs(current);
            prop_assert!(need.contains(&current));
            for (p, (k, _)) in (1u64..).zip(&log) {
                if let Kind::Change { epoch } = k && !c.covers(p, k) {
                    prop_assert!(need.contains(epoch));
                }
                if let Kind::Snapshot { epoch, .. } = k && !c.covers(p, k) {
                    prop_assert!(need.contains(epoch));
                }
            }
        }
    }

    /// `specs/compaction/test.qnt::compactTest`: two changes, a snapshot of
    /// state 3 at 4, and an accept from each device.
    #[test]
    fn compact_scenario() {
        let both: BTreeSet<Hash32> = [dev(1), dev(2)].into();
        let mut c = Compaction::default();
        c.apply(1, Kind::Other, &both);
        c.apply(2, Kind::Change { epoch: 1 }, &both);
        c.apply(3, Kind::Change { epoch: 1 }, &both);
        c.apply(4, Kind::Snapshot { state: 3, epoch: 1 }, &both);
        let acc = |d| Kind::Accept {
            snapshot: 4,
            applied: 3,
            author: dev(d),
        };
        c.apply(5, acc(1), &both);
        assert_eq!(c.usable, None);
        c.apply(6, acc(2), &both);
        assert_eq!((c.usable, c.frontier()), (Some(4), 3));
        assert!(c.covers(2, &Kind::Change { epoch: 1 }));
        assert!(!c.covers(4, &Kind::Snapshot { state: 3, epoch: 1 }));
        assert!(!c.covers(5, &acc(1)));
        assert_eq!(c.needed_epochs(1), [1].into());
    }

    /// `specs/compaction/test.qnt::removalTest` ([CMP-7], [CMP-10], C1): the
    /// removal of the device that never accepts makes the snapshot accepted.
    /// A later snapshot at the same state position wins and covers it.
    #[test]
    fn removal_scenario() {
        let both: BTreeSet<Hash32> = [dev(1), dev(2)].into();
        let one: BTreeSet<Hash32> = [dev(1)].into();
        let mut c = Compaction::default();
        c.apply(2, Kind::Change { epoch: 1 }, &both);
        c.apply(4, Kind::Snapshot { state: 2, epoch: 1 }, &both);
        let acc = |p| Kind::Accept {
            snapshot: p,
            applied: 2,
            author: dev(1),
        };
        c.apply(5, acc(4), &both);
        assert_eq!(c.usable, None);
        c.apply(6, Kind::Other, &one);
        assert_eq!(c.usable, Some(4));
        assert_eq!(c.needed_epochs(2), [1, 2].into());
        c.apply(7, Kind::Snapshot { state: 2, epoch: 2 }, &one);
        c.apply(8, acc(7), &one);
        assert_eq!(c.usable, Some(7));
        assert_eq!(c.covered_snapshots(), vec![4]);
        assert_eq!(c.needed_epochs(2), [2].into());
        assert_eq!(c.pending(), None);
    }

    /// 14.3: a change stub needs the frontier, a snapshot stub a usable
    /// snapshot at another position.
    #[test]
    fn stub_check() {
        assert!(!stub_valid(true, 2, 0, 0));
        assert!(stub_valid(true, 3, 4, 3));
        assert!(!stub_valid(true, 4, 5, 3));
        assert!(stub_valid(false, 7, 9, 3));
        assert!(!stub_valid(false, 9, 9, 3));
        assert!(!stub_valid(false, 2, 0, 0));
    }

    /// [CMP-6]: the replay rows are every record type of level 1 except a
    /// change, so a store that selects by this list misses no accept.
    #[test]
    fn replay_sql_names_every_type_but_a_change() {
        let sql = replay_sql();
        for t in crate::records::RECORD_TYPES {
            assert_eq!(
                sql.contains(&format!("'{t}'")),
                t != "snailfish.change.v1",
                "{t}"
            );
        }
    }

    /// [CMP-8] [CMP-10]: the order of `better`, also for equal values.
    #[test]
    fn better_orders_state_then_position() {
        assert!(better((2, 4), None));
        assert!(better((3, 1), Some((2, 9))));
        assert!(better((2, 5), Some((2, 4))));
        assert!(!better((2, 4), Some((2, 4))));
        assert!(!better((2, 3), Some((2, 4))));
        assert!(!better((1, 9), Some((2, 4))));
    }

    /// [CMP-11] and finding C1: the usable snapshot at 7 with frontier 2
    /// covers a lower state position, and the same state position only at
    /// a lower log position.
    #[test]
    fn coverage_of_changes_and_snapshots() {
        assert!(!covers_change(0, 0));
        assert!(!covers_change(1, 0));
        assert!(covers_change(2, 2));
        assert!(!covers_change(3, 2));
        assert!(covers_snapshot(9, 1, 7, 2));
        assert!(covers_snapshot(4, 2, 7, 2));
        assert!(!covers_snapshot(7, 2, 7, 2));
        assert!(!covers_snapshot(9, 2, 7, 2));
        assert!(!covers_snapshot(9, 3, 7, 2));
        assert!(!covers_snapshot(4, 1, 0, 0));
    }

    #[test]
    fn epochs_rule() {
        let need: BTreeSet<u64> = [1, 2].into();
        assert!(epochs_ok(&[1, 2], &need, 2));
        assert!(!epochs_ok(&[2], &need, 2));
        assert!(!epochs_ok(&[1, 2, 3], &need, 2));
        assert!(epochs_ok(&[2], &[2].into(), 2));
    }
}

/// Kani harnesses: the comparisons of 14.1 to 14.3 for every 64-bit input.
#[cfg(kani)]
mod proofs {
    use super::{better, covers_change, covers_snapshot, stub_valid};

    /// [CMP-8] [CMP-10]: a candidate wins only with a higher state position,
    /// or the same state position at a higher log position.
    #[kani::proof]
    fn better_is_lexicographic() {
        let c: (u64, u64) = kani::any();
        let u: (u64, u64) = kani::any();
        assert!(better(c, None));
        assert!(better(c, Some(u)) == (c.0 > u.0 || (c.0 == u.0 && c.1 > u.1)));
    }

    /// [CMP-11] [CMP-15]: a change stub is valid exactly when the usable
    /// snapshot covers the change, and the usable snapshot never covers
    /// itself.
    #[kani::proof]
    fn stub_check_matches_coverage() {
        let p: u64 = kani::any();
        let u: u64 = kani::any();
        let f: u64 = kani::any();
        let state: u64 = kani::any();
        // A log has a frontier only with a usable snapshot, and the usable
        // snapshot has the frontier as its state position.
        kani::assume(u > 0 || f == 0);
        kani::assume(p != u || state == f);
        assert!(stub_valid(true, p, u, f) == covers_change(p, f));
        assert!(!covers_snapshot(u, f, u, f));
        assert!(!stub_valid(false, u, u, f));
        if covers_snapshot(p, state, u, f) {
            assert!(stub_valid(false, p, u, f));
        }
        if f == 0 {
            assert!(!covers_change(p, f));
        }
    }
}
