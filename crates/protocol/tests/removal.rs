//! M7 space-state scenarios of `protocol::space`: removal, recovery records,
//! full recovery and levels (`PROTOCOL.md` 10.2, 10.6 steps 11 to 13,
//! section 13). Each test names its model scenario (specs/conformance.md).
//! The relay and the engine call the same check ([LOG-9]), so each verdict
//! here is the verdict of both.
#![cfg(test)]

use snailfish_protocol::encoding::Hash32;
use snailfish_protocol::envelope::Envelope;
use snailfish_protocol::keys::{
    device_id, key_commitment, open_key_set, recovery_id, seal_key_set, seal_public,
};
use snailfish_protocol::records::{Author, Device, KeySet, Keys, Position};
use snailfish_protocol::recovery;
use snailfish_protocol::sig::SecretKey;
use snailfish_protocol::space::{
    Levels, MemorySpace, Mode, Refusal, SpaceView, Verdict, check_append, check_append_at,
    check_genesis,
};
use snailfish_protocol::write;

const LOG: [u8; 16] = [7; 16];

struct Party {
    sign: SecretKey,
    seal_seed: [u8; 32],
    keys: Keys,
    id: Hash32,
}

fn party(n: u8) -> Party {
    let sign = SecretKey::from_seed(&[n; 32]);
    let seal_seed = [n.wrapping_add(100); 32];
    let keys = Keys {
        sign: sign.public(),
        seal: Box::new(seal_public(&seal_seed)),
    };
    let id = device_id(&keys.sign, &keys.seal);
    Party {
        sign,
        seal_seed,
        keys,
        id,
    }
}

fn recovery_party(n: u8) -> Party {
    let (sign_seed, seal_seed) = recovery::derive(&[n; 16]);
    let sign = SecretKey::from_seed(&sign_seed);
    let keys = Keys {
        sign: sign.public(),
        seal: Box::new(seal_public(&seal_seed)),
    };
    let id = recovery_id(&keys.sign, &keys.seal);
    Party {
        sign,
        seal_seed,
        keys,
        id,
    }
}

fn device_obj(p: &Party, level: u64) -> Device {
    Device {
        id: p.id,
        keys: p.keys.clone(),
        name: "x".into(),
        level,
    }
}

fn key_set(to: &Party, recovery: bool, epochs: &[u64], keys: &[[u8; 32]]) -> KeySet {
    KeySet {
        to: if recovery {
            Author::Recovery(to.id)
        } else {
            Author::Device(to.id)
        },
        epochs: epochs.to_vec(),
        sealed: seal_key_set(&to.keys.seal[..], &LOG, &to.id, epochs, keys).unwrap(),
    }
}

fn sorted(mut v: Vec<KeySet>) -> Vec<KeySet> {
    v.sort_by(|a, b| a.to.id().cmp(b.to.id()));
    v
}

/// A space and the app key of each epoch, with a helper for each record.
struct Space {
    s: MemorySpace,
    keys: Vec<[u8; 32]>,
    levels: Levels,
}

impl Space {
    /// Genesis by recovery key `r` with first device `a` at device level
    /// `level`.
    fn new(r: &Party, a: &Party, level: u64, levels: Levels) -> Self {
        let k1 = [1; 32];
        let base = Position {
            position: 0,
            digest: snailfish_protocol::hash::digest0(&LOG),
        };
        let ks = sorted(vec![
            key_set(a, false, &[1], &[k1]),
            key_set(r, true, &[1], &[k1]),
        ]);
        let payload = write::genesis(
            &LOG,
            &Author::Recovery(r.id),
            &base,
            &write::Genesis {
                app: "com.example.tasks",
                recovery: &r.keys,
                level: 1,
                device: &device_obj(a, level),
                commitment: &key_commitment(&LOG, 1, &k1),
                keys: &ks,
            },
        );
        let env = sign(r, "snailfish.genesis.v1", payload);
        let mut s = MemorySpace::new(LOG);
        s.apply(&check_genesis(&env, &LOG, Some(&a.id)).unwrap());
        Self {
            s,
            keys: vec![k1],
            levels,
        }
    }

    fn head(&self) -> Position {
        let n = self.s.head();
        Position {
            position: n,
            digest: self.s.digest_at(n).unwrap(),
        }
    }

    fn check(&self, env: &Envelope) -> Verdict {
        check_append_at(&self.s, env, Mode::Verify, &self.levels)
    }

    /// Check and apply. Panics on a refusal.
    fn push(&mut self, env: &Envelope) {
        match self.check(env) {
            Verdict::Store(a) => self.s.apply(&a),
            other => panic!("refused: {other:?}"),
        }
    }

    fn epochs(&self) -> Vec<u64> {
        (1..=self.s.state.epoch).collect()
    }

    fn grant(&self, by: &Party, by_recovery: bool, to: &Party, level: u64) -> Envelope {
        let author = if by_recovery {
            Author::Recovery(by.id)
        } else {
            Author::Device(by.id)
        };
        let ks = key_set(to, false, &self.epochs(), &self.keys);
        sign(
            by,
            "snailfish.grant.v1",
            write::grant(&LOG, &author, &self.head(), &device_obj(to, level), &ks),
        )
    }

    /// An epoch record by `by` that removes `removed`, with the devices that
    /// stay `stay` and the recovery key set to `rec`. It returns the new key.
    fn epoch(
        &self,
        by: &Party,
        removed: &[&Party],
        stay: &[&Party],
        rec: &Party,
    ) -> (Envelope, [u8; 32]) {
        let e = self.s.state.epoch.checked_add(1).unwrap();
        let key = [u8::try_from(e).unwrap(); 32];
        let mut ks: Vec<KeySet> = stay
            .iter()
            .map(|p| key_set(p, false, &[e], &[key]))
            .collect();
        ks.push(key_set(rec, true, &[e], &[key]));
        let mut removed: Vec<Hash32> = removed.iter().map(|p| p.id).collect();
        removed.sort_unstable();
        let mut stay_ids: Vec<Hash32> = stay.iter().map(|p| p.id).collect();
        stay_ids.sort_unstable();
        let payload = write::epoch(
            &LOG,
            &Author::Device(by.id),
            &self.head(),
            &write::Epoch {
                epoch: e,
                removed: &removed,
                stay: &stay_ids,
                commitment: &key_commitment(&LOG, e, &key),
                keys: &sorted(ks),
            },
        );
        (sign(by, "snailfish.epoch.v1", payload), key)
    }

    fn recovery(&self, by: &Party, new: &Party) -> Envelope {
        let proof = new.sign.sign_raw(&recovery::proof_message(
            &LOG,
            &new.keys.sign,
            &new.keys.seal[..],
        ));
        let ks = key_set(new, true, &self.epochs(), &self.keys);
        sign(
            by,
            "snailfish.recovery.v1",
            write::recovery(
                &LOG,
                &Author::Recovery(by.id),
                &self.head(),
                &new.keys,
                &proof,
                &ks,
            ),
        )
    }

    fn level(&self, ptype: &str, by: &Party, level: u64) -> Envelope {
        sign(by, ptype, write::level(&LOG, &by.id, &self.head(), level))
    }

    fn change(&self, by: &Party, epoch: u64, n: u8) -> Envelope {
        let payload = write::change(&LOG, &by.id, &self.head(), epoch, &[n; 16], &[0; 40]);
        sign(by, "snailfish.change.v1", payload)
    }
}

fn sign(by: &Party, ptype: &str, payload: Vec<u8>) -> Envelope {
    Envelope {
        sig: by.sign.sign_record(ptype, &payload),
        payload_type: ptype.into(),
        payload,
    }
}

fn invalid(v: &Verdict) -> bool {
    matches!(v, Verdict::Refused(Refusal::InvalidRecord(_)))
}

/// Genesis by R1 with A, then grants of B and C.
fn three() -> (Space, Party, Party, Party, Party) {
    let (r1, a, b, c) = (recovery_party(1), party(1), party(2), party(3));
    let mut sp = Space::new(&r1, &a, 1, Levels::CURRENT);
    sp.push(&sp.grant(&a, false, &b, 1));
    sp.push(&sp.grant(&a, false, &c, 1));
    (sp, r1, a, b, c)
}

/// `specs/spacelog/test.qnt::removalTest`, [LOG-8], T8: A removes C. The new
/// key opens for A, B and R1, and not for C. Each later record by C is
/// `not_active`, and C cannot be granted again.
#[test]
fn removal_seals_the_new_key_only_to_the_devices_that_stay() {
    let (mut sp, r1, a, b, c) = three();
    let (env, key) = sp.epoch(&a, &[&c], &[&a, &b], &r1);
    sp.push(&env);
    sp.keys.push(key);
    assert_eq!(sp.s.state.epoch, 2);
    assert!(sp.s.is_removed(&c.id) && sp.s.device_key(&c.id).is_none());
    let snailfish_protocol::records::Record { body, .. } =
        snailfish_protocol::records::parse_payload(&env.payload_type, &env.payload).unwrap();
    let snailfish_protocol::records::Body::Epoch { keys, .. } = body else {
        panic!("epoch record");
    };
    for p in [&a, &b, &r1] {
        let k = keys.iter().find(|k| k.to.id() == &p.id).unwrap();
        assert_eq!(
            open_key_set(&p.seal_seed, &LOG, &p.id, &[2], &k.sealed).unwrap(),
            vec![key]
        );
    }
    assert!(keys.iter().all(|k| k.to.id() != &c.id));
    // T8: the removed device cannot sign a change, a grant or a removal.
    assert_eq!(
        sp.check(&sp.change(&c, 2, 1)),
        Verdict::Refused(Refusal::NotActive)
    );
    assert_eq!(
        sp.check(&sp.grant(&c, false, &party(4), 1)),
        Verdict::Refused(Refusal::NotActive)
    );
    // [LOG-8]: a removal is final, so a grant of C again is invalid.
    assert!(invalid(&sp.check(&sp.grant(&a, false, &c, 1))));
    // [DLV-7]: a change must use the new epoch.
    assert_eq!(
        sp.check(&sp.change(&a, 1, 2)),
        Verdict::Refused(Refusal::WrongEpoch)
    );
    assert!(matches!(sp.check(&sp.change(&a, 2, 2)), Verdict::Store(_)));
}

/// `specs/spacelog/test.qnt::resignEpochReconfirmTest`, [LOG-7], T8: a grant
/// of D arrives before the removal of C. The removal that names the old
/// list of devices that stay is invalid on the new state, so the engine must
/// sign a new list after a new confirmation.
#[test]
fn removal_with_an_old_list_of_devices_that_stay_is_refused() {
    let (mut sp, r1, a, b, c) = three();
    let d = party(4);
    let (old, _) = sp.epoch(&a, &[&c], &[&a, &b], &r1);
    sp.push(&sp.grant(&a, false, &d, 1));
    // The base of the old record is now before the grant: stale_base.
    assert_eq!(sp.check(&old), Verdict::Refused(Refusal::StaleBase));
    // The same list on the new tip still leaves out D.
    let (resigned, _) = sp.epoch(&a, &[&c], &[&a, &b], &r1);
    assert!(invalid(&sp.check(&resigned)));
    let (confirmed, _) = sp.epoch(&a, &[&c], &[&a, &b, &d], &r1);
    sp.push(&confirmed);
    assert_eq!(sp.s.active_devices().len(), 3);
}

/// [LOG-8] `PROTOCOL.md` 10.6 step 13: the other state rules of an epoch
/// record. Each one is invalid on the state after the three grants.
#[test]
fn epoch_state_rules() {
    let (sp, r1, a, b, c) = three();
    let r2 = recovery_party(2);
    let (self_removal, _) = sp.epoch(&a, &[&a], &[&b, &c], &r1);
    let (not_active, _) = sp.epoch(&a, &[&party(9)], &[&a, &b, &c], &r1);
    let (old_recovery, _) = sp.epoch(&a, &[&c], &[&a, &b], &r2);
    for env in [self_removal, not_active, old_recovery] {
        assert!(invalid(&sp.check(&env)));
    }
    // A rotation with no removed device is valid (PROTOCOL.md 13.3).
    let (rotation, _) = sp.epoch(&a, &[], &[&a, &b, &c], &r1);
    assert!(matches!(sp.check(&rotation), Verdict::Store(_)));
}

/// `specs/spacelog/test.qnt::recoveryReplaceTest` and
/// `spacelogTestThief::oldRecoveryRefusedTest`, T9: R1 signs a recovery
/// record to R2. R1 can no longer sign, an epoch record sealed to R1 is
/// invalid, and one sealed to R2 is valid. R2 cannot be replaced by R1 again.
#[test]
fn recovery_record_replaces_the_recovery_key() {
    let (mut sp, r1, a, b, c) = three();
    let r2 = recovery_party(2);
    sp.push(&sp.recovery(&r1, &r2));
    assert!(sp.s.recovery_key(&r2.id).is_some() && sp.s.recovery_key(&r1.id).is_none());
    assert_eq!(
        sp.check(&sp.grant(&r1, true, &party(4), 1)),
        Verdict::Refused(Refusal::NotActive)
    );
    assert!(invalid(&sp.check(&sp.recovery(&r2, &r1))));
    assert!(invalid(&sp.check(&sp.recovery(&r2, &r2))));
    let (to_old, _) = sp.epoch(&a, &[&c], &[&a, &b], &r1);
    assert!(invalid(&sp.check(&to_old)));
    let (to_new, _) = sp.epoch(&a, &[&c], &[&a, &b], &r2);
    sp.push(&to_new);
}

/// `specs/spacelog/test.qnt::fullRecoveryTest`, S5: no trusted device
/// survives. The recovery key grants a new device D with each epoch key, and
/// D removes the old devices as an active device.
#[test]
fn full_recovery_grants_a_new_device_that_removes_the_old_ones() {
    let (mut sp, r1, a, b, c) = three();
    let (rot, k2) = sp.epoch(&a, &[], &[&a, &b, &c], &r1);
    sp.push(&rot);
    sp.keys.push(k2);
    let d = party(4);
    // A grant that misses an epoch key is invalid (PROTOCOL.md 10.6 step 13).
    let short = {
        let ks = key_set(&d, false, &[1], &sp.keys[..1]);
        sign(
            &r1,
            "snailfish.grant.v1",
            write::grant(
                &LOG,
                &Author::Recovery(r1.id),
                &sp.head(),
                &device_obj(&d, 1),
                &ks,
            ),
        )
    };
    assert!(invalid(&sp.check(&short)));
    sp.push(&sp.grant(&r1, true, &d, 1));
    let (env, _) = sp.epoch(&d, &[&a, &b, &c], &[&d], &r1);
    sp.push(&env);
    assert_eq!(sp.s.active_devices(), vec![d.id]);
    assert_eq!(sp.s.state.epoch, 3);
}

/// `specs/levels/test.qnt::raiseAfterUpdatesTest`, `removalThenRaiseTest`
/// and `downgradeRefusedTest`, [VER-7] [VER-8] [VER-10], with a synthetic
/// level 2 (D5): a raise needs every active device at level 2. A removal of
/// the device below ends the block. A device record cannot lower a level.
#[test]
fn level_raise_needs_every_active_device() {
    let two = Levels {
        max: 2,
        retired: &[],
    };
    let (r1, a, b, c) = (recovery_party(1), party(1), party(2), party(3));
    let mut sp = Space::new(&r1, &a, 1, two);
    sp.push(&sp.grant(&a, false, &b, 1));
    sp.push(&sp.grant(&a, false, &c, 1));
    sp.push(&sp.level("snailfish.device.v1", &a, 2));
    sp.push(&sp.level("snailfish.device.v1", &b, 2));
    assert!(invalid(&sp.check(&sp.level("snailfish.device.v1", &b, 2))));
    assert!(invalid(&sp.check(&sp.level("snailfish.device.v1", &b, 1))));
    // C is at level 1: the raise is invalid.
    assert!(invalid(&sp.check(&sp.level("snailfish.level.v1", &a, 2))));
    let (env, key) = sp.epoch(&a, &[&c], &[&a, &b], &r1);
    sp.push(&env);
    sp.keys.push(key);
    sp.push(&sp.level("snailfish.level.v1", &a, 2));
    assert_eq!(sp.s.state.level, 2);
    // A grant below the new write level is invalid ([VER-8], Enrollment).
    assert!(invalid(&sp.check(&sp.grant(&a, false, &party(4), 1))));
    // A level above the highest level of the verifier is unsupported.
    assert_eq!(
        sp.check(&sp.level("snailfish.device.v1", &a, 3)),
        Verdict::Refused(Refusal::Unsupported)
    );
    // With only level 1, a raise to 2 is unsupported (production).
    assert_eq!(
        check_append(&sp.s, &sp.level("snailfish.level.v1", &a, 3), Mode::Verify),
        Verdict::Refused(Refusal::Unsupported)
    );
}

/// `specs/levels/test.qnt::lowLevelRefusedTest`, [VER-9]: after a raise, a
/// record type that the new write level drops is `unsupported`. The
/// synthetic level 2 drops `snailfish.device.v1`.
#[test]
fn a_type_that_the_write_level_drops_is_unsupported() {
    let two = Levels {
        max: 2,
        retired: &[("snailfish.device.v1", 2)],
    };
    let (r1, a) = (recovery_party(1), party(1));
    let mut sp = Space::new(&r1, &a, 2, two);
    let device_record = sp.level("snailfish.device.v1", &a, 2);
    assert!(invalid(&sp.check(&device_record)));
    sp.push(&sp.level("snailfish.level.v1", &a, 2));
    assert_eq!(
        sp.check(&sp.level("snailfish.device.v1", &a, 2)),
        Verdict::Refused(Refusal::Unsupported)
    );
    assert!(matches!(sp.check(&sp.change(&a, 1, 1)), Verdict::Store(_)));
}

/// [LOG-8] `PROTOCOL.md` 10.6: the overlay of one append request applies an
/// earlier epoch record and recovery record to the later envelopes.
#[test]
fn overlay_applies_earlier_records_of_the_request() {
    let (sp, r1, a, b, c) = three();
    let r2 = recovery_party(2);
    let mut over = snailfish_protocol::space::Overlay::new(&sp.s);
    let rec = sp.recovery(&r1, &r2);
    match check_append(&over, &rec, Mode::Verify) {
        Verdict::Store(acc) => over.apply(*acc),
        other => panic!("{other:?}"),
    }
    assert!(over.recovery_key(&r1.id).is_none() && over.recovery_key(&r2.id).is_some());
    assert!(over.recovery_known(&r1.id));
    let mut tip = Space {
        s: sp.s.clone(),
        keys: sp.keys.clone(),
        levels: Levels::CURRENT,
    };
    tip.s.apply(&match check_append(&sp.s, &rec, Mode::Verify) {
        Verdict::Store(a) => *a,
        other => panic!("{other:?}"),
    });
    let (env, _) = tip.epoch(&a, &[&c], &[&a, &b], &r2);
    match check_append(&over, &env, Mode::Verify) {
        Verdict::Store(acc) => over.apply(*acc),
        other => panic!("{other:?}"),
    }
    assert_eq!(over.epoch(), 2);
    assert!(over.is_removed(&c.id) && over.device_key(&c.id).is_none());
    assert_eq!(over.active_devices().len(), 2);
}

/// [LOG-8] [VER-7] [VER-8] `PROTOCOL.md` 10.6, `specs/levels/test.qnt::removalThenRaiseTest`,
/// with a synthetic level 2 (D5): the overlay of one append request applies
/// earlier device records, an epoch record and a level record to the later
/// envelopes. Without this, a relay would judge the second record of one
/// request by the levels before the first record.
#[test]
fn overlay_applies_earlier_level_records_of_the_request() {
    let two = Levels {
        max: 2,
        retired: &[],
    };
    let (r1, a, b, c) = (recovery_party(1), party(1), party(2), party(3));
    let mut sp = Space::new(&r1, &a, 1, two);
    sp.push(&sp.grant(&a, false, &b, 1));
    sp.push(&sp.grant(&a, false, &c, 1));
    let mut over = snailfish_protocol::space::Overlay::new(&sp.s);
    // Each envelope names the head after the envelopes before it, so `tip`
    // applies the same records as `over` to build them.
    let mut tip = Space {
        s: sp.s.clone(),
        keys: sp.keys.clone(),
        levels: two,
    };
    let mut send = |tip: &mut Space, env: &Envelope| {
        let v = check_append_at(&over, env, Mode::Verify, &two);
        if let Verdict::Store(acc) = &v {
            over.apply((**acc).clone());
            tip.push(env);
        }
        v
    };
    let env = tip.level("snailfish.device.v1", &a, 2);
    assert!(matches!(send(&mut tip, &env), Verdict::Store(_)));
    let env = tip.level("snailfish.device.v1", &b, 2);
    assert!(matches!(send(&mut tip, &env), Verdict::Store(_)));
    // C is still at level 1.
    let env = tip.level("snailfish.level.v1", &a, 2);
    assert!(invalid(&send(&mut tip, &env)));
    let (env, key) = tip.epoch(&a, &[&c], &[&a, &b], &r1);
    assert!(matches!(send(&mut tip, &env), Verdict::Store(_)));
    tip.keys.push(key);
    let env = tip.level("snailfish.level.v1", &a, 2);
    assert!(matches!(send(&mut tip, &env), Verdict::Store(_)));
    // A grant below the new write level is invalid.
    let env = tip.grant(&a, false, &party(4), 1);
    assert!(invalid(&send(&mut tip, &env)));
}

// ---------------------------------------------------------------- M8

impl Space {
    /// A grant of `to` by the device `by` with a key set of `epochs` only.
    fn grant_with(&self, by: &Party, to: &Party, epochs: &[u64]) -> Envelope {
        let keys: Vec<[u8; 32]> = epochs
            .iter()
            .map(|e| self.keys[usize::try_from(e.checked_sub(1).unwrap()).unwrap()])
            .collect();
        let ks = key_set(to, false, epochs, &keys);
        sign(
            by,
            "snailfish.grant.v1",
            write::grant(
                &LOG,
                &Author::Device(by.id),
                &self.head(),
                &device_obj(to, 1),
                &ks,
            ),
        )
    }

    /// A snapshot by `by` in `epoch` of the state at position `state`.
    fn snapshot(&self, by: &Party, state: u64, epoch: u64) -> Envelope {
        let at = Position {
            position: state,
            digest: self.s.digest_at(state).unwrap(),
        };
        let payload = write::snapshot(&LOG, &by.id, &self.head(), epoch, &at, &[0; 48]);
        sign(by, "snailfish.snapshot.v1", payload)
    }

    /// An accept by `by` of the snapshot at `snap`, applied to the head.
    fn accept(&self, by: &Party, snap: u64) -> Envelope {
        let hash = self.s.snapshot_hash(snap).unwrap();
        let head = self.head();
        let payload = write::accept(&LOG, &by.id, &head, snap, &hash, &head);
        sign(by, "snailfish.accept.v1", payload)
    }
}

/// `specs/compaction/test.qnt::sealNeededTest`, [CMP-20] `PROTOCOL.md`
/// 14.5: A removes C (epoch 2), changes in epoch 2 and removes B (epoch 3).
/// No snapshot covers the change, so a grant must hold epoch 2. Without
/// this, a new device would get no key for a change that it must apply.
#[test]
fn grant_needs_the_epoch_of_an_uncovered_change() {
    let (mut sp, r1, a, b, c) = three();
    let (env, key) = sp.epoch(&a, &[&c], &[&a, &b], &r1);
    sp.push(&env);
    sp.keys.push(key);
    sp.push(&sp.change(&a, 2, 1));
    let (env, key) = sp.epoch(&a, &[&b], &[&a], &r1);
    sp.push(&env);
    sp.keys.push(key);
    let d = party(4);
    assert!(invalid(&sp.check(&sp.grant_with(&a, &d, &[3]))));
    assert!(matches!(
        sp.check(&sp.grant_with(&a, &d, &[2, 3])),
        Verdict::Store(_)
    ));
}

/// A change by A in epoch 1 (4), the removal of C (epoch 2, at 5), a
/// snapshot of A in epoch 2 of the state at 4 (6) and the accept of A (7).
/// B has not accepted, so no snapshot is usable.
fn snapshot_blocked_by_b() -> (Space, Party, Party, Party) {
    let (mut sp, r1, a, b, c) = three();
    sp.push(&sp.change(&a, 1, 1));
    let (env, key) = sp.epoch(&a, &[&c], &[&a, &b], &r1);
    sp.push(&env);
    sp.keys.push(key);
    sp.push(&sp.snapshot(&a, 4, 2));
    sp.push(&sp.accept(&a, 6));
    (sp, r1, a, b)
}

/// Check each envelope of one append request against the overlay, as the
/// relay does (`PROTOCOL.md` 10.6). `tip` applies the stored ones, so the
/// next envelope names the head after them.
fn overlay_send(
    over: &mut snailfish_protocol::space::Overlay<'_, MemorySpace>,
    tip: &mut Space,
    env: &Envelope,
) -> Verdict {
    let v = check_append(&*over, env, Mode::Verify);
    if let Verdict::Store(acc) = &v {
        over.apply((**acc).clone());
        tip.push(env);
    }
    v
}

/// [CMP-7] [CMP-20]: in one request, A removes B and then grants D. The
/// removal makes the snapshot usable, which covers the change in epoch 1,
/// so the grant needs epochs 2 and 3 only. Without the overlay of the
/// removal, the relay would refuse the grant of the device that signed it.
#[test]
fn overlay_removal_makes_the_snapshot_usable_for_a_later_grant() {
    let (sp, r1, a, b) = snapshot_blocked_by_b();
    let mut over = snailfish_protocol::space::Overlay::new(&sp.s);
    let mut tip = Space {
        s: sp.s.clone(),
        keys: sp.keys.clone(),
        levels: Levels::CURRENT,
    };
    let (env, key) = tip.epoch(&a, &[&b], &[&a], &r1);
    assert!(matches!(
        overlay_send(&mut over, &mut tip, &env),
        Verdict::Store(_)
    ));
    tip.keys.push(key);
    let grant = tip.grant_with(&a, &party(4), &[2, 3]);
    let v = overlay_send(&mut over, &mut tip, &grant);
    assert!(matches!(v, Verdict::Store(_)), "{v:?}");
}

/// [CMP-6] [CMP-20]: in one request, A grants D, then B accepts. D is
/// active from its grant and has not accepted, so the snapshot is not
/// usable, and a grant of E must still hold epoch 1. Without the overlay of
/// the grant, the relay would give E a key set without the key of the
/// change in epoch 1.
#[test]
fn overlay_grant_keeps_the_snapshot_blocked_for_a_later_grant() {
    let (sp, _r1, a, b) = snapshot_blocked_by_b();
    let mut over = snailfish_protocol::space::Overlay::new(&sp.s);
    let mut tip = Space {
        s: sp.s.clone(),
        keys: sp.keys.clone(),
        levels: Levels::CURRENT,
    };
    let grant_d = tip.grant_with(&a, &party(4), &[1, 2]);
    assert!(matches!(
        overlay_send(&mut over, &mut tip, &grant_d),
        Verdict::Store(_)
    ));
    let accept = tip.accept(&b, 6);
    assert!(matches!(
        overlay_send(&mut over, &mut tip, &accept),
        Verdict::Store(_)
    ));
    let short = tip.grant_with(&a, &party(5), &[2]);
    assert!(invalid(&overlay_send(&mut over, &mut tip, &short)));
    let full = tip.grant_with(&a, &party(5), &[1, 2]);
    let v = overlay_send(&mut over, &mut tip, &full);
    assert!(matches!(v, Verdict::Store(_)), "{v:?}");
}

/// [CMP-5] `PROTOCOL.md` 14.4: an accept can name a snapshot that an earlier
/// envelope of the same request holds. A change comes first, so the
/// overlay must find the snapshot by its position.
#[test]
fn overlay_accept_names_a_snapshot_of_the_same_request() {
    let (sp, _r1, a, _b, _c) = three();
    let mut over = snailfish_protocol::space::Overlay::new(&sp.s);
    let mut tip = Space {
        s: sp.s.clone(),
        keys: sp.keys.clone(),
        levels: Levels::CURRENT,
    };
    let change = tip.change(&a, 1, 1);
    assert!(matches!(
        overlay_send(&mut over, &mut tip, &change),
        Verdict::Store(_)
    ));
    let snap = tip.snapshot(&a, 4, 1);
    assert!(matches!(
        overlay_send(&mut over, &mut tip, &snap),
        Verdict::Store(_)
    ));
    let accept = tip.accept(&a, 5);
    let v = overlay_send(&mut over, &mut tip, &accept);
    assert!(matches!(v, Verdict::Store(_)), "{v:?}");
}
