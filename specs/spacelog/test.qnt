// Scenario tests for model.qnt. specs/tools/verify.py runs them, also with the
// BUG of each mutant that sampling does not catch.
module spacelogTest {
  import spacelog(DEVS = Set(1, 2, 3), BAD = Set(), MAX_REC = 8, MAX_ATTACKS = 3,
                  FAULTS = Set("fork"), BUG = "none").* from "./model"

  // The honest relay appends or refuses the record with this id.
  action appendId(k: int): bool = {
    nondet r = pending.filter(x => x.id == k).oneOf()
    relayAppend(r)
  }
  action refuseId(k: int): bool = {
    nondet r = pending.filter(x => x.id == k).oneOf()
    relayRefuse(r)
  }
  // The malicious relay appends the signed record with this id to a branch.
  action appendAnyId(k: int, b: int): bool = {
    nondet r = env.signed.filter(x => x.id == k).oneOf()
    appendAny(r, b)
  }

  // Device 1 creates the space and device 2 joins: ids 1 (genesis) and 2 (grant).
  // Device 1 sends a checkpoint at position 2. Device 2 verifies the log up to it.
  action enrolTwo: bool =
    init
      .then(createSpace(1))
      .then(appendId(1))
      .then(signGrant(1, 1, 2))
      .then(appendId(2))
      .then(fetchOne(1, 0))
      .then(sendCheckpoint(1, 2))
      .then(fetchOne(2, 0))
      .then(fetchOne(2, 0))

  // S2: a trusted device appends the grant and sends a checkpoint. The new
  // device checks the log up to the checkpoint and can then write.
  run grantWithCheckpointTest =
    enrolTwo
      .expect(happened(EvGrantAppended) and happened(EvCheckpoint) and happened(EvEnrolled))
      .expect(dev(2).status == Running and dev(2).log.sp.active == Set(1, 2))
      .expect(dev(2).log.sp.keys == dev(1).log.sp.keys)
      .expect(branches.get(0).recs.nth(1).sealed == Set(1) and holders(1, env.signed) == Set(1, 2, RK))
      .then(signChange(2))
      .then(appendId(3))
      .expect(branches.get(0).recs.length() == 3 and happened(EvChangeAppended))

  // A device with no checkpoint does not fetch.
  run noCheckpointNoFetchTest =
    init
      .then(createSpace(1))
      .then(appendId(1))
      .then(fetchOne(2, 0)).fail()

  // S4: the removal is an epoch record. The removed device cannot append a
  // record afterwards, and the new key is not sealed to it.
  run removalTest =
    enrolTwo
      .then(signEpoch(1, 1, 2))
      .then(appendId(3))
      .expect(happened(EvRemovalAppended) and branches.get(0).sp.epoch == 2)
      .expect(branches.get(0).sp.removed == Set(2) and branches.get(0).sp.active == Set(1))
      .expect(holders(3, env.signed) == Set(1, RK) and not(holders(3, env.signed).contains(2)))
      // Device 2 has not verified the removal yet. The relay refuses its grant.
      .then(signGrant(2, 2, 3))
      .then(refuseId(4))
      .expect(happened(EvRefusedAuthor) and branches.get(0).recs.length() == 3)
      // The old key stays with device 2. It cannot read the new key.
      .then(fetchOne(2, 0))
      .expect(dev(2).log.sp.removed == Set(2) and not(happened(EvEpochVerified)))
      .then(fetchOne(1, 0))
      .expect(happened(EvEpochVerified) and dev(1).wepoch == 2)
      .then(signChange(1))
      .then(appendId(5))
      .expect(happened(EvNewEpochChange))
      .expect(noKeyToRemoved and removedKeyIsolation and authorActive)
      // Device 2 verified the removal. It cannot sign a grant.
      .then(signGrant(2, 2, 3)).fail()

  // Two security records with the same base. The relay appends the first and
  // refuses the second under the base rule. The author signs again on the new tip.
  run baseRaceTest =
    enrolTwo
      .then(signGrant(1, 1, 3))
      .then(signEpoch(2, 2, 1))
      .expect(env.signed.filter(x => x.id == 3 or x.id == 4).forall(x => x.bpos == 2))
      .then(appendId(3))
      .then(refuseId(4))
      .expect(happened(EvRefusedBaseRule) and branches.get(0).recs.length() == 3)
      .expect(baseRule and relayLogValid)
      .then(fetchOne(2, 0))
      .then(signEpoch(2, 2, 1))
      .then(appendId(5))
      .expect(branches.get(0).recs.length() == 4 and branches.get(0).sp.removed == Set(1))
      .expect(baseRule and relayLogValid)

  // T7: a malicious relay serves two valid branches. Device 1 and device 2 each
  // accept their own branch. When the relay serves branch 1 to device 1, the
  // base of the next record is not in its log. Device 1 stops with fork.
  run forkDetectedTest =
    enrolTwo
      .then(signGrant(1, 1, 3))
      .then(signChange(2))
      .then(appendId(3))
      .then(forkBranch(2))
      .then(appendAnyId(4, 1))
      .then(fetchOne(1, 0))
      .then(fetchOne(2, 1))
      .expect(not(noFork) and dev(1).status == Running and dev(2).status == Running)
      .then(signChange(2))
      .then(appendAnyId(5, 1))
      .then(fetchOne(1, 1))
      .expect(dev(1).status == Forked and happened(EvForkDetected) and forkStops)
      .then(fetchOne(1, 0)).fail()

}
