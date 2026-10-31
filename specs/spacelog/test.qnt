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

  // [LOG-9] The first device holds the genesis record from the setup, before
  // any fetch. Its first fetch reads position 2, so the relay cannot give it
  // another genesis record (crates/engine relay_with_another_genesis_record_stops).
  run creatorHoldsGenesisTest =
    init
      .then(createSpace(1))
      .expect(dev(1).log.recs.length() == 1 and dev(1).log.recs.nth(0).kind == Genesis
              and dev(1).status == Running)
      .then(appendId(1))
      .then(fetchOne(1, 0)).fail()

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

// Scripted tests for mutants that a 2-device sample seldom reaches. Each one
// passes on the design and fails under the BUG that checks.toml names for it.
module spacelogTest4 {
  import spacelog(DEVS = Set(1, 2, 3, 4), BAD = Set(), MAX_REC = 9, MAX_ATTACKS = 0,
                  FAULTS = Set(), BUG = "none").* from "./model"

  action appendId(k: int): bool = {
    nondet r = pending.filter(x => x.id == k).oneOf()
    relayAppend(r)
  }
  action refuseId(k: int): bool = {
    nondet r = pending.filter(x => x.id == k).oneOf()
    relayRefuse(r)
  }
  // The relay appends the record if `check` accepts it, and refuses it if not.
  action relayDecides(k: int): bool =
    if (relayVerdict(pending.filter(x => x.id == k).getOnlyElement()) == Ok) appendId(k) else refuseId(k)
  // Fetch one record if the branch has one more for device d. If not, change nothing.
  action fetchIfAny(d: Key): bool =
    if (branches.get(0).recs.length() > dev(d).log.recs.length() and dev(d).status == Running) fetchOne(d, 0)
    else all { devs' = devs, branches' = branches, pending' = pending, env' = env }
  action enrolTwo: bool =
    init
      .then(createSpace(1)).then(appendId(1))
      .then(signGrant(1, 1, 2)).then(appendId(2))
      .then(fetchOne(1, 0)).then(sendCheckpoint(1, 2))
      .then(fetchOne(2, 0)).then(fetchOne(2, 0))

  // Mutants noBaseRule and relayNoBaseRule ([LOG-7]). Two grants for two new
  // devices on one base. The second grant is valid on the state after the
  // first, so only the base rule refuses it. Two devices are not enough: each
  // pair of security records with 2 devices fails another check first.
  run concurrentGrantsTest =
    enrolTwo
      .then(signGrant(1, 1, 3))
      .then(signGrant(2, 2, 4))
      .then(appendId(3))
      .then(relayDecides(4))
      .then(fetchOne(1, 0))
      .then(fetchIfAny(1))
      .expect(baseRule and relayLogValid and branches.get(0).recs.length() == 3)

  // Mutant resignReusesKey ([LOG-7] [LOG-8]). Device 2 signs a removal of
  // device 3 (key K, sealed to devices 1, 2 and 4). A grant wins the race, so
  // the relay refuses it under the base rule. Device 2 signs again: a removal
  // of device 1. That record must carry a new key, because the refused record
  // sealed K to device 1.
  run resignTest =
    enrolTwo
      .then(signGrant(1, 1, 3)).then(appendId(3))
      .then(fetchOne(1, 0)).then(fetchOne(2, 0))
      .then(signGrant(1, 1, 4)).then(signEpoch(2, 2, 3))
      .then(appendId(4)).then(refuseId(5))
      .then(fetchOne(2, 0))
      .then(signEpoch(2, 2, 1)).then(appendId(6))
      .then(fetchOne(2, 0))
      .expect(removedKeyIsolation)
}

// A thief (device 2) ignores its own removal.
module spacelogTestThief {
  import spacelog(DEVS = Set(1, 2, 3), BAD = Set(2), MAX_REC = 8, MAX_ATTACKS = 0,
                  FAULTS = Set("recovery"), BUG = "none").* from "./model"

  action appendId(k: int): bool = {
    nondet r = pending.filter(x => x.id == k).oneOf()
    relayAppend(r)
  }
  action refuseId(k: int): bool = {
    nondet r = pending.filter(x => x.id == k).oneOf()
    relayRefuse(r)
  }
  action relayDecides(k: int): bool =
    if (relayVerdict(pending.filter(x => x.id == k).getOnlyElement()) == Ok) appendId(k) else refuseId(k)
  action fetchIfAny(d: Key): bool =
    if (branches.get(0).recs.length() > dev(d).log.recs.length() and dev(d).status == Running) fetchOne(d, 0)
    else all { devs' = devs, branches' = branches, pending' = pending, env' = env }

  // Mutant grantFromRemoved ([LOG-8], C35). The thief verifies its own removal
  // and then grants a new device on the new tip. The relay and each verifier
  // must refuse a grant from a removed author.
  run thiefGrantTest =
    init
      .then(createSpace(1)).then(appendId(1))
      .then(signGrant(1, 1, 2)).then(appendId(2))
      .then(fetchOne(1, 0)).then(sendCheckpoint(1, 2))
      .then(fetchOne(2, 0)).then(fetchOne(2, 0))
      .then(signEpoch(1, 1, 2)).then(appendId(3))
      .then(fetchOne(2, 0)).then(fetchOne(1, 0))
      .then(signGrant(2, 2, 3))
      .then(relayDecides(4))
      .then(fetchIfAny(1))
      .expect(authorActive)
}


// A compromised device key (device 2) signs invalid records. Each record has a
// correct signature, so only the field checks of the verifier can refuse it.
// Bounded scope: the five templates of signInvalid, not a Byzantine key.
module spacelogTestCompromised {
  import spacelog(DEVS = Set(1, 2, 3), BAD = Set(2), MAX_REC = 8, MAX_ATTACKS = 4,
                  FAULTS = Set("signedInvalid", "reorder"), BUG = "none").* from "./model"

  action appendId(k: int): bool = {
    nondet r = pending.filter(x => x.id == k).oneOf()
    relayAppend(r)
  }
  action refuseId(k: int): bool = {
    nondet r = pending.filter(x => x.id == k).oneOf()
    relayRefuse(r)
  }
  action appendAnyId(k: int, b: int): bool = {
    nondet r = env.signed.filter(x => x.id == k).oneOf()
    appendAny(r, b)
  }
  // Ids 1 and 2 are the genesis and the grant. Both devices hold the log.
  action enrolTwo: bool =
    init
      .then(createSpace(1)).then(appendId(1))
      .then(signGrant(1, 1, 2)).then(appendId(2))
      .then(fetchOne(1, 0)).then(sendCheckpoint(1, 2))
      .then(fetchOne(2, 0)).then(fetchOne(2, 0))

  // The record with id 3 has a signature, and the prefix refuses it for a field
  // reason, not for the signature. The honest relay refuses it and stores nothing.
  def invalidSigned(v: Verdict): bool =
    env.signed.filter(x => x.id == 3).size() == 1 and env.hostile.contains(3)
      and relayVerdict(env.signed.filter(x => x.id == 3).getOnlyElement()) == v

  // Honest relay: the compromised key signs a grant that seals no keys.
  run honestRelayRefusesInvalidTest =
    enrolTwo
      .then(signInvalid(2, 0, 0, 3))
      .expect(wInvalidSigned and invalidSigned(BadState))
      .then(refuseId(3))
      .expect(wInvalidRelayRefused and branches.get(0).recs.length() == 2 and pending == Set())
      .expect(relayLogValid and grantSealsAllKeys)

  // Honest relay: a grant for an active device, and a self removal.
  run honestRelayRefusesActiveSubjectAndSelfRemovalTest =
    enrolTwo
      .then(signInvalid(2, 4, 0, 1))
      .expect(invalidSigned(BadState))
      .then(refuseId(3))
      .then(signInvalid(2, 2, 0, 3))
      .expect(relayVerdict(env.signed.filter(x => x.id == 4).getOnlyElement()) == BadState)
      .then(refuseId(4))
      .expect(branches.get(0).recs.length() == 2 and relayLogValid and grantSubjectNew and noSelfRemoval)

  // Malicious relay: it stores a grant with the wrong sealed keys. Device 1 stops
  // with rejected, and its verified log stays valid.
  run clientRejectsWrongSealedTest =
    enrolTwo
      .then(signInvalid(2, 0, 0, 3))
      .then(appendAnyId(3, 0))
      .expect(wInvalidStored and branches.get(0).recs.length() == 3)
      .then(fetchOne(1, 0))
      .expect(wInvalidClientRejected and dev(1).status == Rejected and dev(1).log.recs.length() == 2)
      .expect(grantSealsAllKeys and authorActive and baseInOwnLog)

  // Malicious relay: epoch skip. The epoch number is 3, not 2.
  run clientRejectsEpochSkipTest =
    enrolTwo
      .then(signInvalid(2, 1, 0, 1))
      .expect(invalidSigned(BadState))
      .then(appendAnyId(3, 0))
      .then(fetchOne(1, 0))
      .expect(wInvalidClientRejected and dev(1).status == Rejected and dev(1).log.sp.epoch == 1)
      .expect(epochSequential and noKeyToRemoved)

  // Malicious relay: the compromised key removes itself. Device 1 rejects it.
  run clientRejectsSelfRemovalTest =
    enrolTwo
      .then(signInvalid(2, 2, 0, 3))
      .then(appendAnyId(3, 0))
      .then(fetchOne(1, 0))
      .expect(wInvalidClientRejected and dev(1).status == Rejected and dev(1).log.sp.removed == Set())
      .expect(noSelfRemoval)

  // The same record meets both paths. The honest relay refuses it. A malicious
  // relay replays it from the signed set, and device 1 rejects it (active subject).
  run sameRecordRelayAndClientRejectTest =
    enrolTwo
      .then(signInvalid(2, 4, 0, 1))
      .then(refuseId(3))
      .expect(wInvalidRelayRefused and not(wInvalidStored) and branches.get(0).recs.length() == 2)
      .then(appendAnyId(3, 0))
      .expect(wInvalidStored)
      .then(fetchOne(1, 0))
      .expect(wInvalidClientRejected and dev(1).status == Rejected and grantSubjectNew)

  // A grant with a base digest that is not in the log stops the device with fork.
  run clientForksOnBadBaseTest =
    enrolTwo
      .then(signInvalid(2, 3, 0, 3))
      .expect(relayVerdict(env.signed.filter(x => x.id == 3).getOnlyElement()) == BadBase)
      .then(appendAnyId(3, 0))
      .then(fetchOne(1, 0))
      .expect(wInvalidClientRejected and dev(1).status == Forked and forkStops and baseInOwnLog)
}
