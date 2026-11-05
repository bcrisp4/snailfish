module compactionTest {
  import compaction(MAX_IDS = 3, MAX_LEN = 12, QUOTA = 20, RESERVE = 6, SNAP_SIZE = 2,
    FAULTS = Set("rollback", "appRestore", "engineLoss", "badRepair", "unreadable", "destroy"),
    BUG = "none").* from "./model"

  // Device 1 writes two changes. Both devices apply them.
  action twoChanges: bool =
    init.then(edit(1)).then(push(1, 1)).then(edit(1)).then(push(1, 2))
      .then(fetch(1)).then(pull(1)).then(pull(1)).then(fetch(2)).then(pull(2)).then(pull(2))

  // Device 1 writes a snapshot at position 4. Both devices accept it.
  action bothAccepted: bool =
    twoChanges.then(writeSnapshot(1, true)).then(fetch(1)).then(fetch(2))
      .then(accept(1, 4)).then(accept(2, 4)).then(fetch(1)).then(fetch(2))

  // [CMP-5] [CMP-6] [CMP-12] [CMP-13] S7: after every active device accepts
  // the snapshot, the relay and each engine replace the covered changes with
  // stubs. Security and accept records stay in full.
  run compactTest =
    bothAccepted
      .expect(usable(s.relay, BUG) == 4 and frontier(s.relay, BUG) == 3)
      .then(relayCompact)
      .expect(at(s.relay, 2).stub and at(s.relay, 3).stub and not(at(s.relay, 4).stub))
      .expect(not(at(s.relay, 1).stub) and not(at(s.relay, 5).stub) and not(at(s.relay, 6).stub))
      .then(deviceCompact(1)).then(deviceCompact(2))
      .expect(at(dev(1).log, 2).stub and at(dev(2).log, 3).stub)
      .expect(stubsCovered and securityFull and appConsistent and noNeedlessReset)

  // [CMP-6] One accept is not enough: device 2 blocks compaction ([CMP-7]).
  run blockedTest =
    twoChanges.then(writeSnapshot(1, true)).then(fetch(1)).then(accept(1, 4))
      .expect(usable(s.relay, BUG) == 0)
      .then(relayCompact).fail()

  // [CMP-16] [CMP-8] A new device imports the usable snapshot, then pulls the
  // later changes. [CMP-6] The grant does not end the acceptance.
  run newDeviceTest =
    bothAccepted.then(relayCompact).then(edit(2)).then(push(2, 3)).then(grant).then(fetch(3))
      .expect(resetRequired(dev(3), BUG) and wAcceptedAfterGrant)
      .then(reset(3))
      .expect(dev(3).applied == 3 and dev(3).app == Set(1, 2))
      .then(pull(3))
      .expect(dev(3).app == Set(1, 2, 3) and appConsistent and wNewDeviceImport and readsNeeded)

  // [CMP-14] [DLV-12] A device that is offline while the relay makes stubs
  // goes back to an old app DB backup. It imports the snapshot. A covered
  // outbox row goes, and an outbox edit after the snapshot stays.
  run offlineResetTest =
    init.then(edit(2)).then(backupApp(2)).then(push(2, 1)).then(fetch(1)).then(pull(1))
      .then(fetch(2)).then(pull(2))
      .then(writeSnapshot(1, true)).then(fetch(1)).then(fetch(2))
      .then(accept(1, 3)).then(accept(2, 3)).then(relayCompact)
      .then(fetch(2)).then(deviceCompact(2)).then(restoreApp(2)).then(edit(2))
      .expect(dev(2).outbox == Set(1, 2) and resetRequired(dev(2), BUG))
      .then(reset(2))
      .expect(dev(2).outbox == Set(2) and dev(2).app == Set(1, 2) and dev(2).applied == 2)
      .expect(wCoveredDropped and outboxPending and appConsistent)
      .then(push(2, 2)).then(fetch(1)).then(pull(1))
      .expect(dev(1).app == Set(1, 2))

  // [CMP-5] A snapshot that does not decrypt gets no accept, so every change
  // stays in full.
  run unreadableTest =
    twoChanges.then(writeSnapshot(1, false)).then(fetch(1)).then(fetch(2))
      .then(accept(1, 4)).fail()

  // [CMP-4] [CMP-7] [CMP-9] [CMP-10] Device 2 never accepts. Device 1 removes
  // it, so the snapshot of device 1 is accepted. Device 1 then writes a new
  // snapshot with the same state position, which wins.
  run removalTest =
    twoChanges.then(writeSnapshot(2, true)).then(fetch(1)).then(accept(1, 4))
      .then(remove(1, 2))
      .expect(usable(s.relay, BUG) == 4)
      .then(writeSnapshot(1, true)).then(fetch(1)).then(accept(1, 7))
      .expect(usable(s.relay, BUG) == 7 and frontier(s.relay, BUG) == 3)
      .then(relayCompact)
      .expect(at(s.relay, 4).stub and not(at(s.relay, 7).stub) and stubsCovered)

  // [CMP-20] A change of epoch 1 after the frontier stays in full after a
  // removal. The grant must seal the key of epoch 1 with epoch 2.
  run sealNeededTest =
    bothAccepted.then(relayCompact).then(edit(1)).then(push(1, 3))
      .then(remove(1, 2)).then(grant)
      .expect(at(s.relay, 9).sealed == Set(1, 2) and readsNeeded)

  // [CMP-20] After the frontier passes each epoch 1 record, a grant seals
  // only epoch 2.
  run sealDropsOldTest =
    twoChanges.then(remove(1, 2)).then(edit(1)).then(push(1, 3)).then(fetch(1)).then(pull(1))
      .then(writeSnapshot(1, true)).then(fetch(1)).then(accept(1, 6)).then(grant)
      .expect(at(s.relay, 8).sealed == Set(2) and readsNeeded)

  // [CMP-11] [CMP-16] A snapshot stub after the applied position does not
  // raise ResetRequired: device 2 wrote an older snapshot after the usable one.
  run snapshotStubNoResetTest =
    init.then(edit(1)).then(push(1, 1)).then(edit(1)).then(push(1, 2))
      .then(fetch(1)).then(pull(1)).then(pull(1)).then(writeSnapshot(1, true))
      .then(fetch(2)).then(pull(2)).then(writeSnapshot(2, true)).then(pull(2))
      .then(accept(2, 4)).then(fetch(1)).then(accept(1, 4)).then(relayCompact)
      .expect(at(s.relay, 5).stub)
      .then(edit(1)).then(push(1, 3)).then(fetch(2))
      .expect(at(dev(2).log, 5).stub)
      .then(pull(2))
      .expect(dev(2).app == Set(1, 2, 3) and noNeedlessReset)

  // [LOG-11] [CMP-17] After a rollback, a device repairs the log with its
  // stubs, because the staged range holds the usable snapshot.
  run repairStubsTest =
    bothAccepted.then(relayCompact).then(deviceCompact(1))
      .then(rollback(1))
      .then(repair(1, 0))
      .expect(not(s.hold) and s.relay.length() == 6 and at(s.relay, 2).stub and wRepairStubs)
      .expect(stubsCovered)

  // [LOG-11] A staged stub that no usable snapshot covers is refused.
  run badRepairTest =
    bothAccepted.then(edit(1)).then(push(1, 3)).then(fetch(1)).then(relayCompact)
      .then(rollback(6)).then(repair(1, 7))
      .expect(s.hold and wBadRepairRefused and stubsCovered)

  // [CMP-18] At a full quota, the reserve takes the snapshot and the accept
  // records. [CMP-19] After the stubs, a queued change is stored.
  run quotaTest = {
    val q = QUOTA
    init.then(edit(1)).then(push(1, 1)).then(fetch(1)).then(pull(1))
      .then(all { s' = { ...s, relay: s.relay.replaceAt(1, { ...at(s.relay, 2), size: q }),
                                canon: s.canon.replaceAt(1, { ...at(s.canon, 2), size: q }) } })
      .then(edit(1)).then(push(1, 2))
      .expect(s.events.contains(EvQuotaRefused) and dev(1).outbox == Set(2))
      .then(fetch(2)).then(pull(2)).then(writeSnapshot(2, true))
      .expect(wSnapshotAtFull)
      .then(fetch(1)).then(fetch(2)).then(accept(1, 3)).then(accept(2, 3)).then(relayCompact)
      .then(push(1, 2))
      .expect(s.events.contains(EvStoredAfterCompaction) and withinQuota)
  }
}
