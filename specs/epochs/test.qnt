module epochsTest {
  import epochs(MAX_RECORDS = 4, MAX_RESTORES = 1, BUG = "none").* from "./model"

  // [DLV-7] Device 1 stays active. Its lost response does not permit re-encryption.
  run knownRetryAfterRotationTest =
    init.then(enqueue(1)).then(send(1, true)).then(remove(1, 2))
      .then(send(1, false))
      .expect(wKnownAfterEpoch and knownIdFirst and client(1).envelope.id == 1)
      .expect(client(1).envelope.epoch == 1 and s.relay.length() == 3)

  // [DLV-7] An unknown old-epoch change needs a refusal before a new envelope.
  run unknownRetryAfterRotationTest =
    init.then(enqueue(1)).then(remove(1, 2)).then(send(1, false))
      .expect(wStaleRefused and s.relay.length() == 2 and client(1).stale)
      .then(fetch(1)).then(reencrypt(1)).then(send(1, false))
      .expect(wReencryptedStored and relayAuthorised and s.relay.length() == 3)
      .expect(client(1).envelope.cid == 1 and client(1).envelope.id == 3 and client(1).envelope.epoch == 2)

  // [LOG-8] [LOG-9] Current epoch metadata does not authorise a removed signing key.
  run removedAuthorRefusedTest =
    init.then(remove(1, 2)).then(signUntrusted).then(send(2, false))
      .expect(s.relay.length() == 2 and relayAuthorised)

  // [LOG-10] Repair cannot omit the removal that the device already verified.
  run repairRetainsRotationTest =
    init.then(remove(1, 2)).then(fetch(1)).then(restore(1)).then(repair(1))
      .expect(wSecurityRepaired and repairComplete and epoch(s.relay) == 2)
      .expect(active(s.relay) == Set(1) and s.hold)

  // [LOG-14] [LOG-15] A removal can extend a restored prefix during a hold.
  // It can conflict with a lost change. No global no-fork guarantee follows.
  run removalDuringHoldCanForkTest =
    init.then(enqueue(2)).then(send(2, false)).then(fetch(2)).then(restore(1))
      .then(enqueue(1)).then(send(1, false))
      .expect(wHoldRefused and holdBlocksChanges and s.relay.length() == 1)
      .then(remove(1, 2)).then(fetch(1))
      .expect(wRemovalDuringHold and s.hold and not(noFork))
      .then(fetch(2))
      .expect(wConflict and client(2).stopped and relayAuthorised)
}
