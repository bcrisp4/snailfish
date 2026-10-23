// Scenario tests for model.qnt. specs/tools/verify.py runs them, also with the
// BUG of each mutant that sampling does not catch.
module deliveryTest {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4, MAX_FAULTS = 3,
                  FAULTS = Set("appRestore", "engineLoss", "relayRestore", "silentRollback", "earlyRelease", "warnedRelease"),
                  BUG = "none").* from "./model"

  // Device d edits change id, enqueues it and the relay stores it.
  action editAndPush(d: Dev, id: Id): bool =
    edit(d, false, false).then(enqueue(d, id)).then(push(d, id, false))

  // A lost response: the engine sends the envelope again and the relay answers
  // Known. The own change comes back from the log and is not applied again.
  run retryAfterLostResponseTest =
    init
      .then(edit(1, false, false))
      .then(enqueue(1, 0))
      .then(push(1, 0, true))
      .expect(relay.log == [0] and eng(1).outbox.keys() == Set(0))
      .then(push(1, 0, false))
      .expect(relay.log == [0] and happened(EvPushKnown))
      .then(fetchExtend(1, 1))
      .expect(eng(1).outbox == Map())
      .then(pull(1, false))
      .expect(app(1).outbox == Set() and app(1).applied == Set(0) and app(1).dups == 0)

  // S3: offline edits on two devices converge.
  run offlineEditsConvergeTest =
    init
      .then(edit(1, false, false))
      .then(edit(2, false, false))
      .then(enqueue(2, 1)).then(push(2, 1, false))
      .then(enqueue(1, 0)).then(push(1, 0, false))
      .then(fetchExtend(1, 2)).then(fetchExtend(2, 2))
      .then(pull(1, false)).then(pull(1, false))
      .then(pull(2, false)).then(pull(2, false))
      .expect(DEVS.forall(d => caughtUp(d) and app(d).applied == Set(0, 1) and app(d).outbox == Set()))

  // An app DB restore loses an own edit after enqueue. The engine still holds
  // it, so the app gets it back through the log, applied once.
  run restoredOwnEditReturnsTest =
    init
      .then(edit(1, false, false))
      .then(backupApp(1))
      .then(edit(1, false, false))
      .then(enqueue(1, 1))
      .then(restoreApp(1))
      .expect(app(1).applied == Set(0) and eng(1).outbox.keys() == Set(1))
      .then(push(1, 1, false))
      .then(fetchExtend(1, 1))
      .then(pull(1, false))
      .expect(app(1).applied == Set(0, 1) and app(1).dups == 0 and app(1).outbox == Set(0))

  // An app DB restore moves the applied position back. The app applies the
  // changes after it again, and none twice.
  run restoredPositionReplaysTest =
    init
      .then(editAndPush(1, 0))
      .then(fetchExtend(2, 1)).then(pull(2, false))
      .then(backupApp(2))
      .then(editAndPush(1, 1))
      .then(fetchExtend(2, 2)).then(pull(2, false))
      .then(restoreApp(2))
      .expect(app(2).appliedLog == [0] and app(2).applied == Set(0))
      .then(pull(2, false))
      .expect(app(2).applied == Set(0, 1) and app(2).dups == 0)

  // S6: snailfish-relay restore. The hold refuses changes, a device repairs the
  // log, and the hold stays on after every device reports until a release.
  run relayRestoreRepairTest =
    init
      .then(editAndPush(1, 0))
      .then(editAndPush(2, 1))
      .then(fetchExtend(1, 2)).then(fetchExtend(2, 2))
      .then(restoreRelay(0))
      .expect(relay.hold and relay.log == [])
      .then(edit(1, false, false)).then(enqueue(1, 2))
      // push is disabled by the hold. reportStatus is disabled: the tip is above the head.
      .expect(relay.hold and not(isPrefix(eng(1).log, relay.log)))
      .then(repair(1))
      .expect(relay.log == [0, 1])
      .then(reportStatus(1)).then(reportStatus(2))
      .expect(relay.hold and relay.reported == DEVS)
      .then(releaseHold)
      .then(push(1, 2, false))
      .expect(relay.log == [0, 1, 2])

  // A silent rollback and a new append from another device: the first device
  // sees a conflicting entry, stops with fork and does not apply it.
  run forkStopsTest =
    init
      .then(editAndPush(1, 0))
      .then(fetchExtend(1, 1))
      .then(rollBackRelay(0))
      .then(editAndPush(2, 1))
      .expect(not(comparable(eng(1).log, relay.log)))
      .then(fetchConflict(1))
      .expect(eng(1).stop == Forked and eng(1).log == [0] and app(1).applied == Set(0))
      .then(edit(1, false, false))
      .then(enqueue(1, 2))
      .then(push(1, 2, false).fail())

  // The relay refuses a change over the limit at push. The app splits it only
  // after the engine fetched to the relay head.
  run refusedSplitTest =
    init
      .then(lowerLimit)
      .then(edit(1, true, false))
      .then(enqueue(1, 0))
      .expect(eng(1).outbox.keys() == Set(0) and eng(1).refused == Set())
      .then(push(1, 0, false))
      .expect(eng(1).refused == Set(0))
      .then(resolveRefused(1, 0, true))
      .expect(app(1).applied == Set(1) and app(1).outbox == Set(1))
      .then(enqueue(1, 1)).then(push(1, 1, false))
      .expect(relay.log == [1])

  // F4: after an engine state loss, enqueue_many stores a change that the relay
  // holds. The relay answers Known, so the change is not refused.
  run enqueueAfterLossTest =
    init
      .then(edit(1, true, false))
      .then(enqueue(1, 0)).then(push(1, 0, false))
      .then(lowerLimit)
      .then(loseEngine(1))
      .then(enqueue(1, 0)).then(push(1, 0, false))
      .expect(eng(1).refused == Set() and relay.log == [0])

  // F2: the applied position is past the end of the log. changes_after raises
  // ResetRequired once the engine fetched to the relay head with no hold.
  run aheadOfLogResetTest =
    init
      .then(editAndPush(1, 0))
      .then(fetchExtend(1, 1)).then(pull(1, false))
      .then(loseEngine(1)).then(restoreRelay(0))
      .then(reportStatus(1)).then(reportStatus(2))
      .expect(not(resetRequired(app(1), eng(1), relay, BUG)))
      .then(releaseHoldWarned)
      .expect(resetRequired(app(1), eng(1), relay, BUG))
      // The reset deletes change 0, the last copy (two faults, limit 2).
      .then(handleReset(1))
      .expect(app(1).applied == Set() and not(held.contains(0)))

  // F3: an engine state loss during a restore hold leaves change 1 only in the
  // app state of device 1. Device 1 fetches during the hold. The user page still
  // marks it "not repaired", so only a release with the warning is possible.
  run notRepairedMarkTest =
    init
      .then(edit(2, false, false)).then(enqueue(2, 0)).then(push(2, 0, false))
      .then(edit(1, false, false)).then(enqueue(1, 1)).then(push(1, 1, false))
      .then(fetchExtend(1, 2)).then(pull(1, false)).then(pull(1, false))
      .then(restoreRelay(1))
      .then(loseEngine(1))
      .expect(eng(1).fresh and unheldApplied == Set(1))
      .then(fetchExtend(1, 1))
      .expect(eng(1).fresh)
      .then(reportStatus(1)).then(reportStatus(2))
      .then(releaseHoldWarned)
      .expect(not(relay.hold) and noSilentLoss and env.lostAtRelease == Set(1))

  // The relay lowers the limit after enqueue. The relay refuses the envelope for ever.
  run refusedAtPushTest =
    init
      .then(edit(1, true, false))
      .then(enqueue(1, 0))
      .then(lowerLimit)
      .then(push(1, 0, false))
      .expect(relay.log == [] and eng(1).refused == Set(0) and happened(EvPushRefused))

  // The relay checks the known change_id before the size limit. A retry of a
  // stored change after a lower limit is Known, not Refused.
  run knownBeforeSizeTest =
    init
      .then(edit(1, true, false))
      .then(enqueue(1, 0))
      .then(push(1, 0, true))
      .then(lowerLimit)
      .then(push(1, 0, false))
      .expect(happened(EvPushKnown) and eng(1).refused == Set())

  // ResetRequired: both engine state files are lost and the relay is restored to
  // an empty log. The new log holds a different entry at position 1. Device 2
  // deletes its synced data, applies its outbox rows again and pulls.
  run resetRequiredTest =
    init
      .then(editAndPush(1, 0))
      .then(fetchExtend(2, 1)).then(pull(2, false))
      .then(loseEngine(1)).then(loseEngine(2))
      .then(restoreRelay(0))
      .then(reportStatus(1)).then(reportStatus(2)).then(releaseHoldWarned)
      .then(editAndPush(2, 1))
      .then(enqueue(1, 0)).then(push(1, 0, false))
      .expect(relay.log == [1, 0])
      .then(fetchExtend(2, 2))
      .expect(resetRequired(app(2), eng(2), relay, BUG) and not(canPull(app(2), eng(2))))
      .then(handleReset(2))
      .expect(app(2).applied == Set(1) and app(2).appliedLog == [])
      .then(pull(2, false)).then(pull(2, false))
      .expect(caughtUp(2) and app(2).applied == Set(0, 1) and app(2).dups == 0)

  // The relay refuses an append whose signed base is not in the relay log.
  run badBaseTest =
    init
      .then(editAndPush(1, 0))
      .then(fetchExtend(1, 1))
      .then(edit(1, false, false)).then(enqueue(1, 1))
      .expect(eng(1).outbox.get(1) == [0])
      .then(rollBackRelay(0))
      .then(push(1, 1, false))
      .expect(relay.log == [] and happened(EvPushBadBase) and eng(1).outbox.keys() == Set(1))
}
