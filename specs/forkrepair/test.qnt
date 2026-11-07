module forkrepairTest {
  import forkrepair(DEVS = Set(1, 2, 3), MAX_IDS = 6, SNAPSHOTS = false, BUG = "none").* from "./model"

  // Push the one change of the engine outbox of d, whatever its change ID.
  action pushOutbox(d: Dev): bool = {
    nondet c = dev(d).outbox.oneOf()
    all { dev(d).outbox.size() == 1, push(d, c) }
  }

  // The relay forks after change 1. Device 2 writes change 2 on branch 1 and
  // its app applies it back, so its app outbox row is gone. Device 1 writes
  // change 3 on branch 0. The relay then shows device 2 branch 0.
  action forked: bool =
    init.then(edit(1)).then(push(1, 1)).then(fetch(1)).then(fetch(2)).then(fetch(3))
      .then(fork).then(show(2))
      .then(edit(2)).then(push(2, 2)).then(fetch(2)).then(pull(2)).then(pull(2))
      .then(edit(1)).then(push(1, 3)).then(fetch(1))
      .then(show(2)).then(fetch(2))

  // [FRK-1] to [FRK-8] Device 1 is the source. Device 2 enrolls again, gets
  // its change 2 back from the old state file, sends it with its old change
  // ID, resets and pulls. Device 3 keeps its state: its log is a prefix of
  // the import.
  run repairTest =
    forked
      .expect(wFork and dev(2).stop == Forked and dev(2).appOutbox == Set())
      .then(exportLog(1)).then(delete)
      .then(fetch(3))
      .expect(wDeletedSeen and dev(3).stop == Deleted)
      .then(importLog)
      .then(reenroll(2)).then(recover(2))
      .expect(wRecovered and contentsOf(dev(2).appOutbox) == Set(2) and noLostChange)
      .then(dropOld(2))
      .then(pushOutbox(2)).then(fetch(2)).then(reset(2))
      .then(pull(2)).then(pull(2)).then(pull(2))
      .then(fetch(1)).then(pull(1)).then(pull(1)).then(pull(1))
      .then(fetch(3)).then(pull(3)).then(pull(3)).then(pull(3))
      .expect(noLostChange and noDoubleApply and noResurrect)
      .expect(dev(1).appState == Set(1, 2, 3) and dev(2).appState == Set(1, 2, 3) and dev(3).appState == Set(1, 2, 3))
      .expect(converged)

  // [FRK-8] A second recovery after a crash adds nothing: the change IDs are
  // the old ones.
  run recoverTwiceTest =
    forked.then(exportLog(1)).then(delete).then(importLog)
      .then(reenroll(2)).then(recover(2)).then(recover(2))
      .expect(dev(2).appOutbox == Set(2) and dev(2).outbox == Set(2))
      .then(dropOld(2))
      .then(pushOutbox(2)).then(fetch(2)).then(reset(2))
      .then(pull(2)).then(pull(2)).then(pull(2))
      .expect(noDoubleApply and dev(2).appState == Set(1, 2, 3) and s.relay[0].length() == 3)

  // [FRK-8] Without the reset, the app pulls change 1 again.
  run resetNeededTest =
    forked.then(exportLog(1)).then(delete).then(importLog)
      .then(reenroll(2)).then(recover(2)).then(dropOld(2))
      .then(pushOutbox(2)).then(fetch(2))
      .expect(not(isPrefix(dev(2).appliedLog, cids(dev(2).log))))
      .then(reset(2)).then(pull(2)).then(pull(2)).then(pull(2))
      .expect(noDoubleApply)

  // [LOG-13] A device that sees the deletion marker uploads nothing. After
  // the import it syncs again.
  run deletedThenImportedTest =
    forked.then(exportLog(1)).then(delete).then(fetch(3)).then(fetch(1))
      .expect(dev(3).stop == Deleted and dev(1).stop == Deleted and s.deleted)
      .then(importLog).then(fetch(3))
      .expect(dev(3).stop == Running and noResurrect)
}

module forkrepairTestSnap {
  import forkrepair(DEVS = Set(1, 2, 3), MAX_IDS = 6, SNAPSHOTS = true, BUG = "none").* from "./model"

  // [CMP-21] Device 2 writes change 2 on branch 1, applies it, writes a
  // snapshot and replaces change 2 with a stub. After the fork repair from
  // device 1, the old state file holds only the stub, so FRK-7 cannot give
  // change 2 back.
  run stubLimitTest =
    init.then(edit(1)).then(push(1, 1)).then(fetch(1)).then(fetch(2)).then(pull(2))
      .then(fork).then(show(2))
      .then(edit(2)).then(push(2, 2)).then(fetch(2)).then(pull(2))
      .then(snapshot(2)).then(fetch(2)).then(pull(2)).then(compact(2))
      .then(edit(1)).then(push(1, 4)).then(fetch(1))
      .then(show(2)).then(fetch(2))
      .expect(dev(2).stop == Forked)
      .then(exportLog(1)).then(delete).then(importLog).then(reenroll(2))
      .expect(not(noLostChange))
}
