// Scenario tests for model.qnt. specs/tools/verify.py runs them, also with the
// BUG of each mutant.
module levelsTest {
  import levels(DEVS = Set(1, 2, 3), TOP = 2, MAX_REC = 8, BUG = "none").* from "./model"

  action appendId(k: int): bool = { nondet r = pending.filter(x => x.id == k).oneOf() relayAppend(r) }
  action refuseId(k: int): bool = { nondet r = pending.filter(x => x.id == k).oneOf() relayRefuse(r) }
  action decide(k: int): bool =
    if (valid(space(relay), pending.filter(x => x.id == k).getOnlyElement(), BUG)) appendId(k) else refuseId(k)

  // Device 1 creates the space at level 1 and grants device 2 (engine level 1).
  action two: bool =
    init.then(create(1)).then(grant(1, 2)).then(appendId(2)).then(fetch(1)).then(fetch(2)).then(fetch(2))

  // [VER-7] [VER-8] Both engines update and state level 2. Device 1 then
  // raises the write level, and device 2 writes at level 2.
  run raiseAfterUpdatesTest =
    two
      .then(update(1)).then(announce(1)).then(appendId(3))
      .then(update(2)).then(fetch(2)).then(announce(2)).then(appendId(4))
      .then(fetch(1)).then(fetch(1)).then(raise(1)).then(appendId(5))
      .expect(wRaised and space(relay).level == 2 and levelSupported)
      .then(fetch(2)).then(fetch(2)).then(change(2)).then(appendId(6))
      .expect(relay.nth(5).wl == 2 and recordsAtLevel)

  // [VER-8] [VER-10] Device 2 has not updated, so device 1 cannot raise the
  // level. After device 1 removes device 2, it can.
  run removalUnblocksRaiseTest =
    two
      .then(update(1)).then(announce(1)).then(appendId(3)).then(fetch(1))
      .then(raise(1)).fail()

  run removalThenRaiseTest =
    two
      .then(update(1)).then(announce(1)).then(appendId(3)).then(fetch(1))
      .then(remove(1, 2)).then(appendId(4)).then(fetch(1))
      .then(raise(1)).then(appendId(5))
      .expect(wRemovedThenRaised and levelSupported)

  // [VER-8] A raise and a grant for a level 1 device race. The relay judges
  // the second record against the state after the first, so it refuses it.
  run grantRaceTest =
    two
      .then(update(1)).then(announce(1)).then(appendId(3))
      .then(update(2)).then(fetch(2)).then(announce(2)).then(appendId(4))
      .then(fetch(1)).then(fetch(1)).then(fetch(2))
      .then(grant(2, 3)).then(raise(1))
      .then(appendId(6)).then(decide(5))
      .expect(wGrantRefused and levelSupported and space(relay).active == Set(1, 2))

  // [VER-9] Device 2 signs a change on its old view at level 1. The level
  // record reaches the relay first, so the relay refuses the change.
  run lowLevelRefusedTest =
    two
      .then(update(1)).then(announce(1)).then(appendId(3))
      .then(update(2)).then(fetch(2)).then(announce(2)).then(appendId(4))
      .then(fetch(1)).then(fetch(1)).then(change(2)).then(raise(1))
      .then(appendId(6)).then(decide(5))
      .expect(wLowRefused and recordsAtLevel)

  // [VER-7] After a raise, a reinstalled older engine states a lower level.
  // The record is refused, so the device level stays at the write level.
  run downgradeRefusedTest =
    two
      .then(update(1)).then(announce(1)).then(appendId(3))
      .then(update(2)).then(fetch(2)).then(announce(2)).then(appendId(4))
      .then(fetch(1)).then(fetch(1)).then(raise(1)).then(appendId(5))
      .then(fetch(2)).then(fetch(2)).then(downgrade(2))
      .then(all { pending' = pending.union(Set({ ...blank(2, DeviceRec), lvl: 1 })),
                  nextId' = nextId + 1, relay' = relay, devs' = devs, events' = events })
      .then(decide(6))
      .expect(levelSupported)
}
