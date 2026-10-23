// Model of the Snailfish delivery rules: DESIGN.md "App integration" (Delivery
// rules), "Space log" (repair sessions, restore hold) and threat T7.
// specs/README.md has the coverage map, the findings and the run commands.
//
// Abstractions:
//  - A change is an opaque int id. In the design it is 128 random bits, so ids
//    never collide. A log entry is the change id. The bytes of a change are fixed
//    per id, so a record hash adds nothing here.
//  - The app state is the set of applied change ids. This is the merge contract:
//    the state depends on the set of changes, not on their order.
//  - Each app DB transaction and each engine transaction is one atomic action.
//    A crash between two actions is the same as a long pause, so the free
//    interleaving of actions models a crash at each step.
//  - The applied position (position, digest) is the log prefix that the app
//    handled. Prefix equality stands for digest equality.
//
// The const BUG selects one deliberate violation of the design. "none" is the
// design. delivery_mutants.qnt binds each other value, and specs/check.sh
// requires an invariant to fail for each one. A mutant that survives shows a
// vacuous invariant or a rule that the model does not need.
module delivery {
  type Dev = int
  type Id = int

  type Stop = Running | Forked

  type Event =
    | EvEdit | EvPushStored | EvPushKnown | EvPushRefused | EvPushBadBase
    | EvFetch | EvPull | EvPullOwn | EvAppRestore | EvRelayRestore | EvRelayFault
    | EvRepair | EvHoldReleased | EvEarlyRelease | EvForkDetected | EvReverted
    | EvSplit | EvEngineLoss | EvResetRequired | EvLimitLowered | EvEnqueueRefused

  // The durable part of the app DB that a backup copies.
  type AppImage = { applied: Set[Id], outbox: Set[Id], appliedLog: List[Id] }

  type App = {
    applied: Set[Id],      // the changes in the app state
    outbox: Set[Id],       // app outbox rows
    appliedLog: List[Id],  // applied position: the log prefix that the app handled
    backup: AppImage,
    dups: int,             // ghost: count of changes applied twice. A restore keeps it.
  }

  type Engine = {
    outbox: Id -> List[Id],// envelopes that the verified log does not hold, with the
                           // signed base: the verified log when enqueue signed the record
    refused: Set[Id],      // envelopes that the relay refused for ever (degraded)
    log: List[Id],         // verified log
    stop: Stop,
  }

  type Relay = {
    log: List[Id],
    hold: bool,            // restore hold: appends are refused
    reported: Set[Dev],    // devices that reported a tip at or below the head since the restore
    limitLow: bool,        // the relay operator lowered the change size limit
  }

  type Change = { author: Dev, big: bool }

  // Ghost state for properties and witnesses. No device or relay reads it.
  type Env = {
    nextId: Id,
    changes: Id -> Change,
    stored: Set[Id],       // changes that enqueue stored in an engine outbox
    exposed: Set[Id],      // changes of which an engine state loss destroyed a copy
    reverted: Set[Id],     // changes that an app reverted after a refusal
    faults: int,
    events: Set[Event],
  }

  // ---------------------------------------------------------------- consts

  const DEVS: Set[Dev]
  const MAX_IDS: int
  const MAX_FAULTS: int    // bound on app restores, engine losses and relay rollbacks
  const FAULTS: Set[str]   // the fault classes that this config enables
  const BUG: str

  pure val FAULT_CLASSES: Set[str] = Set(
    "appRestore",      // the app DB is restored from an older backup
    "engineLoss",      // the engine state file is lost; the keys stay (T14)
    "relayRestore",    // snailfish-relay restore from an older backup, with a restore hold
    "silentRollback",  // a storage fault rolls the relay back; no hold (T7 limit)
    "earlyRelease",    // the user releases a restore hold before every device reports
  )

  pure val BUGS: Set[str] = Set(
    "none",
    "editSplitTxn",         // edit and outbox row in two transactions
    "appDropsRowOnEnqueue", // app deletes the outbox row when enqueue returns
    "engineDropsOnAccept",  // engine deletes the envelope when the relay stores it
    "relayNoDedupe",        // relay appends a known change_id again
    "sizeBeforeDedupe",     // relay checks the size limit before the known change_id
    "pullSplitTxn",         // pull applies the change and moves the position in two transactions
    "noRepair",             // engine accepts a shorter relay log and does not repair
    "noHold",               // snailfish-relay restore sets no restore hold
    "adoptFork",            // engine adopts a conflicting relay log and does not stop
    "resetDropsOutbox",     // ResetRequired handling does not apply the outbox rows again
  )

  // ---------------------------------------------------------------- pure logic

  pure def ids(l: List[Id]): Set[Id] = l.foldl(Set(), (s, x) => s.union(Set(x)))

  pure def isPrefix(a: List[Id], b: List[Id]): bool =
    a.length() <= b.length() and b.slice(0, a.length()) == a

  pure def comparable(a: List[Id], b: List[Id]): bool = isPrefix(a, b) or isPrefix(b, a)

  pure def without(m: Id -> List[Id], ks: Set[Id]): Id -> List[Id] =
    m.keys().exclude(ks).mapBy(k => m.get(k))

  pure def image(a: App): AppImage =
    { applied: a.applied, outbox: a.outbox, appliedLog: a.appliedLog }

  pure val emptyImage: AppImage = { applied: Set(), outbox: Set(), appliedLog: List() }
  pure val freshApp: App = { applied: Set(), outbox: Set(), appliedLog: List(), dups: 0, backup: emptyImage }
  pure val freshEngine: Engine = { outbox: Map(), refused: Set(), log: List(), stop: Running }

  // ---- app

  // Edit: apply the edit and write the outbox row in one transaction.
  pure def applyEdit(a: App, id: Id, crash: bool, bug: str): App =
    if (bug == "editSplitTxn" and crash) { ...a, applied: a.applied.union(Set(id)) }
    else { ...a, applied: a.applied.union(Set(id)), outbox: a.outbox.union(Set(id)) }

  pure def canPull(a: App, e: Engine): bool =
    isPrefix(a.appliedLog, e.log) and e.log.length() > a.appliedLog.length()

  pure def nextEntry(a: App, e: Engine): Id = e.log.nth(a.appliedLog.length())

  // Handle the next change in one transaction. If the outbox row exists, the app
  // applied the edit at edit time: it deletes the row and does not apply again.
  pure def applyPull(a: App, e: Engine, crash: bool, bug: str): App = {
    val id = nextEntry(a, e)
    val moved = e.log.slice(0, a.appliedLog.length() + 1)
    if (a.outbox.contains(id))
      { ...a, outbox: a.outbox.exclude(Set(id)), appliedLog: moved }
    else {
      val dups = a.dups + (if (a.applied.contains(id)) 1 else 0)
      val applied = a.applied.union(Set(id))
      if (bug == "pullSplitTxn" and crash) { ...a, applied: applied, dups: dups }
      else { ...a, applied: applied, appliedLog: moved, dups: dups }
    }
  }

  // changes_after raises ResetRequired: the verified log holds a different digest
  // at the applied position.
  pure def resetRequired(a: App, e: Engine): bool =
    e.log.length() >= a.appliedLog.length() and not(isPrefix(a.appliedLog, e.log))

  // Delete the synced data, import no snapshot, apply each outbox row again.
  pure def applyReset(a: App, bug: str): App =
    { ...a, applied: if (bug == "resetDropsOutbox") Set() else a.outbox, appliedLog: List() }

  // ---- engine

  pure def knows(e: Engine, id: Id): bool =
    e.outbox.keys().contains(id) or e.refused.contains(id) or ids(e.log).contains(id)

  // Enqueue has no effect if the engine already knows the change_id.
  pure def canEnqueue(a: App, e: Engine, id: Id): bool =
    a.outbox.contains(id) and not(knows(e, id))

  // An own envelope leaves the outbox only when the verified log holds it.
  pure def applyFetch(e: Engine, newLog: List[Id]): Engine =
    { ...e, log: newLog, outbox: without(e.outbox, ids(newLog)) }

  // ---- relay

  // Refused is permanent (size limit). BadBase is transient: the signed base is
  // not an entry of the relay log, after a rollback or on another branch.
  type Verdict = Stored | Known | Refused | BadBase

  pure def verdict(r: Relay, id: Id, base: List[Id], big: bool, bug: str): Verdict = {
    val known = ids(r.log).contains(id)
    val tooBig = big and r.limitLow
    if (bug == "sizeBeforeDedupe" and tooBig) Refused
    else if (known and bug != "relayNoDedupe") Known
    else if (tooBig) Refused
    else if (not(isPrefix(base, r.log))) BadBase
    else Stored
  }

  pure def verdictEvent(v: Verdict): Event = match v {
    | Stored => EvPushStored
    | Known => EvPushKnown
    | Refused => EvPushRefused
    | BadBase => EvPushBadBase
  }

  // ---------------------------------------------------------------- state

  var apps: Dev -> App
  var engines: Dev -> Engine
  var relay: Relay
  var env: Env

  def app(d: Dev): App = apps.get(d)
  def eng(d: Dev): Engine = engines.get(d)
  def running(d: Dev): bool = eng(d).stop == Running
  def ev(e: Event): Env = { ...env, events: env.events.union(Set(e)) }
  def canFault(f: str): bool = FAULTS.contains(f) and env.faults < MAX_FAULTS
  def fault(e: Event): Env = { ...ev(e), faults: env.faults + 1 }

  // ---------------------------------------------------------------- actions

  action init: bool = all {
    BUGS.contains(BUG),
    FAULTS.subseteq(FAULT_CLASSES),
    apps' = DEVS.mapBy(_ => freshApp),
    engines' = DEVS.mapBy(_ => freshEngine),
    relay' = { log: List(), hold: false, reported: Set(), limitLow: false },
    env' = { nextId: 0, changes: Map(), stored: Set(), exposed: Set(), reverted: Set(),
             faults: 0, events: Set() },
  }

  // The user edits on device d. The app works offline, and also when sync stops.
  action edit(d: Dev, big: bool, crash: bool): bool = {
    val id = env.nextId
    all {
      id < MAX_IDS,
      apps' = apps.set(d, applyEdit(app(d), id, crash, BUG)),
      engines' = engines,
      relay' = relay,
      env' = { ...ev(EvEdit), nextId: id + 1, changes: env.changes.put(id, { author: d, big: big }) },
    }
  }

  // The app calls enqueue_many with its outbox rows, after each commit and at
  // startup. One action is one row. A batch of rows in one transaction is a run
  // of these actions with no other action between them, so the model includes it.
  // A change larger than the relay limit goes to the refused list of the result.
  action enqueue(d: Dev, id: Id): bool = {
    val tooBig = env.changes.get(id).big and relay.limitLow
    all {
      canEnqueue(app(d), eng(d), id),
      engines' = engines.set(d,
        if (tooBig) { ...eng(d), refused: eng(d).refused.union(Set(id)) }
        else { ...eng(d), outbox: eng(d).outbox.put(id, eng(d).log) }),
      apps' = if (BUG == "appDropsRowOnEnqueue")
                apps.set(d, { ...app(d), outbox: app(d).outbox.exclude(Set(id)) })
              else apps,
      relay' = relay,
      env' = if (tooBig) ev(EvEnqueueRefused) else { ...env, stored: env.stored.union(Set(id)) },
    }
  }

  // The engine sends one stored envelope. If the response is lost, the engine
  // learns nothing and sends the same envelope again later.
  action push(d: Dev, id: Id, lost: bool): bool = {
    val v = verdict(relay, id, eng(d).outbox.get(id), env.changes.get(id).big, BUG)
    all {
      eng(d).outbox.keys().contains(id),
      running(d),
      not(relay.hold),
      relay' = if (v == Stored) { ...relay, log: relay.log.append(id) } else relay,
      engines' =
        if (v == Refused and not(lost))
          engines.set(d, { ...eng(d), outbox: without(eng(d).outbox, Set(id)),
                                      refused: eng(d).refused.union(Set(id)) })
        else if (v == Stored and BUG == "engineDropsOnAccept" and not(lost))
          engines.set(d, { ...eng(d), outbox: without(eng(d).outbox, Set(id)) })
        else engines,
      apps' = apps,
      env' = ev(verdictEvent(v)),
    }
  }

  // Fetch when the verified log is a prefix of the relay log: verify n entries.
  action fetchExtend(d: Dev, n: int): bool = all {
    running(d),
    isPrefix(eng(d).log, relay.log),
    eng(d).log.length() < n, n <= relay.log.length(),
    engines' = engines.set(d, applyFetch(eng(d), relay.log.slice(0, n))),
    apps' = apps,
    relay' = relay,
    env' = ev(EvFetch),
  }

  // Fetch when the relay log conflicts with a verified entry: stop with fork.
  // adoptFork adopts the conflicting log. noRepair adopts a shorter log.
  action fetchConflict(d: Dev): bool = {
    val e = eng(d)
    val shorter = isPrefix(relay.log, e.log) and relay.log.length() < e.log.length()
    val forked = not(comparable(e.log, relay.log))
    val adopt = (forked and BUG == "adoptFork") or (shorter and BUG == "noRepair")
    all {
      running(d),
      forked or (shorter and BUG == "noRepair"),
      engines' = engines.set(d, if (adopt) applyFetch(e, relay.log) else { ...e, stop: Forked }),
      apps' = apps,
      relay' = relay,
      env' = ev(if (adopt) EvFetch else EvForkDetected),
    }
  }

  // Repair session: the relay log ends before a verified position, so the device
  // uploads the lost entries at the same positions. The relay commits the staged
  // entries in one transaction. It accepts a repair during a restore hold.
  action repair(d: Dev): bool = all {
    BUG != "noRepair",
    running(d),
    isPrefix(relay.log, eng(d).log),
    relay.log.length() < eng(d).log.length(),
    relay' = { ...relay, log: eng(d).log },
    engines' = engines,
    apps' = apps,
    env' = ev(EvRepair),
  }

  // Status report during a restore hold. The user page shows each device that
  // reported a verified tip at or below the log head since the restore.
  action reportStatus(d: Dev): bool = all {
    relay.hold,
    running(d),
    not(relay.reported.contains(d)),
    isPrefix(eng(d).log, relay.log),
    relay' = { ...relay, reported: relay.reported.union(Set(d)) },
    engines' = engines,
    apps' = apps,
    env' = env,
  }

  // Only the user (user page) or the relay operator (snailfish-relay
  // release-hold) ends a hold. This action is a release after the user page shows
  // a report from every device. The relay does not end a hold by itself.
  action releaseHold: bool = all {
    relay.hold,
    relay.reported == DEVS,
    relay' = { ...relay, hold: false },
    engines' = engines,
    apps' = apps,
    env' = ev(EvHoldReleased),
  }

  action pull(d: Dev, crash: bool): bool = all {
    canPull(app(d), eng(d)),
    apps' = apps.set(d, applyPull(app(d), eng(d), crash, BUG)),
    engines' = engines,
    relay' = relay,
    env' = ev(if (app(d).outbox.contains(nextEntry(app(d), eng(d)))) EvPullOwn else EvPull),
  }

  action handleReset(d: Dev): bool = all {
    resetRequired(app(d), eng(d)),
    apps' = apps.set(d, applyReset(app(d), BUG)),
    engines' = engines,
    relay' = relay,
    env' = ev(EvResetRequired),
  }

  // The app reads the degraded status and removes the outbox row of a refused
  // change: it reverts the edit, or it splits it into a new, smaller change.
  action resolveRefused(d: Dev, id: Id, split: bool): bool = {
    val a = app(d)
    val newId = env.nextId
    val reverted = { ...a, applied: a.applied.exclude(Set(id)), outbox: a.outbox.exclude(Set(id)) }
    val env1 = { ...env, reverted: env.reverted.union(Set(id)) }
    all {
      a.outbox.contains(id),
      eng(d).refused.contains(id),
      not(split) or newId < MAX_IDS,
      apps' = apps.set(d,
        if (split) { ...reverted, applied: reverted.applied.union(Set(newId)),
                                  outbox: reverted.outbox.union(Set(newId)) }
        else reverted),
      env' =
        if (split) { ...env1, events: env.events.union(Set(EvSplit)), nextId: newId + 1,
                              changes: env.changes.put(newId, { author: d, big: false }) }
        else { ...env1, events: env.events.union(Set(EvReverted)) },
      engines' = engines,
      relay' = relay,
    }
  }

  action backupApp(d: Dev): bool = all {
    FAULTS.contains("appRestore"),
    image(app(d)) != app(d).backup,
    apps' = apps.set(d, { ...app(d), backup: image(app(d)) }),
    engines' = engines,
    relay' = relay,
    env' = env,
  }

  // The app DB is restored from its backup. The engine state file is not.
  action restoreApp(d: Dev): bool = {
    val a = app(d)
    all {
      canFault("appRestore"),
      image(a) != a.backup,
      apps' = apps.set(d, { ...a, applied: a.backup.applied, outbox: a.backup.outbox,
                                  appliedLog: a.backup.appliedLog }),
      engines' = engines,
      relay' = relay,
      env' = fault(EvAppRestore),
    }
  }

  // The engine state file is lost. The keys stay, so the engine rebuilds from the
  // relay log and continues as the same device (T14).
  action loseEngine(d: Dev): bool = {
    val e = eng(d)
    all {
      canFault("engineLoss"),
      e != freshEngine,
      engines' = engines.set(d, freshEngine),
      apps' = apps,
      relay' = relay,
      env' = { ...fault(EvEngineLoss),
               exposed: env.exposed.union(e.outbox.keys()).union(e.refused).union(ids(e.log)) },
    }
  }

  // snailfish-relay restore from an older backup. A backup is a log prefix.
  action restoreRelay(k: int): bool = all {
    canFault("relayRestore"),
    0 <= k, k < relay.log.length(),
    relay' = { ...relay, log: relay.log.slice(0, k), hold: BUG != "noHold", reported: Set() },
    engines' = engines,
    apps' = apps,
    env' = fault(EvRelayRestore),
  }

  // A storage fault rolls the relay back with no restore command and no hold.
  action rollBackRelay(k: int): bool = all {
    canFault("silentRollback"),
    0 <= k, k < relay.log.length(),
    relay' = { ...relay, log: relay.log.slice(0, k) },
    engines' = engines,
    apps' = apps,
    env' = fault(EvRelayFault),
  }

  action releaseHoldEarly: bool = all {
    FAULTS.contains("earlyRelease"),
    relay.hold,
    relay' = { ...relay, hold: false },
    engines' = engines,
    apps' = apps,
    env' = ev(EvEarlyRelease),
  }

  action lowerLimit: bool = all {
    not(relay.limitLow),
    relay' = { ...relay, limitLow: true },
    engines' = engines,
    apps' = apps,
    env' = ev(EvLimitLowered),
  }

  action step: bool = {
    nondet d = DEVS.oneOf()
    nondet flag = Set(false, true).oneOf()
    nondet flag2 = Set(false, true).oneOf()
    nondet k = 0.to(MAX_IDS).oneOf()
    any {
      edit(d, flag, flag2),
      { nondet id = app(d).outbox.oneOf() enqueue(d, id) },
      { nondet id = eng(d).outbox.keys().oneOf() push(d, id, flag) },
      fetchExtend(d, k),
      fetchConflict(d),
      repair(d),
      reportStatus(d),
      pull(d, flag),
      handleReset(d),
      { nondet id = app(d).outbox.intersect(eng(d).refused).oneOf() resolveRefused(d, id, flag) },
      backupApp(d),
      restoreApp(d),
      loseEngine(d),
      restoreRelay(k),
      rollBackRelay(k),
      releaseHold,
      releaseHoldEarly,
      lowerLimit,
    }
  }

  // ---------------------------------------------------------------- invariants

  // The places from which sync can still deliver a change: an app outbox, an
  // engine outbox, a verified log (also of a stopped device, for fork repair) or
  // the relay log.
  val held: Set[Id] =
    DEVS.fold(ids(relay.log), (s, d) =>
      s.union(app(d).outbox).union(eng(d).outbox.keys()).union(eng(d).refused).union(ids(eng(d).log)))

  // I1. Each device applies each change once (merge contract).
  val noDoubleApply: bool = DEVS.forall(d => app(d).dups == 0)

  // I2. A change that enqueue stored, and that no app reverted, is never lost.
  // An app DB restore can drop an edit before enqueue: that edit never left the
  // app DB, so the user loses it with the restore.
  val noLostChange: bool = env.stored.exclude(env.reverted).subseteq(held)

  // I2w. I2 for changes that no engine state loss touched. Two faults that each
  // destroy a copy (an engine state loss and an app DB restore or a relay
  // rollback) can lose a change. The design keeps one copy per fault.
  val noLostChangeWeak: bool = env.stored.exclude(env.reverted).exclude(env.exposed).subseteq(held)

  // I3. A change in an app state is never only in that app state. If it is, no
  // other device ever gets it, and the devices diverge without notice (goal 8).
  val appliedHeld: bool = DEVS.forall(d => app(d).applied.exclude(env.exposed).subseteq(held))

  // I4. A running device that has fetched and applied the whole relay log holds
  // exactly the relay changes and its own pending edits. Two such devices differ
  // only by pending edits.
  def caughtUp(d: Dev): bool =
    running(d) and eng(d).log == relay.log and app(d).appliedLog == relay.log
  val caughtUpState: bool = DEVS.forall(d =>
    caughtUp(d) implies app(d).applied == ids(relay.log).union(app(d).outbox))

  // I5. A permanent refusal means that no device can get the change. If one can,
  // the author reverts or splits an edit that other devices apply.
  val logged: Set[Id] = DEVS.fold(ids(relay.log), (s, d) => s.union(ids(eng(d).log)))
  val refusedNotStored: bool = DEVS.forall(d => eng(d).refused.intersect(logged) == Set())

  // I6. Running devices never hold conflicting verified logs. A silent rollback
  // or an early hold release can break it (T7 limit), and the devices then stop
  // with fork before they apply the other branch.
  val noFork: bool = tuples(DEVS, DEVS).forall(((d1, d2)) =>
    (running(d1) and running(d2)) implies comparable(eng(d1).log, eng(d2).log))


  // ---------------------------------------------------------------- witnesses

  def happened(e: Event): bool = env.events.contains(e)
  val wEdit: bool = happened(EvEdit)
  val wPushStored: bool = happened(EvPushStored)
  val wPushKnown: bool = happened(EvPushKnown)
  val wPushRefused: bool = happened(EvPushRefused)
  val wPushBadBase: bool = happened(EvPushBadBase)
  val wEnqueueRefused: bool = happened(EvEnqueueRefused)
  val wPullOther: bool = happened(EvPull)
  val wPullOwn: bool = happened(EvPullOwn)
  val wReverted: bool = happened(EvReverted)
  val wSplit: bool = happened(EvSplit)
  val wAppRestore: bool = happened(EvAppRestore)
  val wEngineLoss: bool = happened(EvEngineLoss)
  val wRelayRestore: bool = happened(EvRelayRestore)
  val wRelayFault: bool = happened(EvRelayFault)
  val wRepair: bool = happened(EvRepair)
  val wHoldReleased: bool = happened(EvHoldReleased)
  val wEarlyRelease: bool = happened(EvEarlyRelease)
  val wForkDetected: bool = happened(EvForkDetected)
  val wResetRequired: bool = happened(EvResetRequired)
  // An app DB restore dropped an own edit after enqueue, and sync gave it back.
  val wRestoredEditReturned: bool = DEVS.exists(d =>
    happened(EvAppRestore) and app(d).applied.exists(id =>
      env.changes.get(id).author == d and not(app(d).backup.applied.contains(id))))
  // Every device is caught up, with nothing pending, on a log with an edit from each device.
  val wAllConverged: bool =
    DEVS.forall(d => caughtUp(d) and app(d).outbox == Set() and eng(d).outbox == Map()) and
    DEVS.forall(d => ids(relay.log).exists(id => env.changes.get(id).author == d))
  // A repair after a restore, and then the hold ends.
  val wRepairThenRelease: bool = happened(EvRepair) and happened(EvHoldReleased)
  // The applied position is past the end of a fully fetched verified log. Neither
  // pull nor ResetRequired is enabled until the log grows. DESIGN.md does not
  // define this case. It needs an engine state loss and a relay rollback.
  val wAheadOfLog: bool = DEVS.exists(d =>
    running(d) and eng(d).log == relay.log and not(relay.hold)
    and app(d).appliedLog.length() > eng(d).log.length())
  // Two faults lost a change that enqueue stored (expected: see noLostChangeWeak).
  val wDoubleFaultLoss: bool = not(env.stored.exclude(env.reverted).subseteq(held))
}

// ------------------------------------------------------------------ configs
// Each config binds every const. specs/check.sh runs each one with the
// invariants that must hold for it.

// One fault class at a time, with crashes and lost responses everywhere.
module crashOnly {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4, MAX_FAULTS = 0, FAULTS = Set(), BUG = "none").*
}
module appRestore {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4, MAX_FAULTS = 2, FAULTS = Set("appRestore"), BUG = "none").*
}
module engineLoss {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4, MAX_FAULTS = 2, FAULTS = Set("engineLoss"), BUG = "none").*
}
// snailfish-relay restore with a hold, together with app DB restores. Three devices.
module relayRestore {
  import delivery(DEVS = Set(1, 2, 3), MAX_IDS = 4, MAX_FAULTS = 2,
                  FAULTS = Set("relayRestore", "appRestore"), BUG = "none").*
}
// Silent rollback and early hold release: forks can occur (T7 limit).
module faultyRelay {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4, MAX_FAULTS = 2,
                  FAULTS = Set("relayRestore", "silentRollback", "earlyRelease", "appRestore"), BUG = "none").*
}
// Every fault class together.
module allFaults {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4, MAX_FAULTS = 3,
                  FAULTS = Set("appRestore", "engineLoss", "relayRestore", "silentRollback", "earlyRelease"),
                  BUG = "none").*
}
