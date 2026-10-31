// Model of the Snailfish delivery rules: DESIGN.md "App integration" (Delivery
// rules), "Space log" (repair sessions, restore hold) and threat T7.
// specs/delivery/README.md has the coverage map and the findings.
//
// Abstractions:
//  - A change is an opaque int id. In the design it is 128 random bits, so ids
//    never collide. The bytes of a change are fixed per id, so the content hash
//    of a change is the same for every record of an id. The model has no way to
//    give one change_id two contents (an app fault). See "Not covered" in the README.
//  - A log entry is a record: an int that stands for the record hash. Each
//    encryption of a change gives a new hash (random nonce). The model encodes
//    entry = id + MAX_IDS * gen, where gen counts the engine state losses of the
//    device, so an engine that lost its state encrypts the same change again with
//    another hash. rid(entry) is the change_id of a record.
//  - The app state is the set of applied change ids. This is the merge contract:
//    the state depends on the set of changes, not on their order.
//  - Each app DB transaction and each engine transaction is one atomic action.
//    A crash between two actions is the same as a long pause, so the free
//    interleaving of actions models a crash at each step.
//  - The applied position (position, digest) is the log prefix that the app
//    handled. Prefix equality stands for digest equality.
//  - A grant is a log entry GRANT + d. It makes a device of LATE active
//    ([LOG-8]). Devices outside LATE are active from the genesis record. A
//    device that is not active in the relay log cannot fetch, push or report
//    (PROTOCOL.md 8.6 step 5). Grants carry no change and the app skips them.
//  - A repair session stages chunks of the verified log of its device. A
//    session ends by its finish, by expiry (24 hours without a chunk) or by a
//    replacement from the same device.
//
// The const BUG selects one deliberate violation of the design. "none" is the
// design. specs/delivery/checks.toml binds the consts for each config and each
// mutant, and specs/tools/verify.py runs them. A mutant that survives shows a
// vacuous invariant or a rule that the model does not need.
module delivery {
  type Dev = int
  type Id = int
  type Rcd = int            // a record hash: one encryption of a change

  type Stop = Running | Forked

  type Event =
    | EvEdit | EvPushStored | EvPushKnown | EvPushRefused | EvPushBadBase
    | EvFetch | EvPull | EvPullOwn | EvAppRestore | EvRelayRestore | EvRelayFault
    | EvRepair | EvHoldReleased | EvEarlyRelease | EvForkDetected | EvReverted
    | EvSplit | EvPushConflict | EvEngineLoss | EvResetRequired | EvLimitLowered | EvResetAhead | EvWarnedRelease
    | EvGrant | EvRepairStart | EvRepairChunk | EvRepairExpired | EvLateRepair

  // The durable part of the app DB that a backup copies.
  type AppImage = { applied: Set[Id], outbox: Set[Id], appliedLog: List[Rcd] }

  type App = {
    applied: Set[Id],      // the changes in the app state
    outbox: Set[Id],       // app outbox rows
    appliedLog: List[Rcd], // applied position: the log prefix that the app handled
    backup: AppImage,
    dups: int,             // ghost: count of changes applied twice. A restore keeps it.
  }

  type Pending = { base: List[Rcd], rec: Rcd }

  type Engine = {
    outbox: Id -> Pending, // envelopes that the verified log does not hold, with the
                           // record hash and the signed base (the verified log when
                           // enqueue signed the record)
    refused: Set[Id],      // envelopes that the relay refused for ever (degraded)
    log: List[Rcd],        // verified log
    gen: int,              // ghost: engine state losses so far. It makes the record hash new.
    stop: Stop,
    fresh: bool,           // a new state file since the last fetch that reached the
                           // relay head with no hold. The status report carries it (F3).
  }

  // A repair session. `base` is the relay log at the start, `staged` the
  // entries in the staging table ([LOG-11]).
  type Session = { live: bool, owner: Dev, base: List[Rcd], staged: List[Rcd] }

  type Relay = {
    log: List[Rcd],
    hold: bool,            // restore hold: appends are refused
    reporters: Set[Dev],   // devices that reported since the restore
    tips: Dev -> List[Rcd],// the last reported verified log of each reporter (a total map)
    marked: Set[Dev],      // devices that reported a new engine state file since the restore
    limitLow: bool,        // the relay operator lowered the change size limit
    session: Session,
  }

  type Change = { author: Dev, big: bool }

  // Ghost state for properties and witnesses. No device or relay reads it.
  type Env = {
    nextId: Id,
    changes: Id -> Change,
    stored: Set[Id],       // changes that enqueue stored in an engine outbox
    exposed: Set[Id],      // changes of which an engine state loss destroyed a copy
    reverted: Set[Id],     // changes that an app reverted after a refusal
    lostAtRelease: Set[Id],// changes that only app DBs held when a hold ended
    silentLoss: bool,      // a hold ended with no warning and lost a change
    granted: Set[Dev],     // LATE devices that got a grant at some time
    faults: int,
    events: Set[Event],
  }

  // ---------------------------------------------------------------- consts

  const DEVS: Set[Dev]
  const LATE: Set[Dev]     // devices that become active only through a grant entry
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
    "warnedRelease",   // the user releases after the warning about a new engine state file (F3)
  )

  pure val BUGS: Set[str] = Set(
    "none",
    "editSplitTxn",         // edit and outbox row in two transactions
    "appDropsRowOnEnqueue", // app deletes the outbox row when enqueue returns
    "engineDropsOnAccept",  // engine deletes the envelope when the relay stores it
    "relayNoDedupe",        // relay appends a known change_id again
    "relayConflictAppends", // relay appends a known change_id with another record hash [WIR-6]
    "conflictRefuses",      // engine treats a Conflict as a permanent refusal [DLV-6]
    "sizeBeforeDedupe",     // relay checks the size limit before the known change_id
    "pullSplitTxn",         // pull applies the change and moves the position in two transactions
    "noRepair",             // engine accepts a shorter relay log and does not repair
    "noHold",               // snailfish-relay restore sets no restore hold
    "adoptFork",            // engine adopts a conflicting relay log and does not stop
    "resetDropsOutbox",     // ResetRequired handling does not apply the outbox rows again
    "enqueueChecksSize",    // enqueue_many refuses a change over the size limit locally (F4)
    "noAheadReset",         // no ResetRequired if the applied position is past the log end (F2)
    "releaseIgnoresFresh",  // the user page does not mark a new engine state file (F3)
    "freshClearsOnFetch",   // the "not repaired" mark ends at the first fetch, not at the hold end (F3)
    "repairMultiSession",   // a repair start replaces the live session of another device [LOG-11]
    "repairMovesEarly",     // the relay puts each chunk into the log at once, not after the finish [LOG-11]
    "repairNoExpiry",       // a repair session never expires [LOG-11]
    "repairNeedsLogGrant",  // a repair signer must be active in the relay log, not in the entries [LOG-12]
  )

  // A grant record. It is larger than every change record, because gen is at most MAX_FAULTS.
  pure val GRANT: int = 1000

  // ---------------------------------------------------------------- pure logic

  pure def rid(r: Rcd): Id = r % MAX_IDS

  pure def isGrant(r: Rcd): bool = r >= GRANT

  pure def ids(l: List[Rcd]): Set[Id] =
    l.foldl(Set(), (s, x) => if (isGrant(x)) s else s.union(Set(rid(x))))

  pure def grantsIn(l: List[Rcd]): Set[Dev] =
    l.foldl(Set(), (s, x) => if (isGrant(x)) s.union(Set(x - GRANT)) else s)

  // Rules: [LOG-8]
  pure def activeIn(d: Dev, l: List[Rcd]): bool = not(LATE.contains(d)) or grantsIn(l).contains(d)

  pure def isPrefix(a: List[Rcd], b: List[Rcd]): bool =
    a.length() <= b.length() and b.slice(0, a.length()) == a

  pure def comparable(a: List[Rcd], b: List[Rcd]): bool = isPrefix(a, b) or isPrefix(b, a)

  pure def without(m: Id -> Pending, ks: Set[Id]): Id -> Pending =
    m.keys().exclude(ks).mapBy(k => m.get(k))

  pure def image(a: App): AppImage =
    { applied: a.applied, outbox: a.outbox, appliedLog: a.appliedLog }

  pure val emptyImage: AppImage = { applied: Set(), outbox: Set(), appliedLog: List() }
  pure val freshApp: App = { applied: Set(), outbox: Set(), appliedLog: List(), dups: 0, backup: emptyImage }
  pure val freshEngine: Engine = { outbox: Map(), refused: Set(), log: List(), gen: 0, stop: Running, fresh: false }
  pure val noSession: Session = { live: false, owner: 0, base: List(), staged: List() }

  // ---- app

  // Edit: apply the edit and write the outbox row in one transaction.
  // Rules: [DLV-2]
  pure def applyEdit(a: App, id: Id, crash: bool, bug: str): App =
    if (bug == "editSplitTxn" and crash) { ...a, applied: a.applied.union(Set(id)) }
    else { ...a, applied: a.applied.union(Set(id)), outbox: a.outbox.union(Set(id)) }

  // Rules: [DLV-10]
  pure def canPull(a: App, e: Engine): bool =
    isPrefix(a.appliedLog, e.log) and e.log.length() > a.appliedLog.length()

  pure def nextEntry(a: App, e: Engine): Rcd = e.log.nth(a.appliedLog.length())

  // Handle the next change in one transaction. If the outbox row exists, the app
  // applied the edit at edit time: it deletes the row and does not apply again.
  // Rules: [DLV-11]
  pure def applyPull(a: App, e: Engine, crash: bool, bug: str): App = {
    val id = rid(nextEntry(a, e))
    val moved = e.log.slice(0, a.appliedLog.length() + 1)
    if (isGrant(nextEntry(a, e)))
      { ...a, appliedLog: moved }
    else if (a.outbox.contains(id))
      { ...a, outbox: a.outbox.exclude(Set(id)), appliedLog: moved }
    else {
      val dups = a.dups + (if (a.applied.contains(id)) 1 else 0)
      val applied = a.applied.union(Set(id))
      if (bug == "pullSplitTxn" and crash) { ...a, applied: applied, dups: dups }
      else { ...a, applied: applied, appliedLog: moved, dups: dups }
    }
  }

  // changes_after raises ResetRequired: the verified log holds a different digest
  // at the applied position, or the applied position is past the end of a log that
  // the engine fetched to the relay head with no hold (F2).
  // Rules: [DLV-12]
  // Partial: stubs are not modelled, so the stub case is not encoded.
  pure def resetRequired(a: App, e: Engine, r: Relay, bug: str): bool =
    (e.log.length() >= a.appliedLog.length() and not(isPrefix(a.appliedLog, e.log)))
    or (bug != "noAheadReset" and e.log.length() < a.appliedLog.length()
        and e.log == r.log and not(r.hold))

  // Delete the synced data, import no snapshot, apply each outbox row again.
  // Rules: [DLV-12]
  pure def applyReset(a: App, bug: str): App =
    { ...a, applied: if (bug == "resetDropsOutbox") Set() else a.outbox, appliedLog: List() }

  // ---- engine

  pure def knows(e: Engine, id: Id): bool =
    e.outbox.keys().contains(id) or e.refused.contains(id) or ids(e.log).contains(id)

  // Enqueue has no effect if the engine already knows the change_id.
  // Rules: [DLV-5]
  // Partial: a change_id has one content, so the different-bytes refusal is not encoded.
  pure def canEnqueue(a: App, e: Engine, id: Id): bool =
    a.outbox.contains(id) and not(knows(e, id))

  // An own envelope leaves the outbox only when the verified log holds it.
  // Rules: [DLV-8]
  // Partial: stubs are not modelled, so the replacement of a covered record is not encoded.
  // The fresh flag ends at a fetch that reaches the relay head with no hold
  // (PROTOCOL.md 10.8). A fetch during a hold keeps it (F3).
  pure def applyFetch(e: Engine, newLog: List[Rcd], r: Relay, bug: str): Engine = {
    val clears = (newLog == r.log and not(r.hold)) or (bug == "freshClearsOnFetch" and newLog.length() > 0)
    { ...e, log: newLog, outbox: without(e.outbox, ids(newLog)), fresh: e.fresh and not(clears) }
  }

  // ---- relay

  // Refused is permanent (size limit). BadBase is transient: the signed base is
  // not an entry of the relay log, after a rollback or on another branch.
  // Known: the change_id is in the log with the same record hash (the original
  // position). Conflict: the change_id is in the log with another record hash.
  // The reply names the original position. The model does not carry the position,
  // because the content of every record of an id is the same.
  type Verdict = Stored | Known | Conflict | Refused | BadBase

  // Known and Conflict come before the size and base checks.
  // Rules: [DLV-7] [DLV-9] [LOG-6] [WIR-6]
  // Partial: epochs are not modelled, so DLV-7 (new epoch) is not encoded.
  pure def verdict(r: Relay, id: Id, rec: Rcd, base: List[Rcd], big: bool, bug: str): Verdict = {
    val known = ids(r.log).contains(id)
    val sameRec = r.log.foldl(false, (b, x) => b or x == rec)
    val tooBig = big and r.limitLow
    if (bug == "sizeBeforeDedupe" and tooBig) Refused
    else if (known and sameRec and bug != "relayNoDedupe") Known
    else if (known and not(sameRec) and bug != "relayNoDedupe" and bug != "relayConflictAppends") Conflict
    else if (tooBig) Refused
    else if (not(isPrefix(base, r.log))) BadBase
    else Stored
  }

  pure def verdictEvent(v: Verdict): Event = match v {
    | Stored => EvPushStored
    | Known => EvPushKnown
    | Conflict => EvPushConflict
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
  def active(d: Dev): bool = activeIn(d, relay.log)
  // The devices of the space: each device outside LATE, and each LATE device that got a grant.
  def members: Set[Dev] = DEVS.filter(d => not(LATE.contains(d)) or env.granted.contains(d))
  // The relay reads a stored tip as reported if the log holds it now (PROTOCOL.md 10.8).
  def reportedNow(d: Dev): bool = relay.reporters.contains(d) and isPrefix(relay.tips.get(d), relay.log)
  def allReported: bool = members.forall(d => reportedNow(d))
  def canFault(f: str): bool = FAULTS.contains(f) and env.faults < MAX_FAULTS
  def fault(e: Event): Env = { ...ev(e), faults: env.faults + 1 }

  // ---------------------------------------------------------------- actions

  action init: bool = all {
    BUGS.contains(BUG),
    FAULTS.subseteq(FAULT_CLASSES),
    apps' = DEVS.mapBy(_ => freshApp),
    engines' = DEVS.mapBy(_ => freshEngine),
    LATE.subseteq(DEVS),
    relay' = { log: List(), hold: false, reporters: Set(), tips: DEVS.mapBy(_ => List()), marked: Set(),
               limitLow: false, session: noSession },
    env' = { nextId: 0, changes: Map(), stored: Set(), exposed: Set(), reverted: Set(),
             lostAtRelease: Set(), silentLoss: false, granted: Set(), faults: 0, events: Set() },
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
  // The engine does not check the size limit. Only the relay refuses a change for
  // size, and it checks the known change_id first (F4).
  // Rules: [DLV-2] [DLV-5]
  action enqueue(d: Dev, id: Id): bool = {
    val tooBig = BUG == "enqueueChecksSize" and env.changes.get(id).big and relay.limitLow
    all {
      canEnqueue(app(d), eng(d), id),
      engines' = engines.set(d,
        if (tooBig) { ...eng(d), refused: eng(d).refused.union(Set(id)) }
        else { ...eng(d), outbox: eng(d).outbox.put(id, { base: eng(d).log, rec: id + MAX_IDS * eng(d).gen }) }),
      apps' = if (BUG == "appDropsRowOnEnqueue")
                apps.set(d, { ...app(d), outbox: app(d).outbox.exclude(Set(id)) })
              else apps,
      relay' = relay,
      env' = if (tooBig) env else { ...env, stored: env.stored.union(Set(id)) },
    }
  }

  // The engine sends one stored envelope. If the response is lost, the engine
  // learns nothing and sends the same envelope again later.
  // On Conflict (the relay holds the change_id with another record hash, which
  // happens after an engine state loss) the engine fetches the record at the
  // reported position. The content of a change_id is fixed in this model, so the
  // record holds the same content hash and the engine treats the change as stored:
  // it keeps the envelope until a fetch shows the change_id in the verified log
  // (DLV-8, in applyFetch). Mutant conflictRefuses refuses it for ever instead.
  // Partial: a record with other content under the same change_id is not encoded.
  // Rules: [DLV-6] [DLV-7] [DLV-9] [LOG-14]
  action push(d: Dev, id: Id, lost: bool): bool = {
    val p = eng(d).outbox.get(id)
    val v = verdict(relay, id, p.rec, p.base, env.changes.get(id).big, BUG)
    all {
      eng(d).outbox.keys().contains(id),
      running(d),
      active(d),
      not(relay.hold),
      relay' = if (v == Stored) { ...relay, log: relay.log.append(p.rec) } else relay,
      engines' =
        if ((v == Refused or (v == Conflict and BUG == "conflictRefuses")) and not(lost))
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
  // n equal to the verified length is a fetch that adds nothing: it can still
  // reach the relay head and end the fresh flag.
  action fetchExtend(d: Dev, n: int): bool = all {
    running(d),
    active(d),
    isPrefix(eng(d).log, relay.log),
    eng(d).log.length() < n or (n == relay.log.length() and eng(d).fresh and not(relay.hold)),
    n <= relay.log.length(),
    engines' = engines.set(d, applyFetch(eng(d), relay.log.slice(0, n), relay, BUG)),
    apps' = apps,
    relay' = relay,
    env' = ev(EvFetch),
  }

  // Fetch when the relay log conflicts with a verified entry: stop with fork.
  // adoptFork adopts the conflicting log. noRepair adopts a shorter log.
  // Rules: [FRK-1]
  action fetchConflict(d: Dev): bool = {
    val e = eng(d)
    val shorter = isPrefix(relay.log, e.log) and relay.log.length() < e.log.length()
    val forked = not(comparable(e.log, relay.log))
    val adopt = (forked and BUG == "adoptFork") or (shorter and BUG == "noRepair")
    all {
      running(d),
      active(d),
      forked or (shorter and BUG == "noRepair"),
      engines' = engines.set(d, if (adopt) applyFetch(e, relay.log, relay, BUG) else { ...e, stop: Forked }),
      apps' = apps,
      relay' = relay,
      env' = ev(if (adopt) EvFetch else EvForkDetected),
    }
  }

  // A device needs a repair: the relay log is a proper prefix of its verified log.
  // Rules: [LOG-10]
  def needsRepair(d: Dev): bool =
    running(d) and isPrefix(relay.log, eng(d).log) and relay.log.length() < eng(d).log.length()

  // Start a repair session with the first chunk: the n verified entries after the
  // relay head. The relay stages them and checks the chain. A space has one
  // session. A start replaces a session of the same device. The signer must be
  // active in the log or in the staged entries, so a device whose grant is only
  // in the lost range can repair. The relay accepts a repair during a restore hold.
  // Rules: [LOG-10] [LOG-11] [LOG-12] [LOG-14]
  // Partial: the device learns the relay head from a fetch, which a device that
  // is not active cannot do. PROTOCOL.md 10.9 needs the relay head as the base.
  action startRepair(d: Dev, n: int): bool = {
    val h = relay.log.length()
    val chunk = eng(d).log.slice(h, h + n)
    val signerOk = active(d) or (BUG != "repairNeedsLogGrant" and activeIn(d, relay.log.concat(chunk)))
    val early = BUG == "repairMovesEarly"
    all {
      BUG != "noRepair",
      needsRepair(d),
      1 <= n, h + n <= eng(d).log.length(),
      not(relay.session.live) or relay.session.owner == d or BUG == "repairMultiSession",
      signerOk,
      relay' = { ...relay,
        log: if (early) relay.log.concat(chunk) else relay.log,
        session: { live: true, owner: d,
                   base: if (early) relay.log.concat(chunk) else relay.log,
                   staged: if (early) List() else chunk } },
      engines' = engines,
      apps' = apps,
      env' = { ...ev(EvRepairStart), events: env.events.union(
                 if (active(d)) Set(EvRepairStart) else Set(EvRepairStart, EvLateRepair)) },
    }
  }

  // Add the next n entries to the session of d. The relay head must not have
  // changed since the start.
  // Rules: [LOG-11] [LOG-12]
  action chunkRepair(d: Dev, n: int): bool = {
    val ses = relay.session
    val k = ses.base.length() + ses.staged.length()
    val chunk = eng(d).log.slice(k, k + n)
    val early = BUG == "repairMovesEarly"
    all {
      running(d),
      ses.live, ses.owner == d,
      relay.log == ses.base,
      isPrefix(ses.base.concat(ses.staged), eng(d).log),
      1 <= n, k + n <= eng(d).log.length(),
      relay' = { ...relay,
        log: if (early) relay.log.concat(chunk) else relay.log,
        session: if (early) { ...ses, base: relay.log.concat(chunk) }
                 else { ...ses, staged: ses.staged.concat(chunk) } },
      engines' = engines,
      apps' = apps,
      env' = ev(EvRepairChunk),
    }
  }

  // The finish names the verified head of d. The relay moves the staged entries
  // into the log in one transaction and ends the session.
  // Rules: [LOG-10] [LOG-11]
  // Partial: no stubs, so the snapshot rule of [LOG-11] holds for every staged range.
  action finishRepair(d: Dev): bool = {
    val ses = relay.session
    all {
      running(d),
      ses.live, ses.owner == d,
      relay.log == ses.base,
      ses.base.concat(ses.staged) == eng(d).log,
      relay' = { ...relay, log: eng(d).log, session: noSession },
      engines' = engines,
      apps' = apps,
      env' = ev(EvRepair),
    }
  }

  // 24 hours pass without a chunk. The relay deletes the staged entries.
  // Mutant repairNoExpiry keeps the session.
  // Rules: [LOG-11]
  action expireSession: bool = all {
    relay.session.live,
    relay' = if (BUG == "repairNoExpiry") relay else { ...relay, session: noSession },
    engines' = engines,
    apps' = apps,
    env' = ev(EvRepairExpired),
  }

  // An active device g grants a LATE device d. A grant is a security record, so
  // the relay accepts it during a hold. Its base is the verified log of g.
  // Rules: [LOG-8] [LOG-14]
  action grantDevice(g: Dev, d: Dev): bool = all {
    running(g),
    active(g),
    isPrefix(eng(g).log, relay.log),
    LATE.contains(d),
    not(active(d)),
    not(env.granted.contains(d)),
    relay' = { ...relay, log: relay.log.append(GRANT + d) },
    engines' = engines,
    apps' = apps,
    env' = { ...ev(EvGrant), granted: env.granted.union(Set(d)) },
  }

  // Status report during a restore hold: the verified log of the device and its
  // fresh flag. A new report replaces the tip. The fresh mark stays until the
  // hold ends (PROTOCOL.md 10.8).
  // Rules: [LOG-14]
  action reportStatus(d: Dev): bool = {
    val markNew = eng(d).fresh and not(relay.marked.contains(d))
    all {
      relay.hold,
      running(d),
      active(d),
      not(relay.reporters.contains(d)) or relay.tips.get(d) != eng(d).log or markNew,
      relay' = { ...relay, reporters: relay.reporters.union(Set(d)), tips: relay.tips.set(d, eng(d).log),
                           marked: if (eng(d).fresh) relay.marked.union(Set(d)) else relay.marked },
      engines' = engines,
      apps' = apps,
      env' = env,
    }
  }

  // The end of a hold. The relay forgets the reports. The ghost state records
  // the changes that only app DBs hold at this point: the release loses them. A
  // release with no warning that loses a change is silent.
  // Rules: [LOG-14] [LOG-15]
  action endHold(e: Event, warned: bool): bool = {
    val newLoss = unheldApplied.exclude(env.lostAtRelease)
    all {
      relay' = { ...relay, hold: false, reporters: Set(), tips: DEVS.mapBy(_ => List()), marked: Set() },
      engines' = engines,
      apps' = apps,
      env' = { ...ev(e), lostAtRelease: env.lostAtRelease.union(newLoss),
               silentLoss: env.silentLoss or (not(warned) and newLoss != Set()) },
    }
  }

  // Only the user (user page) or the relay operator (snailfish-relay
  // release-hold) ends a hold. This action is a release after the reports show
  // a reported tip from every device and mark no device as "not repaired". The
  // relay does not end a hold by itself.
  // Rules: [LOG-15]
  action releaseHold: bool = all {
    relay.hold,
    allReported,
    BUG == "releaseIgnoresFresh" or relay.marked == Set(),
    endHold(EvHoldReleased, false),
  }

  // Rules: [DLV-10] [DLV-11]
  action pull(d: Dev, crash: bool): bool = all {
    canPull(app(d), eng(d)),
    apps' = apps.set(d, applyPull(app(d), eng(d), crash, BUG)),
    engines' = engines,
    relay' = relay,
    env' = ev(if (app(d).outbox.contains(nextEntry(app(d), eng(d)))) EvPullOwn else EvPull),
  }

  // Rules: [DLV-12]
  action handleReset(d: Dev): bool = all {
    resetRequired(app(d), eng(d), relay, BUG),
    apps' = apps.set(d, applyReset(app(d), BUG)),
    engines' = engines,
    relay' = relay,
    env' = ev(if (eng(d).log.length() < app(d).appliedLog.length()) EvResetAhead else EvResetRequired),
  }

  // The app reads the degraded status and removes the outbox row of a refused
  // change: it reverts the edit, or it splits it into a new, smaller change.
  // Rules: [DLV-9]
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
      { ...e, gen: 0 } != { ...freshEngine, fresh: e.fresh },
      engines' = engines.set(d, { ...freshEngine, fresh: true, gen: e.gen + 1 }),
      apps' = apps,
      relay' = relay,
      env' = { ...fault(EvEngineLoss),
               exposed: env.exposed.union(e.outbox.keys()).union(e.refused).union(ids(e.log)) },
    }
  }

  // snailfish-relay restore from an older backup. A backup is a log prefix.
  // Rules: [LOG-14]
  action restoreRelay(k: int): bool = all {
    canFault("relayRestore"),
    0 <= k, k < relay.log.length(),
    relay' = { ...relay, log: relay.log.slice(0, k), hold: BUG != "noHold", reporters: Set(),
               tips: DEVS.mapBy(_ => List()), marked: Set(),
               session: noSession },
    engines' = engines,
    apps' = apps,
    env' = fault(EvRelayRestore),
  }

  // A storage fault rolls the relay back with no restore command and no hold.
  action rollBackRelay(k: int): bool = all {
    canFault("silentRollback"),
    0 <= k, k < relay.log.length(),
    relay' = { ...relay, log: relay.log.slice(0, k), session: noSession },
    engines' = engines,
    apps' = apps,
    env' = fault(EvRelayFault),
  }

  // The user page marks a device as "not repaired". The user confirms the warning
  // and releases. The changes that only the lost engine state file held are lost.
  action releaseHoldWarned: bool = all {
    FAULTS.contains("warnedRelease"),
    relay.hold,
    allReported,
    relay.marked != Set(),
    endHold(EvWarnedRelease, true),
  }

  // The user page shows that a device did not report. The user releases anyway.
  action releaseHoldEarly: bool = all {
    FAULTS.contains("earlyRelease"),
    relay.hold,
    not(allReported),
    endHold(EvEarlyRelease, true),
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
      startRepair(d, k),
      chunkRepair(d, k),
      finishRepair(d),
      expireSession,
      { nondet g = DEVS.oneOf() grantDevice(g, d) },
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
      releaseHoldWarned,
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

  // Changes in an app state that sync can no longer deliver.
  val unheldApplied: Set[Id] = DEVS.fold(Set(), (s, d) => s.union(app(d).applied)).exclude(held)

  // I1. Each device applies each change once (merge contract).
  // Rules: [MRG-1]
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

  // I5. A change that an app reverted after a permanent refusal is in no log. If
  // it is, a device holds it and the other devices apply it, so the devices
  // diverge without notice (goal 8).
  // Limit F1: a silent rollback, or a hold release before every device reports,
  // can break it.
  val logged: Set[Id] = DEVS.fold(ids(relay.log), (s, d) => s.union(ids(eng(d).log)))
  val refusedNotStored: bool = env.reverted.intersect(logged) == Set()

  // I7. No running device is stuck. A device that fetched to the relay head, with
  // no hold, either holds the same position as the relay or can pull or reset.
  // Without the reset for an applied position past the log end (F2), it is stuck.
  val noStuckDevice: bool = DEVS.forall(d =>
    (running(d) and eng(d).log == relay.log and not(relay.hold) and app(d).appliedLog != eng(d).log)
      implies (canPull(app(d), eng(d)) or resetRequired(app(d), eng(d), relay, BUG)))

  // I8. No hold ends without a warning while it loses a change (F3). An engine
  // state loss and a relay restore can leave a change that only an app DB holds.
  // The user page then marks a device as "not repaired", so the user sees the
  // loss before the release.
  val noSilentLoss: bool = not(env.silentLoss)

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
  val wPushConflict: bool = happened(EvPushConflict)
  val wPushRefused: bool = happened(EvPushRefused)
  val wPushBadBase: bool = happened(EvPushBadBase)
  val wResetAhead: bool = happened(EvResetAhead)
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
  val wWarnedRelease: bool = happened(EvWarnedRelease)
  // A warned release lost a change: the case that the "not repaired" mark is for.
  val wWarnedLoss: bool = happened(EvWarnedRelease) and env.lostAtRelease != Set()
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
  val wGrant: bool = happened(EvGrant)
  // A repair with at least one chunk after the start.
  val wChunkedRepair: bool = happened(EvRepairChunk) and happened(EvRepair)
  val wRepairExpired: bool = happened(EvRepairExpired)
  // A device that is not active in the relay log started a repair [LOG-12].
  val wLateRepair: bool = happened(EvLateRepair)
  val wRepairThenRelease: bool = happened(EvRepair) and (happened(EvHoldReleased) or happened(EvWarnedRelease))
  // Two faults lost a change that enqueue stored (expected: see noLostChangeWeak).
  val wDoubleFaultLoss: bool = not(env.stored.exclude(env.reverted).subseteq(held))
}
