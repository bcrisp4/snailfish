// Log compaction: snapshots, accept records, the frontier, the usable
// snapshot and stubs on the relay and on each device (DESIGN.md "Log
// compaction", the CMP rules, [LOG-11] and [DLV-12]).
// specs/compaction/README.md has the coverage map and the findings.
//
// Abstractions:
//  - One space. Devices 1 and 2 are active from the genesis record. Device 3
//    joins later through a grant: a new device, or a full recovery (S5) with
//    the recovery key. Signatures, hashes and bytes are outside the model.
//  - `canon` is the one log of the space, in full. It is ghost state: the
//    relay log and each device log are prefixes of it, each with its own
//    stub marks. The model has no fork: a relay rollback puts the space on
//    hold, and the hold ends only with a repair to the full log.
//  - A change is an int id. The app state is the set of applied ids (merge
//    contract). A snapshot holds the app state of its author as a set of ids.
//  - The applied position is the position of the last change that the app
//    applied, or the state position of an imported snapshot. Other records do
//    not move it ([CMP-10]).
//  - A stub keeps the kind and the change id of its record and loses the
//    rest. The model code that runs on a device or on the relay reads only
//    these fields of a stub ([CMP-1]).
//  - A fetch reads to the relay head in one action. The engine checks the
//    stubs after the fetch reaches the head (see README "Fetch and stubs").
//  - A repair session is one action (start, chunks and finish). specs/delivery
//    models the chunks and the session rules.
//  - Each app DB transaction and each engine transaction is one action.
//
// The const BUG selects one deliberate design violation. "none" is the design.
module compaction {
  type Dev = int
  type Kind = Gen | Chg | Snap | Acc | Grant | Rem

  type Entry = {
    kind: Kind,
    id: int,            // Chg: the change id
    author: Dev,
    epoch: int,         // Chg, Snap: the epoch of the key that encrypts it
    statePos: int,      // Snap: the state position
    content: Set[int],  // Snap: the change ids of the app state
    readable: bool,     // Snap: false if the ciphertext does not decrypt
    snapPos: int,       // Acc: the position of the snapshot
    applied: int,       // Acc: the applied position of the author
    dev: Dev,           // Grant: the new device. Rem: the removed device
    sealed: Set[int],   // Grant: the epochs of the key set to the new device
    size: int,          // bytes against the space quota
    stub: bool,
    act: Set[Dev],      // cache: the active devices after this entry ([LOG-8])
    ep: int,            // cache: the current epoch after this entry
    u: int,             // cache: the usable snapshot of the log that ends here
  }

  type Event =
    | EvEdit | EvPush | EvQuotaRefused | EvStoredAfterCompaction | EvSnapshot | EvUnreadableSnapshot
    | EvAccept | EvRelayCompact | EvDeviceCompact | EvGrant | EvRemove | EvDestroy
    | EvReset | EvResetImport | EvCoveredDropped | EvNewDeviceImport | EvCompactAfterRemoval
    | EvRollback | EvRepairStubs | EvBadRepairRefused | EvUnreadableKeptFull | EvSnapshotAtFull
    | EvAppRestore | EvEngineLoss | EvSnapshotStubSkipped | EvAcceptedAfterGrant

  type AppImage = { app: Set[int], outbox: Set[int], applied: int }

  type Device = {
    log: List[Entry],   // the verified log, with the own stub marks
    applied: int,
    app: Set[int],
    outbox: Set[int],   // app outbox rows (and the engine envelopes)
    backup: AppImage,
    alive: bool,        // false after the device is destroyed (S5)
    fresh: bool,        // ghost: the app DB or the engine state file is older than the log
    stopped: bool,      // stopped: missing records ([CMP-15])
  }

  type State = {
    canon: List[Entry],
    relay: List[Entry],
    hold: bool,
    devs: Dev -> Device,
    nextId: int,
    made: Set[int],
    lost: Set[int],         // ghost: unsent edits that an app DB restore or a fire destroyed
    dups: int,              // ghost: changes applied twice
    needless: bool,         // ghost: a ResetRequired on a device with no lost state
    unreadable: bool,       // ghost: a device pulled a change that it cannot decrypt
    events: Set[Event],
  }

  const MAX_IDS: int        // the most changes in a run
  const MAX_LEN: int        // the longest log
  const QUOTA: int          // the space quota for changes, snapshots and accept records
  const RESERVE: int        // the snapshot reserve on top of the quota ([CMP-18])
  const SNAP_SIZE: int
  const FAULTS: Set[str]    // "rollback", "appRestore", "engineLoss", "badRepair", "unreadable", "destroy"
  const BUG: str

  pure val BUGS: Set[str] = Set(
    "none",
    "compactBeforeAccept",  // the relay makes stubs for the newest valid snapshot, accepted or not
    "acceptCountsNow",      // acceptance counts the devices that are active now, not at the position
    "validNeedsActiveNow",  // a snapshot is valid only while its author is active
    "acceptUnreadable",     // a device accepts a snapshot that does not decrypt
    "acceptEarly",          // a device accepts before it applies past the state position
    "stubSecurity",         // the relay makes stubs for security records too
    "stubAccept",           // the relay makes stubs for accept records too
    "resetOnStubOnly",      // ResetRequired only if a change stub follows the applied position
    "resetKeepsCovered",    // the reset applies a covered outbox row and keeps the row
    "resetDropsOutbox",     // the reset does not apply the outbox rows again
    "snapshotWithOutbox",   // a device writes a snapshot with a non-empty outbox
    "sealCurrentOnly",      // a grant seals only the key of the current epoch
    "repairNoCoverCheck",   // the relay moves a staged stub that no usable snapshot covers
    "snapshotNoReserve",    // a snapshot counts against the quota with no reserve
    "stubsCount",           // stubs count against the quota
  )
  pure val INIT: Set[Dev] = Set(1, 2)
  pure val LATE: Set[Dev] = Set(3, 4)
  pure val DEVS: Set[Dev] = INIT.union(LATE)
  pure val ACC_SIZE: int = 1
  pure val CHG_SIZE: int = 1

  pure val blank: Entry = {
    kind: Gen, id: 0, author: 0, epoch: 1, statePos: 0, content: Set(), readable: true,
    snapPos: 0, applied: 0, dev: 0, sealed: Set(), size: 0, stub: false, act: Set(), ep: 1, u: 0,
  }

  // ---- Log content: functions that a device or the relay computes ----

  pure def at(log: List[Entry], p: int): Entry = log.nth(p - 1)
  // Apalache needs constant ranges, so these helpers filter 1..MAX_LEN.
  pure def positions(log: List[Entry]): Set[int] = 1.to(MAX_LEN).filter(p => p <= log.length())
  pure def between(a: int, b: int): Set[int] = 1.to(MAX_LEN).filter(p => a <= p and p <= b)
  pure def firstN(log: List[Entry], n: int): List[Entry] =
    log.foldl(List(), (out, e) => if (out.length() < n) out.append(e) else out)
  pure def dropN(log: List[Entry], n: int): List[Entry] =
    log.foldl({ i: 0, out: List() }, (acc, e) =>
      { i: acc.i + 1, out: if (acc.i >= n) acc.out.append(e) else acc.out }).out
  pure def isSecurity(e: Entry): bool = e.kind == Gen or e.kind == Grant or e.kind == Rem

  // [LOG-8] The active devices after the entries 1 to n. Each entry caches
  // them: `withCache` computes the cache from the entry before it.
  pure def activeAfter(log: List[Entry], n: int): Set[Dev] = if (n == 0) Set() else at(log, n).act
  pure def epochAfter(log: List[Entry], n: int): int = if (n == 0) 1 else at(log, n).ep
  pure def everActive(log: List[Entry]): Set[Dev] =
    log.foldl(Set(), (s, e) => if (e.kind == Gen) INIT else if (e.kind == Grant) s.union(Set(e.dev)) else s)
  pure def currentEpoch(log: List[Entry]): int = epochAfter(log, log.length())
  pure def withCache(log: List[Entry], e: Entry, bug: str): Entry = {
    val before = activeAfter(log, log.length())
    val act = if (e.kind == Gen) INIT
      else if (e.kind == Grant) before.union(Set(e.dev))
      else if (e.kind == Rem) before.exclude(Set(e.dev))
      else before
    val e2 = { ...e, act: act, ep: if (e.kind == Rem) currentEpoch(log) + 1 else currentEpoch(log) }
    { ...e2, u: usableFull(log.append(e2), bug) }
  }

  // [CMP-3] [CMP-4] A snapshot is valid if its state position is before its
  // record and its author is active at its position. A later removal of the
  // author does not change that.
  pure def valid(log: List[Entry], p: int, bug: str): bool = {
    val e = at(log, p)
    val authorOk = if (bug == "validNeedsActiveNow") activeAfter(log, log.length()).contains(e.author)
                   else activeAfter(log, p - 1).contains(e.author)
    e.kind == Snap and not(e.stub) and e.statePos >= 1 and e.statePos < p and authorOk
  }

  // [CMP-6] A snapshot is accepted at the first position q where the log
  // holds an accept record for it from every device that is active at q.
  // Each counted accept names an applied position at or after the state
  // position. After that the snapshot stays accepted.
  pure def acceptedBy(log: List[Entry], p: int, q: int, d: Dev): bool =
    between(p + 1, q).exists(r => {
      val a = at(log, r)
      a.kind == Acc and not(a.stub) and a.author == d and a.snapPos == p and a.applied >= at(log, p).statePos
    })
  pure def accepted(log: List[Entry], p: int, bug: str): bool =
    if (bug == "compactBeforeAccept") true
    else if (bug == "acceptCountsNow")
      activeAfter(log, log.length()).forall(d => acceptedBy(log, p, log.length(), d))
    else {
      // One pass from p + 1: `got` holds the devices with a counted accept.
      val sp = at(log, p).statePos
      dropN(log, p).foldl({ got: Set(), done: false }, (acc, a) => {
        val got = if (a.kind == Acc and not(a.stub) and a.snapPos == p and (a.applied >= sp or bug == "acceptEarly"))
                    acc.got.union(Set(a.author)) else acc.got
        { got: got, done: acc.done or a.act.subseteq(got) }
      }).done
    }

  pure def candidates(log: List[Entry], bug: str): Set[int] =
    positions(log).filter(p => valid(log, p, bug) and accepted(log, p, bug))

  // [CMP-8] The frontier is the highest state position of an accepted, valid
  // snapshot. The usable snapshot has that state position, and the highest
  // log position of the ties. 0 means no usable snapshot.
  // The engine and the relay compute the usable snapshot from the log
  // content. Each entry caches it for the log that ends at the entry, because
  // the full computation is slow in the simulator. A stub does not change it:
  // a covered record is never valid, accepted or a counted accept.
  pure def usable(log: List[Entry], bug: str): int = if (log.length() == 0) 0 else at(log, log.length()).u
  pure def usableFull(log: List[Entry], bug: str): int =
    candidates(log, bug).fold(0, (m, p) =>
      if (m == 0 or at(log, p).statePos > at(log, m).statePos
          or (at(log, p).statePos == at(log, m).statePos and p > m)) p else m)
  pure def frontier(log: List[Entry], bug: str): int = {
    val u = usable(log, bug)
    if (u > 0) at(log, u).statePos else 0
  }

  // [CMP-11] The usable snapshot covers each change at or before the frontier
  // and each other snapshot with a lower state position, or the same state
  // position at a lower log position (finding C1). Security records and
  // accept records are never covered ([CMP-20]). This form needs the full
  // record: the relay and the engine use it to make stubs.
  pure def covers(log: List[Entry], u: int, p: int, bug: str): bool = {
    val e = at(log, p)
    val f = if (u > 0) at(log, u).statePos else 0
    u > 0 and (
      (e.kind == Chg and p <= f)
      or (e.kind == Snap and p != u and (e.statePos < f or (e.statePos == f and p < u)))
      or (bug == "stubSecurity" and isSecurity(e) and p <= f)
      or (bug == "stubAccept" and e.kind == Acc and p < u)
    )
  }

  // [CMP-15] The check of a stub. A stub keeps only its kind and change id, so
  // a change stub must be at or before the frontier, and a snapshot stub must
  // not be the usable snapshot (finding C2). Each other stub is invalid.
  pure def stubValid(log: List[Entry], u: int, p: int): bool = {
    val e = at(log, p)
    u > 0 and ((e.kind == Chg and p <= at(log, u).statePos) or (e.kind == Snap and p != u))
  }
  pure def stubsValidWith(log: List[Entry], u: int): bool =
    positions(log).forall(p => at(log, p).stub implies stubValid(log, u, p))
  pure def stubsValid(log: List[Entry]): bool = stubsValidWith(log, usable(log, "none"))

  // [CMP-12] [CMP-13] Replace each covered record with a stub.
  pure def compactWith(log: List[Entry], u: int, bug: str): List[Entry] =
    log.foldl(List(), (out, e) => {
      val p = out.length() + 1
      out.append(if (covers(log, u, p, bug)) { ...e, stub: true } else e)
    })
  pure def compact(log: List[Entry], bug: str): List[Entry] = compactWith(log, usable(log, bug), bug)

  // [CMP-14] `is_covered`: the log holds the change id, in full or as a stub,
  // at or before the state position of the usable snapshot.
  pure def coveredIdsWith(log: List[Entry], u: int): Set[int] =
    if (u == 0) Set() else changesUpTo(log, at(log, u).statePos)
  pure def isCovered(log: List[Entry], id: int, bug: str): bool = coveredIdsWith(log, usable(log, bug)).contains(id)

  // [CMP-20] A grant seals the key of each epoch that a change or a snapshot
  // uses if the usable snapshot does not cover it, and the current epoch.
  pure def neededWith(log: List[Entry], u: int, bug: str): Set[int] =
    positions(log).filter(p => {
      val e = at(log, p)
      (e.kind == Chg or e.kind == Snap) and not(e.stub) and not(covers(log, u, p, bug))
    }).map(p => at(log, p).epoch).union(Set(currentEpoch(log)))
  pure def neededEpochs(log: List[Entry], bug: str): Set[int] = neededWith(log, usable(log, bug), bug)
  // A grant also seals epoch 1: each engine opens it as its app key.
  pure def sealFor(log: List[Entry], bug: str): Set[int] =
    if (bug == "sealCurrentOnly") Set(currentEpoch(log)) else neededEpochs(log, bug).union(Set(1))

  // The keys of a device: epoch 1 from the genesis record, the sealed epochs
  // of its grant, and each epoch record that keeps it.
  pure def keysOf(log: List[Entry], d: Dev): Set[int] =
    positions(log).fold(Set(), (k, p) => {
      val e = at(log, p)
      if (e.kind == Gen and INIT.contains(d)) k.union(Set(1))
      else if (e.kind == Grant and e.dev == d) k.union(e.sealed)
      else if (e.kind == Rem and activeAfter(log, p).contains(d)) k.union(Set(epochAfter(log, p)))
      else k
    })

  pure def holdsId(log: List[Entry], id: int): bool =
    positions(log).exists(p => at(log, p).kind == Chg and at(log, p).id == id)
  pure def changesUpTo(log: List[Entry], n: int): Set[int] =
    positions(log).filter(p => p <= n and at(log, p).kind == Chg).map(p => at(log, p).id)

  // [CMP-19] Stubs do not count against the quota.
  pure def used(log: List[Entry], bug: str): int =
    log.foldl(0, (n, e) => if (isSecurity(e) or (e.stub and bug != "stubsCount")) n else n + e.size)
  pure def fullSnapshots(log: List[Entry]): int =
    log.foldl(0, (n, e) => if (e.kind == Snap and not(e.stub)) n + 1 else n)

  // [CMP-16] [DLV-12] ResetRequired: the applied position is before the
  // frontier of the verified log (finding C4). Each change stub is at or
  // before the frontier, so this holds also if a change stub follows the
  // applied position. A snapshot stub does not move the frontier (finding C3).
  pure def resetRequired(dv: Device, bug: str): bool =
    if (bug == "resetOnStubOnly")
      positions(dv.log).exists(p => p > dv.applied and at(dv.log, p).stub and at(dv.log, p).kind == Chg)
    else frontier(dv.log, bug) > dv.applied

  // The next change after the applied position, or 0.
  pure def nextChange(log: List[Entry], applied: int): int =
    positions(log).fold(0, (m, p) =>
      if (p > applied and at(log, p).kind == Chg and (m == 0 or p < m)) p else m)

  pure def restoreFull(cut: List[Entry], uc: int, canon: List[Entry]): List[Entry] =
    cut.foldl(List(), (out, e) => {
      val p = out.length() + 1
      out.append(if (e.stub and not(covers(cut, uc, p, "none"))) canon.nth(p - 1) else e)
    })

  // ---- State machine ----

  var s: State
  def dev(d: Dev): Device = s.devs.get(d)
  def active(d: Dev): bool = activeAfter(s.relay, s.relay.length()).contains(d) and dev(d).alive
  def ev(e: Event): Set[Event] = s.events.union(Set(e))

  pure val genesis: Entry = { ...blank, kind: Gen, epoch: 1, act: INIT, ep: 1 }
  pure val newDevice: Device = {
    log: List(genesis), applied: 0, app: Set(), outbox: Set(),
    backup: { app: Set(), outbox: Set(), applied: 0 },
    alive: true, fresh: false, stopped: false,
  }

  action init: bool = s' = {
    canon: List(genesis), relay: List(genesis), hold: false,
    devs: DEVS.mapBy(_ => newDevice),
    nextId: 1, made: Set(), lost: Set(), dups: 0, needless: false, unreadable: false, events: Set(),
  }

  // Append one record at the relay head, and to the ghost log.
  action appendRecord(e: Entry, events: Set[Event]): bool = all {
    s.relay.length() < MAX_LEN,
    s' = { ...s, canon: s.canon.append(withCache(s.canon, e, BUG)), relay: s.relay.append(withCache(s.canon, e, BUG)),
           events: events },
  }

  // The app commits an edit and its outbox row in one transaction.
  action edit(d: Dev): bool = all {
    dev(d).alive,
    s.nextId <= MAX_IDS,
    s' = { ...s, nextId: s.nextId + 1, made: s.made.union(Set(s.nextId)),
      devs: s.devs.set(d, { ...dev(d), app: dev(d).app.union(Set(s.nextId)),
                                        outbox: dev(d).outbox.union(Set(s.nextId)) }),
      events: ev(EvEdit) },
  }

  // The engine sends an outbox change. [DLV-5] [DLV-7] The relay holds the
  // change id, in full or as a stub: no effect. [QTA-1] A full quota refuses
  // the change, and the row stays.
  action push(d: Dev, id: int): bool = {
    val e = { ...blank, kind: Chg, id: id, author: d, epoch: currentEpoch(s.relay), size: CHG_SIZE }
    val full = used(s.relay, BUG) + CHG_SIZE > QUOTA
    all {
      active(d), not(s.hold), dev(d).outbox.contains(id), not(holdsId(s.canon, id)),
      if (full) s' = { ...s, events: ev(EvQuotaRefused) }
      else appendRecord(e, if (s.events.contains(EvQuotaRefused) and s.events.contains(EvRelayCompact))
                       ev(EvStoredAfterCompaction) else ev(EvPush)),
    }
  }

  // A fetch to the relay head. [CMP-15] After the fetch, the engine checks
  // each stub against the usable snapshot of its log.
  action fetch(d: Dev): bool = all {
    active(d), not(dev(d).stopped), s.relay.length() > dev(d).log.length(),
    fetchWith(d, dev(d).log.concat(dropN(s.relay, dev(d).log.length()))),
  }
  action fetchWith(d: Dev, log2: List[Entry]): bool =
    s' = { ...s, devs: s.devs.set(d, { ...dev(d), log: log2, stopped: not(stubsValid(log2)) }) }

  // [DLV-10] [DLV-11] `changes_after` and the app apply the next change.
  // [DLV-13] A change that the device cannot decrypt is skipped.
  action pull(d: Dev): bool = {
    val dv = dev(d)
    val p = nextChange(dv.log, dv.applied)
    val e = at(dv.log, if (p > 0) p else 1)
    val own = dv.outbox.contains(e.id)
    all {
      dv.alive, not(dv.stopped), p > 0, not(e.stub), not(resetRequired(dv, BUG)),
      s' = { ...s,
        devs: s.devs.set(d, { ...dv, applied: p,
          app: if (own) dv.app else dv.app.union(Set(e.id)),
          outbox: dv.outbox.exclude(Set(e.id)) }),
        dups: if (not(own) and dv.app.contains(e.id)) s.dups + 1 else s.dups,
        unreadable: s.unreadable or not(keysOf(s.canon, d).contains(e.epoch)) },
    }
  }

  // [CMP-16] [DLV-12] The app handles ResetRequired: it deletes the synced
  // data, imports the usable snapshot, and applies each outbox row again
  // unless `is_covered` holds for it ([CMP-14]).
  action reset(d: Dev): bool = all {
    dev(d).alive, not(dev(d).stopped), resetRequired(dev(d), BUG),
    resetWith(d, usable(dev(d).log, BUG)),
  }
  action resetWith(d: Dev, u: int): bool = {
    val dv = dev(d)
    val snap = at(dv.log, if (u > 0) u else 1)
    val covered = dv.outbox.intersect(coveredIdsWith(dv.log, u))
    val kept = if (BUG == "resetKeepsCovered") dv.outbox else dv.outbox.exclude(covered)
    val base = if (u > 0) snap.content else Set()
    s' = { ...s,
      devs: s.devs.set(d, { ...dv,
        applied: if (u > 0) snap.statePos else 0,
        app: if (BUG == "resetDropsOutbox") base else base.union(kept),
        // A reset before the fetch reaches the head can need a second reset.
        outbox: kept, fresh: dv.log.length() < s.relay.length() }),
      needless: s.needless or not(dv.fresh),
      unreadable: s.unreadable or (u > 0 and not(keysOf(s.canon, d).contains(snap.epoch))),
      events: s.events.union(Set(EvReset)).union(if (u > 0) Set(EvResetImport) else Set())
        .union(if (covered != Set()) Set(EvCoveredDropped) else Set())
        .union(if (u > 0 and LATE.contains(d)) Set(EvNewDeviceImport) else Set()) }
  }

  // [CMP-3] The app writes a snapshot of its state at the applied position,
  // only with an empty outbox. [CMP-18] Snapshots and accept records can use
  // the reserve above the quota.
  action writeSnapshot(d: Dev, readable: bool): bool = {
    val dv = dev(d)
    val e = { ...blank, kind: Snap, author: d, epoch: currentEpoch(s.relay), statePos: dv.applied,
              content: dv.app, readable: readable, size: SNAP_SIZE }
    val limit = if (BUG == "snapshotNoReserve") QUOTA else QUOTA + RESERVE
    val afterRemoval = positions(s.relay).exists(p => at(s.relay, p).kind == Rem)
    all {
      active(d), not(s.hold), not(dv.stopped), dv.applied >= 1,
      dv.outbox == Set() or BUG == "snapshotWithOutbox",
      readable or FAULTS.contains("unreadable"),
      used(s.relay, BUG) + SNAP_SIZE <= limit,
      appendRecord(e, s.events.union(Set(EvSnapshot))
        .union(if (not(readable)) Set(EvUnreadableSnapshot) else Set())
        .union(if (used(s.relay, BUG) + SNAP_SIZE > QUOTA) Set(EvSnapshotAtFull) else Set())
        .union(if (afterRemoval) Set(EvCompactAfterRemoval) else Set())),
    }
  }

  // [CMP-5] A device that applied past the state position, decrypts the
  // snapshot and gets true from `can_import` appends an accept record.
  action accept(d: Dev, p: int): bool = {
    val dv = dev(d)
    val e = at(dv.log, if (p >= 1 and p <= dv.log.length()) p else 1)
    val limit = if (BUG == "snapshotNoReserve") QUOTA else QUOTA + RESERVE
    val a = { ...blank, kind: Acc, author: d, snapPos: p, applied: dv.applied, size: ACC_SIZE }
    all {
      active(d), not(s.hold), not(dv.stopped), p >= 1, p <= dv.log.length(),
      e.kind == Snap, valid(dv.log, p, BUG),
      e.readable or BUG == "acceptUnreadable",
      keysOf(s.canon, d).contains(e.epoch),
      dv.applied >= e.statePos or BUG == "acceptEarly",
      not(positions(s.canon).exists(r => at(s.canon, r).kind == Acc and at(s.canon, r).author == d
                                       and at(s.canon, r).snapPos == p)),
      used(s.relay, BUG) + ACC_SIZE <= limit,
      appendRecord(a, ev(EvAccept)),
    }
  }

  // [CMP-12] The relay replaces each covered record with a stub after the
  // usable snapshot is accepted.
  action relayCompact: bool = all { not(s.hold), relayCompactWith(compact(s.relay, BUG)) }
  action relayCompactWith(log2: List[Entry]): bool = {
    val unreadableFull = positions(s.relay).exists(p =>
      at(s.relay, p).kind == Snap and not(at(s.relay, p).readable) and not(log2.nth(p - 1).stub))
    all {
      log2 != s.relay,
      s' = { ...s, relay: log2,
        events: s.events.union(Set(EvRelayCompact))
          .union(if (unreadableFull) Set(EvUnreadableKeptFull) else Set()) },
    }
  }

  // [CMP-13] Each engine replaces its own copies of covered records with
  // stubs after the app applies past the frontier and the engine accepts the
  // usable snapshot.
  action deviceCompact(d: Dev): bool = all {
    dev(d).alive, not(dev(d).stopped), deviceCompactWith(d, usable(dev(d).log, BUG)),
  }
  action deviceCompactWith(d: Dev, u: int): bool = {
    val dv = dev(d)
    all {
      u > 0,
      dv.applied >= at(dv.log, u).statePos,
      acceptedBy(dv.log, u, dv.log.length(), d),
      deviceCompactLog(d, compactWith(dv.log, u, BUG)),
    }
  }
  action deviceCompactLog(d: Dev, log2: List[Entry]): bool = all {
    log2 != dev(d).log,
    s' = { ...s, devs: s.devs.set(d, { ...dev(d), log: log2 }), events: ev(EvDeviceCompact) },
  }

  // A grant adds device 3 or 4: a new device from a trusted device, or a
  // full recovery with the recovery key (S5). [CMP-20] It seals the keys
  // that the full records still need. The device starts with a new state
  // file.
  action grant(x: Dev): bool = {
    val e = { ...blank, kind: Grant, dev: x, sealed: sealFor(s.relay, BUG) }
    val wasAccepted = usable(s.relay, BUG) > 0
    all {
      not(s.hold), LATE.contains(x), not(everActive(s.relay).contains(x)),
      DEVS.exists(d => active(d)) or FAULTS.contains("destroy"),
      s.relay.length() < MAX_LEN,
      s' = { ...s, canon: s.canon.append(withCache(s.canon, e, BUG)), relay: s.relay.append(withCache(s.canon, e, BUG)),
        // The app keeps its local edits as outbox rows.
        devs: s.devs.set(x, { ...dev(x), log: List(genesis), applied: 0, fresh: true }),
        events: s.events.union(Set(EvGrant)).union(if (wasAccepted) Set(EvAcceptedAfterGrant) else Set()) },
    }
  }

  // [CMP-7] [CMP-9] A removal makes the device inactive, so it stops its
  // block of compaction. The new key goes to each device that stays.
  action remove(d: Dev, x: Dev): bool = all {
    active(d), d != x, activeAfter(s.relay, s.relay.length()).contains(x), not(s.hold),
    appendRecord({ ...blank, kind: Rem, dev: x }, ev(EvRemove)),
  }

  // S5: a fire destroys a device. Its unsent edits are lost.
  action destroy(d: Dev): bool = all {
    FAULTS.contains("destroy"), INIT.contains(d), dev(d).alive,
    s' = { ...s, devs: s.devs.set(d, { ...dev(d), alive: false }), lost: s.lost.union(dev(d).outbox),
           events: ev(EvDestroy) },
  }

  action backupApp(d: Dev): bool = all {
    FAULTS.contains("appRestore"), dev(d).alive,
    s' = { ...s, devs: s.devs.set(d, { ...dev(d),
      backup: { app: dev(d).app, outbox: dev(d).outbox, applied: dev(d).applied } }) },
  }

  // [DLV-11] The app DB goes back to its backup. The rows of the backup stay.
  action restoreApp(d: Dev): bool = {
    val b = dev(d).backup
    all {
      FAULTS.contains("appRestore"), dev(d).alive,
      s' = { ...s, devs: s.devs.set(d, { ...dev(d), app: b.app, outbox: b.outbox, applied: b.applied,
                                                      fresh: true }),
             lost: s.lost.union(dev(d).outbox.exclude(b.outbox)),
             events: ev(EvAppRestore) },
    }
  }

  // T14: the engine state file is lost. The keys stay in the key store.
  action loseEngine(d: Dev): bool = all {
    FAULTS.contains("engineLoss"), dev(d).alive,
    s' = { ...s, devs: s.devs.set(d, { ...dev(d), log: List(genesis), fresh: true }),
           events: ev(EvEngineLoss) },
  }

  // S6: the relay goes back to an earlier state of its log. The records of
  // that earlier state that the stubs of the prefix do not cover were still
  // in full then. The space goes on hold until a repair.
  action rollback(k: int): bool = {
    val earlier = restoreFull(firstN(s.relay, k), usable(firstN(s.relay, k), BUG), s.canon)
    all {
      FAULTS.contains("rollback"), not(s.hold), k >= 1, k < s.relay.length(),
      DEVS.exists(d => dev(d).alive and dev(d).log.length() == s.canon.length()),
      s' = { ...s, relay: earlier, hold: true, events: ev(EvRollback) },
    }
  }

  // [LOG-10] [LOG-11] [CMP-17] A repair: the device uploads its entries after
  // the relay head, with its own stubs. The relay moves them only if the
  // usable snapshot of the staged range covers each staged stub.
  // FAULTS "badRepair": a faulty device makes one more full change a stub.
  action repair(d: Dev, bad: int): bool = {
    val dv = dev(d)
    val n = s.relay.length()
    val staged = dropN(dv.log, n)
    val badOk = if (bad > n and bad <= dv.log.length()) at(dv.log, bad).kind == Chg and not(at(dv.log, bad).stub) else false
    val faulty = if (badOk)
      staged.foldl(List(), (out, e) => out.append(if (n + out.length() + 1 == bad) { ...e, stub: true } else e))
      else staged
    all {
      s.hold, dv.alive, dv.log.length() > n, activeAfter(dv.log, dv.log.length()).contains(d),
      bad == 0 or (badOk and FAULTS.contains("badRepair")),
      repairWith(n, s.relay.concat(faulty)),
    }
  }
  action repairWith(n: int, log2: List[Entry]): bool = {
    val stagedStubs = between(n + 1, log2.length()).filter(p => at(log2, p).stub)
    val ok = stubsValidWith(log2, usable(log2, "none")) or BUG == "repairNoCoverCheck"
    if (ok) s' = { ...s, relay: log2, hold: log2.length() < s.canon.length(),
                   events: s.events.union(if (stagedStubs != Set()) Set(EvRepairStubs) else Set()) }
    else s' = { ...s, events: ev(EvBadRepairRefused) }
  }

  action step: bool = any {
    { nondet d = DEVS.oneOf() edit(d) },
    { nondet d = DEVS.oneOf() nondet id = 1.to(MAX_IDS).oneOf() push(d, id) },
    { nondet d = DEVS.oneOf() fetch(d) },
    { nondet d = DEVS.oneOf() pull(d) },
    { nondet d = DEVS.oneOf() reset(d) },
    { nondet d = DEVS.oneOf() nondet readable = Set(true, false).oneOf() writeSnapshot(d, readable) },
    { nondet d = DEVS.oneOf() nondet p = 1.to(MAX_LEN).oneOf() accept(d, p) },
    relayCompact,
    { nondet d = DEVS.oneOf() deviceCompact(d) },
    { nondet x = LATE.oneOf() grant(x) },
    { nondet d = DEVS.oneOf() nondet x = DEVS.oneOf() remove(d, x) },
    { nondet d = DEVS.oneOf() destroy(d) },
    { nondet d = DEVS.oneOf() backupApp(d) },
    { nondet d = DEVS.oneOf() restoreApp(d) },
    { nondet d = DEVS.oneOf() loseEngine(d) },
    { nondet k = 1.to(MAX_LEN).oneOf() rollback(k) },
    { nondet d = DEVS.oneOf() nondet bad = 0.to(MAX_LEN).oneOf() repair(d, bad) },
  }

  // ---- Invariants ----

  def liveDevs: Set[Dev] = DEVS.filter(d => dev(d).alive and not(dev(d).stopped))

  // [MRG-1] [DLV-12] The app state of each device is the changes up to its
  // applied position and its own outbox rows. A snapshot import keeps this.
  val appConsistent: bool = liveDevs.forall(d =>
    dev(d).app == changesUpTo(s.canon, dev(d).applied).union(dev(d).outbox))
  // [MRG-1] Each device applies each change once.
  val noDoubleApply: bool = s.dups == 0
  // [DLV-11] An outbox row stays only until its change comes back.
  val outboxPending: bool = liveDevs.forall(d =>
    dev(d).outbox.forall(id => not(changesUpTo(s.canon, dev(d).applied).contains(id))))
  // [CMP-15] Each stub on the relay and on each device passes the stub check,
  // so no engine stops with `missing records`.
  // The invariants compute the usable snapshot in full with the design
  // rules, not from the cache, which a BUG value changes.
  pure def stubsOk(log: List[Entry]): bool = stubsValidWith(log, usableFull(log, "none"))
  val stubsCovered: bool = stubsOk(s.relay) and DEVS.forall(d => stubsOk(dev(d).log))
  val noMissingRecords: bool = DEVS.forall(d => not(dev(d).stopped))
  // [CMP-20] Security records and accept records never become stubs.
  val securityFull: bool = s.relay.concat(DEVS.fold(List(), (l, d) => l.concat(dev(d).log)))
    .foldl(true, (ok, e) => ok and not(e.stub and (isSecurity(e) or e.kind == Acc)))
  // [CMP-5] The usable snapshot decrypts.
  val usableReadable: bool = {
    val u = usableFull(s.relay, "none")
    u == 0 or at(s.relay, u).readable
  }
  // [CMP-20] Each active device holds the key of each record that the
  // usable snapshot does not cover, so it can import and pull.
  pure def allRead(need: Set[int], held: Dev -> Set[int], act: Set[Dev]): bool =
    act.forall(d => need.subseteq(held.get(d)))
  val readsNeeded: bool = not(s.unreadable) and
    allRead(neededWith(s.relay, usableFull(s.relay, "none"), "none"), DEVS.mapBy(d => keysOf(s.canon, d)), DEVS.filter(d => active(d)))
  // [CMP-12] [CMP-13] A device with no lost state never needs a reset.
  val noNeedlessReset: bool = not(s.needless)
  // A change is in the log or in an outbox, unless an app DB restore or a
  // fire destroyed it before the push (S5, [DLV-11]).
  val noLostChange: bool = s.made.exclude(s.lost).forall(id =>
    holdsId(s.canon, id) or DEVS.exists(d => dev(d).outbox.contains(id)))
  // [CMP-16] A device never waits on a change stub that it cannot reset past.
  val noStuckDevice: bool = liveDevs.forall(d => {
    val n = nextChange(dev(d).log, dev(d).applied)
    (n > 0 and at(dev(d).log, n).stub) implies resetRequired(dev(d), BUG)
  })
  // [CMP-18] The relay stores within the quota and the reserve.
  val withinQuota: bool = used(s.relay, "none") <= QUOTA + RESERVE

  // ---- Witnesses ----
  val wRelayCompact: bool = s.events.contains(EvRelayCompact)
  val wDeviceCompact: bool = s.events.contains(EvDeviceCompact)
  val wResetImport: bool = s.events.contains(EvResetImport)
  val wCoveredDropped: bool = s.events.contains(EvCoveredDropped)
  val wNewDeviceImport: bool = s.events.contains(EvNewDeviceImport)
  val wCompactAfterRemoval: bool = s.events.contains(EvCompactAfterRemoval) and s.events.contains(EvRelayCompact)
  val wRepairStubs: bool = s.events.contains(EvRepairStubs)
  val wBadRepairRefused: bool = s.events.contains(EvBadRepairRefused)
  val wUnreadableKeptFull: bool = s.events.contains(EvUnreadableKeptFull)
  val wSnapshotAtFull: bool = s.events.contains(EvSnapshotAtFull)
  val wAcceptedAfterGrant: bool = s.events.contains(EvAcceptedAfterGrant)
}
