// Model of the fork repair procedure: DESIGN.md "Fork repair" ([FRK-1] to
// [FRK-8]), its limit after compaction ([CMP-21]), and the space deletion
// marker ([LOG-13]). specs/forkrepair/README.md has the coverage map.
//
// Abstractions:
//  - One space, two or three devices (DEVS). Every device is active from the genesis
//    record. Grants, epochs and keys are outside this model.
//  - A log entry is a change or a snapshot, with a unique int `cid` that
//    stands for its entry hash. Prefix equality of cids stands for digest
//    equality. A stub keeps its cid ([CMP-1]).
//  - A change carries a content int. A new change has the content of its own
//    cid. A re-sent change keeps its cid, so its content is the same. The app
//    state is a set of contents (the merge contract).
//  - The relay can fork once: it copies its log to a second branch and shows
//    each device one branch. A device that the relay moves to the other
//    branch finds a conflict at its next fetch ([FRK-1]).
//  - The export file is the verified log of the source device at the export
//    ([FRK-3]). The import puts it on the relay as the only branch ([FRK-5]).
//  - A snapshot holds the app state of its author. Acceptance is outside this
//    model (specs/compaction): a device can replace the changes before the
//    last snapshot of its log with stubs after its app applied the log
//    ([CMP-13]).
//  - Each app DB transaction and each engine transaction is one atomic
//    action. A crash between actions is a long pause, so the free
//    interleaving of actions models a crash at each step. The old state file
//    stays until the app deletes it, so a recovery can run twice.
//
// The const BUG selects one deliberate violation of the design. "none" is the
// design. checks.toml binds the consts for each config and each mutant.
module forkrepair {
  type Dev = int
  type Entry = { cid: int, author: Dev, content: int, snap: bool, state: Set[int], stub: bool }
  type Stop = Running | Forked | Deleted

  type Device = {
    appState: Set[int],      // the contents in the app state
    counts: int -> int,      // ghost: applications of each content since the last reset
    appOutbox: Set[int],     // app outbox rows, by cid
    appliedLog: List[int],   // applied position: the cids of the log prefix that the app handled
    outbox: Set[int],        // engine outbox, by cid
    log: List[Entry],        // verified log
    stop: Stop,
    old: List[Entry],        // the verified log of the old state file ([FRK-6])
    oldOutbox: Set[int],     // the engine outbox of the old state file
    hasOld: bool,
    recovered: bool,         // the app ran the recovery of the old state file
    reenrolled: bool,
  }

  type Event = EvFork | EvForkFound | EvDeletedSeen | EvImported | EvReenrolled | EvRecovered
               | EvResentStored | EvStubLost | EvRepairAfterImport | EvReset

  type State = {
    devs: Dev -> Device,
    relay: List[List[Entry]], // branch 0 and branch 1
    view: Dev -> int,         // the branch that the relay shows each device
    forked: bool,
    deleted: bool,            // the deletion marker ([LOG-13])
    source: Dev,              // 0 until the user selects the source ([FRK-2])
    exported: List[Entry],    // the export file ([FRK-3])
    imported: bool,
    afterDelete: bool,        // ghost: the relay deleted the space once
    contentOf: int -> int,    // ghost: the content of each change cid
    authorOf: int -> Dev,     // ghost: the author of each change content
    made: Set[int],           // ghost: each content that an app wrote
    nextId: int,
    events: Set[Event],
  }

  const DEVS: Set[Dev]           // the devices, from 1
  const MAX_IDS: int
  const SNAPSHOTS: bool
  const BUG: str
  pure val BUGS: Set[str] = Set(
    "none",
    "skipOld",           // [FRK-7] the engine gives the app no change of the old state file
    "freshIds",          // [FRK-8] the app sends each recovered change with a new change ID
    "noReset",           // [FRK-8] the app does not handle ResetRequired after the recovery
    "uploadAfterDelete", // [LOG-13] a device that sees the deletion marker uploads its log again
  )

  pure def cids(log: List[Entry]): List[int] = log.foldl(List(), (xs, e) => xs.append(e.cid))
  pure def isPrefix(a: List[int], b: List[int]): bool =
    a.length() <= b.length() and a.indices().forall(i => a[i] == b[i])
  pure def holdsCid(log: List[Entry], c: int): bool = log.indices().exists(i => log[i].cid == c)
  pure def holdsFull(log: List[Entry], content: int): bool =
    log.indices().exists(i => not(log[i].snap) and not(log[i].stub) and log[i].content == content)
  // The index of the last snapshot of a log, or -1.
  pure def inSnapshot(log: List[Entry], content: int): bool =
    log.indices().exists(i => log[i].snap and log[i].state.contains(content))
  pure def lastSnap(log: List[Entry]): int =
    log.indices().fold(-1, (m, i) => if (log[i].snap and i > m) i else m)
  pure def bump(m: int -> int, k: int): int -> int = m.put(k, if (m.keys().contains(k)) m.get(k) + 1 else 1)

  var s: State
  def dev(d: Dev): Device = s.devs.get(d)
  def branch(d: Dev): List[Entry] = s.relay[s.view.get(d)]
  def contentsOf(ids: Set[int]): Set[int] = ids.map(c => s.contentOf.get(c))

  pure val emptyDevice: Device = {
    appState: Set(), counts: Map(), appOutbox: Set(), appliedLog: List(), outbox: Set(), log: List(),
    stop: Running, old: List(), oldOutbox: Set(), hasOld: false, recovered: false, reenrolled: false,
  }

  action init: bool = s' = {
    devs: DEVS.mapBy(_ => emptyDevice),
    relay: List(List(), List()), view: DEVS.mapBy(_ => 0), forked: false, deleted: false,
    source: 0, exported: List(), imported: false, afterDelete: false,
    contentOf: Map(), authorOf: Map(), made: Set(), nextId: 1, events: Set(),
  }

  action setDev(d: Dev, x: Device, ev: Set[Event]): bool =
    s' = { ...s, devs: s.devs.set(d, x), events: s.events.union(ev) }

  // [DLV-2] The app applies an edit and writes its outbox row in one
  // transaction, then calls enqueue_many. The app works offline, also while
  // the engine is stopped.
  action edit(d: Dev): bool = {
    val x = dev(d)
    val c = s.nextId
    all {
      c <= MAX_IDS,
      s' = { ...s,
        devs: s.devs.set(d, { ...x, appState: x.appState.union(Set(c)), counts: bump(x.counts, c),
          appOutbox: x.appOutbox.union(Set(c)), outbox: x.outbox.union(Set(c)) }),
        contentOf: s.contentOf.put(c, c), authorOf: s.authorOf.put(c, d),
        made: s.made.union(Set(c)), nextId: c + 1 },
    }
  }

  // The engine appends one outbox change to the branch that the relay shows
  // it. The relay answers a known change ID as stored ([DLV-5]).
  action push(d: Dev, c: int): bool = {
    val x = dev(d)
    val v = s.view.get(d)
    val b = s.relay[v]
    val e = { cid: c, author: d, content: s.contentOf.get(c), snap: false, state: Set(), stub: false }
    all {
      x.stop == Running, not(s.deleted), x.outbox.contains(c),
      isPrefix(cids(x.log), cids(b)),
      s' = { ...s,
        relay: if (holdsCid(b, c)) s.relay else s.relay.replaceAt(v, b.append(e)),
        events: s.events.union(
          if (x.reenrolled and not(holdsCid(b, c)) and holdsCid(x.old, c)) Set(EvResentStored) else Set()) },
    }
  }

  // A snapshot: the author applied its whole log and both outboxes are empty
  // (PROTOCOL.md 14.7).
  action snapshot(d: Dev): bool = {
    val x = dev(d)
    val v = s.view.get(d)
    val b = s.relay[v]
    val e = { cid: s.nextId, author: d, content: 0, snap: true, state: x.appState, stub: false }
    all {
      SNAPSHOTS, x.stop == Running, not(s.deleted), s.nextId <= MAX_IDS,
      cids(x.log) == cids(b), x.appliedLog == cids(x.log),
      x.outbox == Set(), x.appOutbox == Set(),
      s' = { ...s, relay: s.relay.replaceAt(v, b.append(e)), nextId: s.nextId + 1 },
    }
  }

  // [CMP-13] After its app applied the log, the engine replaces each change
  // before the last snapshot with a stub.
  action compact(d: Dev): bool = {
    val x = dev(d)
    val k = lastSnap(x.log)
    all {
      SNAPSHOTS, k > 0, x.appliedLog == cids(x.log),
      x.log.indices().exists(i => i < k and not(x.log[i].snap) and not(x.log[i].stub)),
      setDev(d, { ...x, log: range(0, x.log.length()).foldl(List(), (l, i) =>
        l.append(if (i < k and not(x.log[i].snap)) { ...x.log[i], stub: true } else x.log[i])) }, Set()),
    }
  }

  // A fetch to the relay head. An extension of the verified log adds the
  // entries, and each own change in the log leaves the engine outbox
  // ([DLV-8]). A relay log that ends before the verified head gets a repair
  // ([LOG-10]). Each other relay log is a conflict: `stopped: fork`
  // ([FRK-1]). A deletion marker gives `stopped: deleted` ([LOG-13]).
  action fetch(d: Dev): bool = {
    val x = dev(d)
    val v = s.view.get(d)
    val b = s.relay[v]
    all {
      x.stop != Forked,
      if (s.deleted) {
        if (BUG == "uploadAfterDelete" and x.log.length() > 0)
          s' = { ...s, deleted: false, relay: List(x.log, x.log), view: DEVS.mapBy(_ => 0),
            devs: s.devs.set(d, { ...x, stop: Running }) }
        else setDev(d, { ...x, stop: Deleted }, Set(EvDeletedSeen))
      } else if (isPrefix(cids(x.log), cids(b))) {
        val log2 = x.log.concat(b.slice(x.log.length(), b.length()))
        setDev(d, { ...x, log: log2, stop: Running,
          outbox: x.outbox.filter(c => not(holdsCid(log2, c))) }, Set())
      } else if (isPrefix(cids(b), cids(x.log))) {
        all {
          x.stop == Running,
          s' = { ...s, relay: s.relay.replaceAt(v, x.log),
            events: s.events.union(if (s.imported) Set(EvRepairAfterImport) else Set()) },
        }
      } else setDev(d, { ...x, stop: Forked }, Set(EvForkFound)),
    }
  }

  // changes_after and the app loop ([DLV-10], [DLV-11]). An applied position
  // that the verified log does not hold, or a stub after it, gives
  // ResetRequired ([DLV-12], [CMP-16]): no pull.
  action pull(d: Dev): bool = {
    val x = dev(d)
    val n = x.appliedLog.length()
    if (isPrefix(x.appliedLog, cids(x.log)) and n < x.log.length() and not(x.log[n].stub)) {
      val e = x.log[n]
      if (e.snap) setDev(d, { ...x, appliedLog: x.appliedLog.append(e.cid) }, Set())
      else if (x.appOutbox.contains(e.cid))
        setDev(d, { ...x, appliedLog: x.appliedLog.append(e.cid), appOutbox: x.appOutbox.exclude(Set(e.cid)) }, Set())
      else
        setDev(d, { ...x, appliedLog: x.appliedLog.append(e.cid), appState: x.appState.union(Set(e.content)),
          counts: bump(x.counts, e.content) }, Set())
    } else all { false, s' = s }
  }

  def needsReset(x: Device): bool =
    not(isPrefix(x.appliedLog, cids(x.log)))
    or (x.appliedLog.length() < x.log.length() and x.log[x.appliedLog.length()].stub)

  // [DLV-12] [CMP-16] The app deletes its synced data, imports the last
  // snapshot of the log, drops the outbox rows that the snapshot covers,
  // applies each other outbox row again, and pulls from there.
  action reset(d: Dev): bool = {
    val x = dev(d)
    val k = lastSnap(x.log)
    val covered = if (k < 0) Set() else x.appOutbox.filter(c => x.log.indices().exists(i => i < k and x.log[i].cid == c))
    val rows = x.appOutbox.exclude(covered)
    val base = if (k < 0) Set() else x.log[k].state
    val contents = contentsOf(rows)
    all {
      needsReset(x),
      if (BUG == "noReset")
        setDev(d, { ...x, appliedLog: if (k < 0) List() else cids(x.log.slice(0, k + 1)) }, Set(EvReset))
      else
        setDev(d, { ...x, appState: base.union(contents), appOutbox: rows,
          counts: base.union(contents).mapBy(_ => 1),
          appliedLog: if (k < 0) List() else cids(x.log.slice(0, k + 1)) }, Set(EvReset)),
    }
  }

  // The relay forks: branch 1 starts as a copy of branch 0.
  action fork: bool = all {
    not(s.forked), not(s.deleted), s.source == 0, s.relay[0].length() > 0,
    s' = { ...s, forked: true, relay: List(s.relay[0], s.relay[0]), events: s.events.union(Set(EvFork)) },
  }

  // The forked relay shows device d the other branch.
  action show(d: Dev): bool = all {
    s.forked, not(s.imported), not(s.deleted),
    s' = { ...s, view: s.view.set(d, 1 - s.view.get(d)) },
  }

  // [FRK-2] [FRK-3] After a device stopped with `fork`, the user selects one
  // device as the source, and the source device exports its log.
  action exportLog(src: Dev): bool = all {
    s.source == 0, DEVS.exists(d => dev(d).stop == Forked),
    s' = { ...s, source: src, exported: dev(src).log },
  }

  // [FRK-4] [LOG-13] The user deletes the space. The relay keeps the
  // deletion marker.
  action delete: bool = all {
    s.source != 0, not(s.deleted), not(s.imported),
    s' = { ...s, deleted: true, afterDelete: true, relay: List(List(), List()) },
  }

  // [FRK-5] The source imports the export file. The import removes the
  // deletion marker. The relay serves one log again.
  action importLog: bool = all {
    s.deleted,
    s' = { ...s, deleted: false, imported: true, relay: List(s.exported, s.exported),
      view: DEVS.mapBy(_ => 0), devs: s.devs.set(s.source, { ...dev(s.source), stop: Running }),
      events: s.events.union(Set(EvImported)) },
  }

  // [FRK-6] Another device enrolls again from the source, with a new engine
  // state file. The old file stays aside. The new verified log is the relay
  // log at the checkpoint. At startup the app calls enqueue_many with its
  // outbox rows ([DLV-2]), and the engine skips each change that its verified
  // log holds ([DLV-5]).
  action reenroll(d: Dev): bool = {
    val x = dev(d)
    val b = s.relay[0]
    all {
      s.imported, d != s.source, not(x.reenrolled),
      cids(dev(s.source).log) == cids(b),
      setDev(d, { ...x, old: x.log, oldOutbox: x.outbox, hasOld: true, reenrolled: true, stop: Running,
        log: b, outbox: x.appOutbox.filter(c => not(holdsCid(b, c))) }, Set(EvReenrolled)),
    }
  }

  // [FRK-7] The engine gives the app each own change that the new log does
  // not hold and that the old verified log holds in full. It reads no old
  // outbox: the app outbox row of each change stays until the change comes
  // back from changes_after ([DLV-11]), so the app outbox holds it. [FRK-8] The app
  // writes an outbox row for each one with its old change ID and calls
  // enqueue_many. The app keys its outbox rows by change ID, so a second
  // run after a crash adds nothing.
  action recover(d: Dev): bool = {
    val x = dev(d)
    val own = x.old.indices().filter(i => x.old[i].author == d and not(x.old[i].snap) and not(x.old[i].stub))
      .map(i => x.old[i].cid)
    val found = if (BUG == "skipOld") Set() else own.filter(c => not(holdsCid(x.log, c)))
    val stubbed = x.old.indices().exists(i => x.old[i].author == d and x.old[i].stub and not(holdsCid(x.log, x.old[i].cid)))
    all {
      x.hasOld,
      if (BUG == "freshIds") {
        val n = found.size()
        val fresh = s.nextId.to(s.nextId + n - 1)
        val pairs = found.fold(List(), (l, c) => l.append(c))
        all {
          n > 0, s.nextId + n <= MAX_IDS + 4,
          s' = { ...s,
            devs: s.devs.set(d, { ...x, appOutbox: x.appOutbox.union(fresh), outbox: x.outbox.union(fresh), recovered: true }),
            contentOf: pairs.indices().fold(s.contentOf, (m, i) => m.put(s.nextId + i, s.contentOf.get(pairs[i]))),
            nextId: s.nextId + n,
            events: s.events.union(Set(EvRecovered)) },
        }
      } else
        setDev(d, { ...x, appOutbox: x.appOutbox.union(found), recovered: true,
          outbox: x.outbox.union(found.filter(c => not(holdsCid(x.log, c)))) },
          (if (found != Set()) Set(EvRecovered) else Set()).union(if (stubbed) Set(EvStubLost) else Set())),
    }
  }

  // The app deletes the old state file only after the recovery.
  action dropOld(d: Dev): bool = {
    val x = dev(d)
    all { x.hasOld, x.recovered, setDev(d, { ...x, hasOld: false, old: List(), oldOutbox: Set() }, Set()) }
  }

  action step: bool = any {
    { nondet d = DEVS.oneOf() edit(d) },
    { nondet d = DEVS.oneOf() nondet c = dev(d).outbox.oneOf() all { dev(d).outbox != Set(), push(d, c) } },
    { nondet d = DEVS.oneOf() fetch(d) },
    { nondet d = DEVS.oneOf() pull(d) },
    { nondet d = DEVS.oneOf() reset(d) },
    { nondet d = DEVS.oneOf() snapshot(d) },
    { nondet d = DEVS.oneOf() compact(d) },
    fork,
    { nondet d = DEVS.oneOf() show(d) },
    { nondet d = DEVS.oneOf() exportLog(d) },
    delete,
    importLog,
    { nondet d = DEVS.oneOf() reenroll(d) },
    { nondet d = DEVS.oneOf() recover(d) },
    { nondet d = DEVS.oneOf() dropOld(d) },
  }

  // A content is held if a relay branch, a device log in full, an outbox, or
  // the old state file of its author holds it. A copy in the old state file
  // of another device does not count: FRK-7 gives the app own changes only.
  def held(content: int): bool = {
    val a = s.authorOf.get(content)
    or {
      holdsFull(s.relay[0], content), holdsFull(s.relay[1], content),
      inSnapshot(s.relay[0], content), inSnapshot(s.relay[1], content),
      DEVS.exists(d => holdsFull(dev(d).log, content) or inSnapshot(dev(d).log, content)),
      DEVS.exists(d => contentsOf(dev(d).appOutbox).contains(content) or contentsOf(dev(d).outbox).contains(content)),
      dev(a).hasOld and (holdsFull(dev(a).old, content) or contentsOf(dev(a).oldOutbox).contains(content)),
    }
  }

  // [FRK-7] [FRK-8] [CMP-21] No change that an app wrote is lost: some log,
  // outbox or the old state file of its author holds it.
  val noLostChange: bool = s.made.forall(c => held(c))
  // [MRG-1] [FRK-8] No device applies a content twice since its last reset.
  val noDoubleApply: bool = DEVS.forall(d => dev(d).counts.keys().forall(k => dev(d).counts.get(k) <= 1))
  // [LOG-13] [FRK-5] After a deletion, only the import of the export file
  // makes the space exist again, and the relay log extends the export.
  val noResurrect: bool = not(s.afterDelete) or s.deleted or
    (s.imported and isPrefix(cids(s.exported), cids(s.relay[0])))

  val wFork: bool = s.events.contains(EvForkFound)
  val wDeletedSeen: bool = s.events.contains(EvDeletedSeen)
  val wImported: bool = s.events.contains(EvImported)
  val wReenrolled: bool = s.events.contains(EvReenrolled)
  val wRecovered: bool = s.events.contains(EvRecovered)
  val wReset: bool = s.events.contains(EvReset)
  val wRepairAfterImport: bool = s.events.contains(EvRepairAfterImport)
  // Every device runs on the imported log, has applied it, and has an empty
  // outbox. The app states are equal.
  val converged: bool = s.imported and s.events.contains(EvRecovered) and DEVS.forall(d =>
    dev(d).stop == Running and dev(d).outbox == Set() and dev(d).appOutbox == Set()
    and cids(dev(d).log) == cids(s.relay[0]) and dev(d).appliedLog == cids(dev(d).log)
    and dev(d).appState == dev(1).appState)
}
