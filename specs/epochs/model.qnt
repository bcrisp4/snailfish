// Epoch retries and relay recovery. Signatures and the initial enrolled prefix
// are trusted abstractions. This model checks shared log transitions, not bytes.
module epochs {
  type Dev = int
  type Kind = Trusted | Change | Rotation
  type Verdict = Stored | Known | Held | OldEpoch | BadAuthor | BadBase
  type Event = Enqueued | Rotated | RotatedHeld | Fetched | Restored | Repaired
    | SecurityRepaired | Released | KnownOld | StaleRefused | Reencrypted | ReencryptedStored | Conflict | HoldRefused
  type Record = { id: int, cid: int, kind: Kind, author: Dev, epoch: int, base: List[int], target: Dev }
  type Client = { log: List[Record], pending: bool, envelope: Record, stale: bool, stopped: bool }
  type State = {
    relay: List[Record], hold: bool, clients: Dev -> Client,
    nextId: int, made: Set[Dev], rotated: bool, restores: int,
    knownRefused: bool, incompleteRepair: bool, heldAppend: bool,
    reencoded: Set[int], events: Set[Event],
  }

  const MAX_RECORDS: int
  const MAX_RESTORES: int
  const BUG: str
  pure val BUGS: Set[str] = Set(
    "none", "epochBeforeDedupe", "repairDropsRotation", "ignoreRemoval", "ignoreEpoch", "ignoreHold",
  )
  pure val DEVS: Set[Dev] = Set(1, 2)
  pure val root: Record = { id: 0, cid: 0, kind: Trusted, author: 0, epoch: 1, base: List(), target: 0 }
  pure val initialLog: List[Record] = List(root)
  pure def ids(log: List[Record]): List[int] = log.foldl(List(), (xs, r) => xs.append(r.id))
  pure def prefix(a: List[Record], b: List[Record]): bool =
    a.length() <= b.length() and a == b.slice(0, a.length())
  pure def epoch(log: List[Record]): int = 1 + log.select(r => r.kind == Rotation).length()
  pure def active(log: List[Record]): Set[Dev] =
    log.foldl(DEVS, (ds, r) => if (r.kind == Rotation) ds.exclude(Set(r.target)) else ds)
  pure def hasChange(log: List[Record], cid: int): bool = log.indices().exists(i => {
    val r = log.nth(i)
    r.kind == Change and r.cid == cid
  })
  pure def baseFits(r: Record, log: List[Record]): bool =
    r.base.length() >= 1 and r.base.length() <= log.length()
      and r.base == ids(log.slice(0, r.base.length()))

  // [DLV-7] A known ID cannot receive an epoch refusal, even for an old envelope.
  // [LOG-14] A hold refuses change requests before the append path.
  pure def verdict(log: List[Record], hold: bool, r: Record): Verdict =
    if (hold and BUG != "ignoreHold") Held
    else if (BUG == "epochBeforeDedupe" and r.epoch < epoch(log)) OldEpoch
    else if (hasChange(log, r.cid)) Known
    else if (not(baseFits(r, log))) BadBase
    else if (BUG != "ignoreRemoval" and not(active(log).contains(r.author))) BadAuthor
    else if (BUG != "ignoreEpoch" and r.epoch != epoch(log)) OldEpoch
    else Stored

  // Independent prefix properties do not call verdict or use a cached space state.
  // [LOG-6] [LOG-8] [LOG-9]
  pure def valid(log: List[Record]): bool = log.indices().forall(i => {
    val r = log.nth(i)
    val before = log.slice(0, i)
    if (i == 0) r == root
    else and {
      r.kind != Trusted,
      baseFits(r, before),
      active(before).contains(r.author),
      if (r.kind == Change)
        r.epoch == epoch(before) and not(hasChange(before, r.cid))
      else r.epoch == epoch(before) + 1 and r.target != r.author and active(before).contains(r.target),
    }
  })

  var s: State
  def client(d: Dev): Client = s.clients.get(d)
  action init: bool = s' = {
    relay: initialLog, hold: false,
    clients: DEVS.mapBy(_ => { log: initialLog, pending: false, envelope: root, stale: false, stopped: false }),
    nextId: 1, made: Set(), rotated: false, restores: 0,
    knownRefused: false, incompleteRepair: false, heldAppend: false,
    reencoded: Set(), events: Set(),
  }

  action enqueue(d: Dev): bool = {
    val c = client(d)
    val r = { id: s.nextId, cid: d, kind: Change, author: d, epoch: epoch(c.log), base: ids(c.log), target: 0 }
    all {
      not(c.stopped), not(c.pending), not(s.made.contains(d)),
      active(c.log).contains(d), s.nextId <= MAX_RECORDS,
      s' = { ...s, nextId: s.nextId + 1, made: s.made.union(Set(d)),
        clients: s.clients.set(d, { ...c, pending: true, envelope: r }), events: s.events.union(Set(Enqueued)) },
    }
  }

  // A compromised device key can sign current public metadata without an app key.
  // The relay must reject a removed author before any payload decryption.
  action signUntrusted: bool = {
    val c = client(2)
    val r = { id: s.nextId, cid: 2, kind: Change, author: 2, epoch: epoch(s.relay), base: ids(s.relay), target: 0 }
    all {
      not(s.made.contains(2)), s.nextId <= MAX_RECORDS,
      s' = { ...s, nextId: s.nextId + 1, made: s.made.union(Set(2)),
        clients: s.clients.set(2, { ...c, pending: true, envelope: r }) },
    }
  }

  // The response can disappear. A successful send never discards the envelope.
  // [DLV-7] [LOG-9] [LOG-14]
  action send(d: Dev, lost: bool): bool = {
    val c = client(d)
    val r = c.envelope
    val v = verdict(s.relay, s.hold, r)
    val ev = if (v == Known and r.epoch < epoch(s.relay)) Set(KnownOld)
      else if (v == OldEpoch) Set(StaleRefused)
      else if (v == Held) Set(HoldRefused)
      else if (v == Stored and s.reencoded.contains(r.id)) Set(ReencryptedStored)
      else Set()
    all {
      not(c.stopped), c.pending,
      s' = { ...s,
        relay: if (v == Stored) s.relay.append(r) else s.relay,
        clients: s.clients.set(d, { ...c, stale: if (lost) c.stale else v == OldEpoch }),
        knownRefused: s.knownRefused or (v == OldEpoch and hasChange(s.relay, r.cid)),
        heldAppend: s.heldAppend or (s.hold and v == Stored),
        events: s.events.union(ev),
      },
    }
  }

  // [DLV-7] A new envelope follows an epoch refusal and a verified newer epoch.
  action reencrypt(d: Dev): bool = {
    val c = client(d)
    val r = { ...c.envelope, id: s.nextId, epoch: epoch(c.log), base: ids(c.log) }
    all {
      not(c.stopped), c.pending, c.stale, active(c.log).contains(d),
      epoch(c.log) > c.envelope.epoch, s.nextId <= MAX_RECORDS,
      s' = { ...s, nextId: s.nextId + 1, reencoded: s.reencoded.union(Set(r.id)),
        clients: s.clients.set(d, { ...c, envelope: r, stale: false }), events: s.events.union(Set(Reencrypted)) },
    }
  }

  // [LOG-7] [LOG-14] One removal is an atomic security append, also during a hold.
  // The signer can base it before changes, but not before another security record.
  action remove(d: Dev, target: Dev): bool = {
    val c = client(d)
    val r = { id: s.nextId, cid: 0, kind: Rotation, author: d, epoch: epoch(c.log) + 1, base: ids(c.log), target: target }
    all {
      not(c.stopped), not(s.rotated), s.nextId <= MAX_RECORDS,
      prefix(c.log, s.relay), epoch(c.log) == epoch(s.relay),
      d != target, active(s.relay).contains(d), active(s.relay).contains(target),
      s' = { ...s, relay: s.relay.append(r), nextId: s.nextId + 1, rotated: true,
        events: s.events.union(Set(Rotated)).union(if (s.hold) Set(RotatedHeld) else Set()) },
    }
  }

  // A shorter matching relay log needs repair, not adoption. A conflict stops sync.
  action fetch(d: Dev): bool = {
    val c = client(d)
    val extends = prefix(c.log, s.relay)
    val conflict = not(extends) and not(prefix(s.relay, c.log))
    all {
      not(c.stopped), (extends and c.log != s.relay) or conflict,
      s' = { ...s, clients: s.clients.set(d, if (conflict) { ...c, stopped: true }
        else { ...c, log: s.relay, pending: c.pending and not(hasChange(s.relay, c.envelope.cid)) }),
        events: s.events.union(Set(if (conflict) Conflict else Fetched)) },
    }
  }

  // [LOG-14] A restored prefix starts a hold. The old verified copies remain.
  action restore(n: int): bool = all {
    s.restores < MAX_RESTORES, 1 <= n, n < s.relay.length(),
    s' = { ...s, relay: s.relay.slice(0, n), hold: true, restores: s.restores + 1,
      events: s.events.union(Set(Restored)) },
  }

  // [LOG-10] Repair must reproduce the full verified suffix, including rotations.
  action repair(d: Dev): bool = {
    val c = client(d)
    val restored = if (BUG == "repairDropsRotation") c.log.select(r => r.kind != Rotation) else c.log
    all {
      not(c.stopped), prefix(s.relay, c.log), s.relay.length() < c.log.length(),
      active(s.relay).contains(d) or active(c.log).contains(d),
      s' = { ...s, relay: restored, incompleteRepair: s.incompleteRepair or restored != c.log,
        events: s.events.union(Set(Repaired)).union(if (c.log.select(r => r.kind == Rotation).length() > 0) Set(SecurityRepaired) else Set()) },
    }
  }

  // [LOG-15] The operator can release early. No global no-fork guarantee follows.
  action release: bool = all {
    s.hold,
    s' = { ...s, hold: false, events: s.events.union(Set(Released)) },
  }

  action step: bool = {
    nondet d = DEVS.oneOf()
    any {
      enqueue(d),
      signUntrusted,
      { nondet lost = Set(false, true).oneOf() send(d, lost) },
      reencrypt(d),
      { nondet target = DEVS.oneOf() remove(d, target) },
      fetch(d),
      { nondet n = 1.to(MAX_RECORDS).oneOf() restore(n) },
      repair(d),
      release,
    }
  }

  val knownIdFirst: bool = not(s.knownRefused)
  val repairComplete: bool = not(s.incompleteRepair)
  val relayAuthorised: bool = valid(s.relay)
  val holdBlocksChanges: bool = not(s.heldAppend)
  val noFork: bool = tuples(DEVS, DEVS).forall(((a, b)) =>
    (not(client(a).stopped) and not(client(b).stopped)) implies
      (prefix(client(a).log, client(b).log) or prefix(client(b).log, client(a).log)))

  val wEnqueued: bool = s.events.contains(Enqueued)
  val wRemovalDuringHold: bool = s.events.contains(RotatedHeld)
  val wSecurityRepaired: bool = s.events.contains(SecurityRepaired)
  val wKnownAfterEpoch: bool = s.events.contains(KnownOld)
  val wStaleRefused: bool = s.events.contains(StaleRefused)
  val wReencryptedStored: bool = s.events.contains(ReencryptedStored)
  val wConflict: bool = s.events.contains(Conflict)
  val wHoldRefused: bool = s.events.contains(HoldRefused)
}
