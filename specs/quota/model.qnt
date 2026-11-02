// Space quota on the relay and the outbox of each device (DESIGN.md S7,
// "Quotas"), and the security record reserve ([STO-15]). One space, two
// devices. A record is an ID, a kind and a size. Signatures, epochs and
// compaction are outside this model. Device 2 can be a thief that sends
// security records until the user blocks it. The daily limit is a count per
// author, because the model has no clock: one run is one relay day.
module quota {
  type Dev = int
  type Kind = Change | Security
  type Verdict = Stored | Known | QuotaFull | ReserveFull | Limited
  type Event = Enqueued | QuotaRefused | SecurityAtFull | StoredAfterRaise | FetchedAtFull | Raised
               | ThiefLimited | Blocked | RemovalAfterFlood
  type Record = { id: int, kind: Kind, size: int, author: Dev }
  type Client = { outbox: List[Record], log: List[int], paused: bool, refused: Set[int] }
  type State = {
    relay: List[Record], quota: int, clients: Dev -> Client, nextId: int,
    made: Set[int], lost: Set[int], fetchRefused: bool, securityRefused: bool,
    silentQuota: bool, events: Set[Event],
    blocked: bool, honestSecurityRefused: bool,
  }

  const QUOTA: int
  const MAX_QUOTA: int
  const MAX_RECORDS: int
  const RESERVE: int           // the security record reserve, outside the quota
  const LIMIT: int             // the most security records from one author in one day
  const THIEF: bool            // device 2 sends security records until the block
  const BUG: str
  pure val BUGS: Set[str] = Set(
    "none", "noQuota", "quotaDrops", "quotaBlocksFetch", "quotaBlocksSecurity", "quotaNoPause",
    "noSecurityLimit",   // the relay does not limit the security records of one author
    "noReserve",         // the relay does not check the reserve
  )
  pure val DEVS: Set[Dev] = Set(1, 2)
  pure val SIZES: Set[int] = Set(1, 2)

  // [QTA-1] [QTA-3] Usage counts the stored change records only.
  pure def used(log: List[Record]): int =
    log.foldl(0, (n, r) => if (r.kind == Change) n + r.size else n)
  pure def holds(log: List[Record], id: int): bool = log.indices().exists(i => log.nth(i).id == id)
  pure def ids(log: List[Record]): List[int] = log.foldl(List(), (xs, r) => xs.append(r.id))
  pure def full(log: List[Record], quota: int): bool = used(log) >= quota
  // [STO-15] Security records count against the reserve only.
  pure def reserveUsed(log: List[Record]): int =
    log.foldl(0, (n, r) => if (r.kind == Security) n + r.size else n)
  pure def securityBy(log: List[Record], d: Dev): int =
    log.foldl(0, (n, r) => if (r.kind == Security and r.author == d) n + 1 else n)

  // [DLV-7] A known record is never refused. [QTA-1] A change that takes the
  // space past its quota is refused, and the relay stores nothing.
  // [QTA-3] A security record never counts against the quota.
  // [STO-15] It counts against the reserve, and one author has at most LIMIT
  // security records in one day.
  pure def verdict(log: List[Record], quota: int, r: Record): Verdict =
    if (holds(log, r.id)) Known
    else if (r.kind == Change and used(log) + r.size > quota and BUG != "noQuota") QuotaFull
    else if (r.kind == Security and used(log) + r.size > quota and BUG == "quotaBlocksSecurity") QuotaFull
    else if (r.kind == Security and securityBy(log, r.author) >= LIMIT and BUG != "noSecurityLimit") Limited
    else if (r.kind == Security and reserveUsed(log) + r.size > RESERVE and BUG != "noReserve") ReserveFull
    else Stored

  var s: State
  def client(d: Dev): Client = s.clients.get(d)

  action init: bool = s' = {
    relay: List(), quota: QUOTA,
    clients: DEVS.mapBy(_ => { outbox: List(), log: List(), paused: false, refused: Set() }),
    nextId: 1, made: Set(), lost: Set(), fetchRefused: false, securityRefused: false,
    silentQuota: false, events: Set(), blocked: false, honestSecurityRefused: false,
  }

  // The app commits an edit and its outbox row, or the engine makes a
  // security record. Both wait in the outbox of the device.
  action enqueue(d: Dev, kind: Kind, z: int): bool = {
    val c = client(d)
    val r = { id: s.nextId, kind: kind, size: if (kind == Security) 1 else z, author: d }
    all {
      s.nextId <= MAX_RECORDS,
      // An honest device writes few security records: one in a run (a removal).
      d == 2 and THIEF or kind == Change or securityBy(s.relay, d) + c.outbox.select(x => x.kind == Security).length() == 0,
      not(d == 2 and s.blocked),
      s' = { ...s, nextId: s.nextId + 1, made: s.made.union(Set(r.id)),
        clients: s.clients.set(d, { ...c, outbox: c.outbox.append(r) }),
        events: s.events.union(Set(Enqueued)) },
    }
  }

  // The device sends the first record of its outbox.
  // [QTA-4] After a quota refusal the engine keeps the record in its outbox
  // and reports `paused: quota`. The refusal is transient.
  action push(d: Dev): bool = {
    val c = client(d)
    val r = c.outbox.head()
    val v = verdict(s.relay, s.quota, r)
    val transient = v == QuotaFull or v == ReserveFull or v == Limited
    val keep = transient and (v != QuotaFull or BUG != "quotaDrops")
    val paused = v == QuotaFull and BUG != "quotaNoPause"
    val honest = not(THIEF and d == 2)
    val ev = if (v == Limited and not(honest)) Set(ThiefLimited)
      else if (v == Stored and r.kind == Security and honest and THIEF and securityBy(s.relay, 2) >= LIMIT) Set(RemovalAfterFlood)
      else if (v == QuotaFull) Set(QuotaRefused)
      else if (v == Stored and r.kind == Security and full(s.relay, s.quota)) Set(SecurityAtFull)
      else if (v == Stored and c.refused.contains(r.id)) Set(StoredAfterRaise)
      else Set()
    all {
      c.outbox.length() > 0,
      // [STO-12] The relay refuses each request of a blocked device.
      not(d == 2 and s.blocked),
      s' = { ...s,
        relay: if (v == Stored) s.relay.append(r) else s.relay,
        clients: s.clients.set(d, { ...c,
          outbox: if (keep) c.outbox else c.outbox.tail(),
          paused: paused,
          refused: if (v == QuotaFull) c.refused.union(Set(r.id)) else c.refused }),
        lost: if (v == QuotaFull and not(keep)) s.lost.union(Set(r.id)) else s.lost,
        securityRefused: s.securityRefused or (v == QuotaFull and r.kind == Security),
        honestSecurityRefused: s.honestSecurityRefused or (honest and r.kind == Security and transient),
        silentQuota: s.silentQuota or (v == QuotaFull and not(paused)),
        events: s.events.union(ev) },
    }
  }

  // [QTA-2] The relay serves the stored records also at a full quota.
  action fetch(d: Dev): bool = {
    val c = client(d)
    val refuse = BUG == "quotaBlocksFetch" and full(s.relay, s.quota)
    all {
      ids(s.relay) != c.log or refuse,
      s' = { ...s,
        clients: if (refuse) s.clients else s.clients.set(d, { ...c, log: ids(s.relay) }),
        fetchRefused: s.fetchRefused or refuse,
        events: s.events.union(if (not(refuse) and full(s.relay, s.quota)) Set(FetchedAtFull) else Set()) },
    }
  }

  // S7: the relay operator sets a larger quota. Compaction is not modelled.
  action raise: bool = all {
    s.quota < MAX_QUOTA,
    s' = { ...s, quota: s.quota + 1, events: s.events.union(Set(Raised)) },
  }

  // S4: the user blocks device 2 on the user page.
  action block: bool = all {
    THIEF,
    not(s.blocked),
    s' = { ...s, blocked: true, events: s.events.union(Set(Blocked)) },
  }

  action step: bool = {
    nondet d = DEVS.oneOf()
    any {
      block,
      { nondet k = Set(Change, Security).oneOf() nondet z = SIZES.oneOf() enqueue(d, k, z) },
      push(d),
      fetch(d),
      raise,
    }
  }

  // [QTA-1] The stored changes never exceed the quota.
  val withinQuota: bool = used(s.relay) <= s.quota
  // [QTA-4] A record that a device made is in the relay log or in its outbox.
  val noLostChange: bool = s.made.forall(id =>
    holds(s.relay, id) or DEVS.exists(d => holds(client(d).outbox, id)))
  // [QTA-2] No fetch is refused for quota.
  val servesStored: bool = not(s.fetchRefused)
  // [QTA-3] No security record is refused for quota.
  val securityNotBlocked: bool = not(s.securityRefused)
  // [QTA-4] Each quota refusal sets `paused: quota`.
  val quotaReported: bool = not(s.silentQuota)
  // [STO-15] The stored security records never exceed the reserve, and they
  // never take quota from changes.
  val withinReserve: bool = reserveUsed(s.relay) <= RESERVE
  // [STO-15] T10: a thief cannot fill the reserve, so the relay never refuses
  // the security record of an honest device (a removal).
  val honestSecurityStored: bool = not(s.honestSecurityRefused)

  val wQuotaRefused: bool = s.events.contains(QuotaRefused)
  val wSecurityAtFull: bool = s.events.contains(SecurityAtFull)
  val wStoredAfterRaise: bool = s.events.contains(StoredAfterRaise)
  val wFetchedAtFull: bool = s.events.contains(FetchedAtFull)
  val wThiefLimited: bool = s.events.contains(ThiefLimited)
  val wRemovalAfterFlood: bool = s.events.contains(RemovalAfterFlood)
}
