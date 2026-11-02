// Protocol levels (DESIGN.md "Versioning", [VER-6] to [VER-10]). One space, an
// honest relay that runs the shared check, and devices that update or
// reinstall their engine. specs/levels/README.md has the coverage map.
//
// Abstractions:
//  - A level is an int from 1 to TOP. Each record carries `wl`, the write level
//    that its author wrote it at ([VER-9]).
//  - A device engine supports the levels up to `max`. An update raises it, and a
//    reinstall of an older engine lowers it.
//  - Signatures, bases, keys and epochs are out of scope (specs/spacelog). The
//    relay judges each record against the state after the record before it
//    ([LOG-8]), so a record that a device signed on an old view gets the
//    verdict of the current state.
//  - A removal is an epoch record with one removed device and no key.
module levels {
  type Dev = int
  type Kind = Genesis | Grant | DeviceRec | LevelRec | Removal | Change
  type LRec = { id: int, kind: Kind, author: Dev, subject: Dev, lvl: int, wl: int }
  type Space = { active: Set[Dev], dlv: Dev -> int, level: int }
  type Event = EvRaised | EvRaiseRefused | EvLowRefused | EvAnnounced | EvRemovedThenRaised
               | EvGrantRefused | EvUpdated | EvDowngraded
  type Device = { log: List[LRec], max: int }

  const DEVS: Set[Dev]
  const TOP: int
  const MAX_REC: int
  const BUG: str

  pure val BUGS: Set[str] = Set(
    "none",
    "grantBelowLevel",     // a grant for a device below the write level is valid
    "levelIgnoresDevices", // a level record is valid while an active device is below it
    "lowLevelAccepted",    // a record written below the write level is valid
    "deviceLevelDown",     // a device record can lower the level of its device
  )

  // ---------------------------------------------------------------- pure logic

  pure val noSpace: Space = { active: Set(), dlv: Map(), level: 0 }

  pure def lvOf(sp: Space, d: Dev): int = if (sp.dlv.keys().contains(d)) sp.dlv.get(d) else 0

  // Rules: [VER-7] [VER-8] [VER-10]
  pure def applyRec(sp: Space, r: LRec): Space = match r.kind {
    | Genesis => { active: Set(r.subject), dlv: Map(r.subject -> r.lvl), level: r.wl }
    | Grant => { ...sp, active: sp.active.union(Set(r.subject)), dlv: sp.dlv.put(r.subject, r.lvl) }
    | DeviceRec => { ...sp, dlv: sp.dlv.put(r.author, r.lvl) }
    | LevelRec => { ...sp, level: r.lvl }
    | Removal => { ...sp, active: sp.active.exclude(Set(r.subject)) }
    | Change => sp
  }

  pure def space(log: List[LRec]): Space = log.foldl(noSpace, (sp, r) => applyRec(sp, r))

  // The shared check of the relay and of each device, against the state before
  // the record.
  // Rules: [VER-7] [VER-8] [VER-9]
  pure def valid(sp: Space, r: LRec, bug: str): bool = and {
    r.kind == Genesis or sp.active.contains(r.author),
    // [VER-9] Each new record is written at the write level or above.
    r.kind == Genesis or r.wl >= sp.level or bug == "lowLevelAccepted",
    match r.kind {
      | Genesis => sp == noSpace and r.lvl >= r.wl
      // A grant needs a device level at or above the write level (Enrollment).
      | Grant => not(sp.active.contains(r.subject)) and (r.lvl >= sp.level or bug == "grantBelowLevel")
      // [VER-7] A device record states a new highest level after an update.
      | DeviceRec => r.lvl > lvOf(sp, r.author) or bug == "deviceLevelDown"
      // [VER-8] A raise needs every active device at or above the new level.
      | LevelRec => r.lvl > sp.level
                    and (sp.active.forall(d => lvOf(sp, d) >= r.lvl) or bug == "levelIgnoresDevices")
      | Removal => sp.active.contains(r.subject) and r.subject != r.author
      | Change => true
    },
  }

  // ---------------------------------------------------------------- state

  var relay: List[LRec]
  var devs: Dev -> Device
  var pending: Set[LRec]
  var nextId: int
  var events: Set[Event]

  def dev(d: Dev): Device = devs.get(d)
  def view(d: Dev): Space = space(dev(d).log)
  def active(d: Dev): bool = view(d).active.contains(d)

  action init: bool = all {
    BUGS.contains(BUG),
    relay' = List(),
    devs' = DEVS.mapBy(_ => { log: List(), max: 1 }),
    pending' = Set(),
    nextId' = 1,
    events' = Set(),
  }

  // A device signs a record on its own view. An honest engine writes at the
  // write level of its view ([VER-9]) and signs only a record that its own
  // check accepts.
  action sign(d: Dev, r: LRec): bool = all {
    nextId <= MAX_REC,
    valid(view(d), r, BUG),
    pending' = pending.union(Set(r)),
    nextId' = nextId + 1,
    relay' = relay, devs' = devs, events' = events,
  }

  // The first device creates the space at the level of its engine. It holds the
  // genesis record at once.
  action create(d: Dev): bool = {
    val g = { id: nextId, kind: Genesis, author: d, subject: d, lvl: dev(d).max, wl: 1 }
    all {
      nextId == 1,
      relay' = List(g),
      devs' = devs.set(d, { ...dev(d), log: List(g) }),
      pending' = pending, nextId' = 2, events' = events,
    }
  }

  def blank(d: Dev, k: Kind): LRec = { id: nextId, kind: k, author: d, subject: d, lvl: 0, wl: view(d).level }

  // Enrollment: the new device reports the highest level of its engine.
  action grant(d: Dev, n: Dev): bool = all { active(d), sign(d, { ...blank(d, Grant), subject: n, lvl: dev(n).max }) }

  // [VER-7] After an engine update, the device states its new highest level.
  action announce(d: Dev): bool = all { active(d), sign(d, { ...blank(d, DeviceRec), lvl: dev(d).max }) }

  // [VER-8] A trusted device raises the write level by one.
  action raise(d: Dev): bool = all { active(d), sign(d, { ...blank(d, LevelRec), lvl: view(d).level + 1 }) }

  action remove(d: Dev, x: Dev): bool = all { active(d), sign(d, { ...blank(d, Removal), subject: x }) }

  action change(d: Dev): bool = all { active(d), dev(d).max >= view(d).level, sign(d, blank(d, Change)) }

  action update(d: Dev): bool = all {
    dev(d).max < TOP,
    devs' = devs.set(d, { ...dev(d), max: dev(d).max + 1 }),
    relay' = relay, pending' = pending, nextId' = nextId, events' = events.union(Set(EvUpdated)),
  }

  // A reinstall of an older engine (it keeps its keys). It announces its real level.
  action downgrade(d: Dev): bool = all {
    dev(d).max > 1,
    devs' = devs.set(d, { ...dev(d), max: dev(d).max - 1 }),
    relay' = relay, pending' = pending, nextId' = nextId, events' = events.union(Set(EvDowngraded)),
  }

  // Rules: [LOG-9]
  action relayAppend(r: LRec): bool = {
    val sp = space(relay)
    all {
      pending.contains(r),
      valid(sp, r, BUG),
      relay' = relay.append(r),
      pending' = pending.exclude(Set(r)),
      devs' = devs, nextId' = nextId,
      events' = events.union(Set(
        if (r.kind == LevelRec) Set(EvRaised) else Set(),
        if (r.kind == DeviceRec) Set(EvAnnounced) else Set(),
        if (r.kind == LevelRec and relay.indices().exists(i => relay.nth(i).kind == Removal)) Set(EvRemovedThenRaised) else Set(),
      ).flatten()),
    }
  }

  action relayRefuse(r: LRec): bool = {
    val sp = space(relay)
    all {
      pending.contains(r),
      not(valid(sp, r, BUG)),
      relay' = relay,
      pending' = pending.exclude(Set(r)),
      devs' = devs, nextId' = nextId,
      events' = events.union(Set(
        if (r.kind == LevelRec) Set(EvRaiseRefused) else Set(),
        if (r.kind != Genesis and r.wl < sp.level) Set(EvLowRefused) else Set(),
        if (r.kind == Grant) Set(EvGrantRefused) else Set(),
      ).flatten()),
    }
  }

  // A device verifies the next relay record with the shared check.
  action fetch(d: Dev): bool = {
    val l = dev(d).log
    all {
      l.length() >= 1 or relay.length() >= 1,
      l.length() < relay.length(),
      // A device that is not in the log yet fetches only after its grant.
      l.length() >= 1 or relay.indices().exists(i => relay.nth(i).subject == d),
      valid(space(l), relay.nth(l.length()), "none"),
      devs' = devs.set(d, { ...dev(d), log: l.append(relay.nth(l.length())) }),
      relay' = relay, pending' = pending, nextId' = nextId, events' = events,
    }
  }

  action step: bool = {
    nondet d = DEVS.oneOf()
    nondet x = DEVS.oneOf()
    any {
      create(d), grant(d, x), announce(d), raise(d), remove(d, x), change(d),
      update(d), downgrade(d), fetch(d),
      { nondet r = pending.oneOf() relayAppend(r) },
      { nondet r = pending.oneOf() relayRefuse(r) },
    }
  }

  // ---------------------------------------------------------------- invariants

  // Reference definitions read the relay log only, not the check.
  pure def refLevel(log: List[LRec]): int =
    log.foldl(0, (v, r) => if (r.kind == Genesis) r.wl else if (r.kind == LevelRec) r.lvl else v)

  // [VER-8] Each active device of the relay log states a level at or above the
  // write level, so each active device can read and write every record.
  val levelSupported: bool = {
    val sp = space(relay)
    sp.active.forall(d => lvOf(sp, d) >= refLevel(relay))
  }

  // [VER-9] Each record after the genesis record is written at the write level
  // of the log before it, or above.
  val recordsAtLevel: bool = relay.indices().forall(i =>
    i == 0 or relay.nth(i).wl >= refLevel(relay.slice(0, i)))

  // ---------------------------------------------------------------- witnesses

  val wRaised: bool = events.contains(EvRaised)
  val wRaiseRefused: bool = events.contains(EvRaiseRefused)
  val wLowRefused: bool = events.contains(EvLowRefused)
  val wAnnounced: bool = events.contains(EvAnnounced)
  val wRemovedThenRaised: bool = events.contains(EvRemovedThenRaised)
  val wGrantRefused: bool = events.contains(EvGrantRefused)
}
