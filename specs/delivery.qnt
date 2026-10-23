// Delivery rules from DESIGN.md (App integration > Delivery rules).
// Scope: push (outbox, enqueue, retry), fetch, pull by applied position, app DB restore.
// Out of scope: crypto, epochs, compaction, relay rollback or fork, quotas.
// Abstractions:
//  - A change is an int id (128 random bits in the design, so ids never repeat).
//  - App state is the set of applied change ids. This matches the merge contract:
//    the state depends on the set of changes, not on their order.
//  - Each DB commit is atomic. A crash between two steps is the same as the steps
//    interleaving with a long pause, so the step interleaving models crashes.
module delivery {
  type Dev = int
  type Id = int

  // Durable copy of the app DB, used for the backup and restore action.
  type AppImage = { applied: Set[Id], outbox: Set[Id], pos: int }

  type App = {
    applied: Set[Id],   // changes that the app state holds
    outbox: Set[Id],    // app outbox rows
    pos: int,           // applied position: count of log entries handled
    dups: int,          // count of changes applied twice (must stay 0)
    backup: AppImage,
  }

  type Engine = {
    outbox: Set[Id],    // enqueued envelopes that the verified log does not hold yet
    log: List[Id],      // verified log
  }

  const DEVS: Set[Dev]
  const MAX_IDS: int

  var apps: Dev -> App
  var engines: Dev -> Engine
  var relay: List[Id]
  var owner: Id -> Dev     // author of each created change
  var nextId: int

  pure def emptyImage: AppImage = { applied: Set(), outbox: Set(), pos: 0 }

  pure def listIds(l: List[Id]): Set[Id] = l.indices().map(i => l.nth(i))

  pure def image(a: App): AppImage = { applied: a.applied, outbox: a.outbox, pos: a.pos }

  // Edit: apply the edit and write the outbox row in one app DB transaction.
  pure def canEdit(id: Id): bool = id < MAX_IDS
  pure def applyEdit(a: App, id: Id): App =
    { ...a, applied: a.applied.union(Set(id)), outbox: a.outbox.union(Set(id)) }

  // Enqueue: no effect if the engine outbox or the verified log already holds the id.
  pure def canEnqueue(a: App, e: Engine, id: Id): bool =
    a.outbox.contains(id) and not(e.outbox.contains(id)) and not(listIds(e.log).contains(id))
  pure def applyEnqueue(e: Engine, id: Id): Engine =
    { ...e, outbox: e.outbox.union(Set(id)) }

  // Fetch: the verified log extends to a prefix of the relay log. The engine keeps an
  // own envelope in its outbox until the verified log holds it.
  pure def applyFetch(e: Engine, relayLog: List[Id], n: int): Engine = {
    val newLog = relayLog.slice(0, n)
    { outbox: e.outbox.exclude(listIds(newLog)), log: newLog }
  }

  // Pull: handle the next log entry in one app DB transaction.
  pure def canPull(a: App, e: Engine): bool = e.log.length() > a.pos
  pure def applyPull(a: App, e: Engine): App = {
    val id = e.log.nth(a.pos)
    if (a.outbox.contains(id))
      { ...a, outbox: a.outbox.exclude(Set(id)), pos: a.pos + 1 }
    else
      { ...a,
        applied: a.applied.union(Set(id)),
        dups: a.dups + (if (a.applied.contains(id)) 1 else 0),
        pos: a.pos + 1 }
  }

  action init: bool = all {
    apps' = DEVS.mapBy(_ => { applied: Set(), outbox: Set(), pos: 0, dups: 0, backup: emptyImage }),
    engines' = DEVS.mapBy(_ => { outbox: Set(), log: List() }),
    relay' = List(),
    owner' = Map(),
    nextId' = 0,
  }

  action edit(d: Dev): bool = all {
    canEdit(nextId),
    apps' = apps.set(d, applyEdit(apps.get(d), nextId)),
    owner' = owner.put(nextId, d),
    nextId' = nextId + 1,
    engines' = engines,
    relay' = relay,
  }

  action enqueue(d: Dev, id: Id): bool = all {
    canEnqueue(apps.get(d), engines.get(d), id),
    engines' = engines.set(d, applyEnqueue(engines.get(d), id)),
    apps' = apps,
    relay' = relay,
    owner' = owner,
    nextId' = nextId,
  }

  // Send an envelope from the engine outbox. The relay is idempotent on the id.
  // The device does not learn the result until a fetch, which models a lost response.
  action push(d: Dev, id: Id): bool = all {
    engines.get(d).outbox.contains(id),
    relay' = if (listIds(relay).contains(id)) relay else relay.append(id),
    apps' = apps,
    engines' = engines,
    owner' = owner,
    nextId' = nextId,
  }

  action fetch(d: Dev): bool = {
    val e = engines.get(d)
    nondet n = e.log.length().to(relay.length()).oneOf()
    all {
      engines' = engines.set(d, applyFetch(e, relay, n)),
      apps' = apps,
      relay' = relay,
      owner' = owner,
      nextId' = nextId,
    }
  }

  action pull(d: Dev): bool = all {
    canPull(apps.get(d), engines.get(d)),
    apps' = apps.set(d, applyPull(apps.get(d), engines.get(d))),
    engines' = engines,
    relay' = relay,
    owner' = owner,
    nextId' = nextId,
  }

  action backupApp(d: Dev): bool = all {
    apps' = apps.set(d, { ...apps.get(d), backup: image(apps.get(d)) }),
    engines' = engines,
    relay' = relay,
    owner' = owner,
    nextId' = nextId,
  }

  // App DB restore from backup. The engine state file is not affected.
  action restoreApp(d: Dev): bool = {
    val a = apps.get(d)
    all {
      apps' = apps.set(d, { ...a, applied: a.backup.applied, outbox: a.backup.outbox, pos: a.backup.pos }),
      engines' = engines,
      relay' = relay,
      owner' = owner,
      nextId' = nextId,
    }
  }

  action step: bool = {
    nondet d = DEVS.oneOf()
    nondet id = 0.to(MAX_IDS - 1).oneOf()
    any {
      edit(d),
      enqueue(d, id),
      push(d, id),
      fetch(d),
      pull(d),
      backupApp(d),
      restoreApp(d),
    }
  }

  // Properties

  // No change reaches the app state twice.
  val noDoubleApply: bool = DEVS.forall(d => apps.get(d).dups == 0)

  // An own edit in the app state is never lost: it is in the app outbox, the engine
  // outbox, or the relay log.
  val noLostOwnEdit: bool = DEVS.forall(d =>
    apps.get(d).applied.forall(id =>
      owner.keys().contains(id) and owner.get(id) != d or
      apps.get(d).outbox.contains(id) or
      engines.get(d).outbox.contains(id) or
      listIds(relay).contains(id)))

  // A device that has nothing pending holds exactly the changes in the relay log.
  def quiescent(d: Dev): bool = {
    val a = apps.get(d)
    val e = engines.get(d)
    a.outbox == Set() and e.outbox == Set() and e.log == relay and a.pos == relay.length()
  }
  val quiescentConverged: bool = DEVS.forall(d =>
    not(quiescent(d)) or apps.get(d).applied == listIds(relay))

  // Witnesses
  val relayHoldsTwoChanges: bool = relay.length() >= 2
  val deviceAppliedOtherEdit: bool =
    DEVS.exists(d => apps.get(d).applied.exists(id => owner.keys().contains(id) and owner.get(id) != d))
  val restoreReplayed: bool = DEVS.exists(d => apps.get(d).pos > 0 and apps.get(d).backup.pos < apps.get(d).pos)
  val converged: bool = DEVS.exists(d => quiescent(d) and apps.get(d).applied.size() >= 2)
}

module deliveryAnalysis {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4).*
}
