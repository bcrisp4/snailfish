// Model of the Snailfish space log security state: DESIGN.md "Space log" (record
// table, signed base rule), "Enrollment" (steps 8 and 9), Security T7 and T8, and
// the closed issues C34, C35, C47 and C48. specs/spacelog/README.md has the
// coverage map, the findings and the known limits.
//
// Abstractions:
//  - A key is an opaque int. A device key is the device id. The recovery key is
//    RK (0). Key secrecy is out of scope. The model tracks which keys each record
//    seals to which devices, and checks that no removed device gets a later key.
//  - A signature is a record in the ghost set env.signed. Only an author can add a
//    record to it. A relay can offer a record that is not in the set (a forgery),
//    and the verifier then finds no signature.
//  - A digest is the list of record ids, folded to an int. Record ids are unique,
//    so equal digests mean equal log prefixes.
//  - The shared `protocol` crate is the pure function `check`. The relay and each
//    device use it. A relay that is malicious does not use it.
//  - The relay holds up to two branches of the log. An honest relay uses branch 0.
//    A malicious relay can copy a prefix to branch 1 and serve any branch to any
//    device. A device fetches one record at a time from the position after its tip.
//  - The app data, compaction, recovery records, levels and request signing are out
//    of scope. A change record carries only its author and its epoch number.
//
// The const BUG selects one deliberate violation of the design. "none" is the
// design. specs/spacelog/checks.toml binds the consts for each config and each
// mutant, and specs/tools/verify.py runs them.
module spacelog {
  type Key = int
  type Kind = Genesis | Grant | Epoch | Change
  type Verdict = Ok | BadSig | BadBase | BaseRule | BadAuthor | BadState
  type Status = Running | Forked | Rejected

  type Event =
    | EvGenesis | EvGrantAppended | EvRecoveryGrant | EvEpochAppended | EvRemovalAppended
    | EvChangeAppended | EvNewEpochChange | EvRefusedBaseRule | EvRefusedAuthor | EvRefusedOther
    | EvCheckpoint | EvEnrolled | EvEpochVerified | EvForkBranch | EvForkDetected
    | EvForgedRejected | EvDeviceRejected | EvForged | EvReplayed | EvStaleWrite | EvThiefSigned

  type LogRec = {
    id: int,               // unique for each signature. Stands for the signature bytes.
    kind: Kind,
    author: Key,           // the signing key
    bpos: int,             // base position
    bdig: int,             // base digest: the digest of the log prefix that ends at bpos
    subject: Key,          // genesis: the first device. grant: the new device.
    removed: Set[Key],     // epoch: the devices that the record removes
    stay: Set[Key],        // epoch: the devices that stay. The new key is sealed to them.
    sealed: Set[int],      // grant: the keys sealed to the subject
    epoch: int,            // genesis: 1. epoch: the new epoch. change: the epoch of its key.
    key: int,              // genesis and epoch: the id of the new key
  }

  // The space state after the last entry of a log.
  type Space = {
    active: Set[Key],
    removed: Set[Key],     // devices that a record removed. A removal is final.
    epoch: int,
    keys: Set[int],        // the key of each epoch
    lastSec: int,          // position of the last security record
  }

  type Log = { recs: List[LogRec], sp: Space }

  // A signed statement of one log position and its digest (Enrollment, step 8).
  type Checkpoint = { has: bool, pos: int, dig: int }

  type Device = {
    log: Log,              // the verified log
    status: Status,        // Forked and Rejected are "stopped"
    wepoch: int,           // the epoch that the device encrypts a new change with
    cp: Checkpoint,
  }

  // Ghost state for properties and witnesses. No device or relay reads it, except
  // `signed`, which stands for the signatures, and `lastKey` for one BUG value.
  type Env = {
    nextId: int,
    attacks: int,              // actions of a malicious relay so far
    signed: Set[LogRec],       // every record that a key signed
    conflictSeen: Set[Key],    // honest devices that received a record whose base conflicts
    badWrite: bool,            // an honest device wrote with an epoch that is not its verified epoch
    staleStored: bool,         // a relay stored a change with an epoch below a stored epoch record
    lastKey: Key -> int,       // the key of the last epoch record that a device signed
    events: Set[Event],
  }

  // ---------------------------------------------------------------- consts

  const DEVS: Set[Key]
  const BAD: Set[Key]        // devices that an attacker controls. They ignore their own removal.
  const MAX_REC: int         // bound on the records that keys sign
  const MAX_ATTACKS: int     // bound on the actions of a malicious relay
  const FAULTS: Set[str]     // the relay capabilities and key uses that this config enables
  const BUG: str

  pure val RK: Key = 0
  pure val HON: Set[Key] = DEVS.exclude(BAD)

  pure val FAULT_CLASSES: Set[str] = Set(
    "fork",       // the relay keeps a second branch and serves any branch to any device
    "reorder",    // the relay appends any signed record to any branch, in any order, also a replay
    "forge",      // the relay appends a grant or a change with a signature that nobody made
    "recovery",   // the recovery key can sign a grant or an epoch record
  )

  pure val BR: Set[int] = if (FAULTS.contains("fork")) Set(0, 1) else Set(0)

  pure val BUGS: Set[str] = Set(
    "none",
    "noBaseRule",           // the protocol crate does not check the base of a security record
    "relayNoBaseRule",      // the relay does not check the base of a security record
    "relaySkipsCheck",      // the relay appends each record that it gets
    "verifierIgnoresRemovals", // the protocol crate does not remove a device from the active set
    "epochSealsToAll",      // an epoch record seals the new key to every active device
    "trustsRelayVerdict",   // a device accepts each record that the relay serves
    "noSigCheck",           // the protocol crate does not check signatures
    "baseUnchecked",        // a device accepts a record before it checks the base digest
    "grantFromRemoved",     // a grant from a removed device is valid
    "regrantRemoved",       // a grant for a removed device is valid
    "epochUnchecked",       // a change with a past epoch is valid
    "staleWriteEpoch",      // a device keeps its write epoch after it verifies an epoch record
    "resignReusesKey",      // the engine signs a refused epoch record again with the same key
  )

  pure val DEVICE_ONLY: Set[str] = Set("trustsRelayVerdict", "baseUnchecked", "staleWriteEpoch")
  pure val RELAY_ONLY: Set[str] = Set("relayNoBaseRule", "relaySkipsCheck")

  // The BUG value that the protocol crate sees in a device, and in the relay.
  pure def deviceBug(b: str): str = if (RELAY_ONLY.contains(b)) "none" else b
  pure def relayBug(b: str): str =
    if (b == "relayNoBaseRule") "noBaseRule"
    else if (DEVICE_ONLY.contains(b) or b == "relaySkipsCheck") "none"
    else b

  // ---------------------------------------------------------------- pure logic

  pure def max2(a: int, b: int): int = if (a > b) a else b

  // Rules: [LOG-5]
  pure def dig(l: List[LogRec]): int = l.foldl(0, (h, r) => h * 100 + r.id)

  pure def isSec(r: LogRec): bool = r.kind != Change

  pure def anyRec(l: List[LogRec], f: LogRec => bool): bool = l.indices().exists(i => f(l.nth(i)))

  pure val emptySpace: Space = { active: Set(), removed: Set(), epoch: 0, keys: Set(), lastSec: 0 }
  pure val emptyLog: Log = { recs: List(), sp: emptySpace }
  pure val freshDevice: Device =
    { log: emptyLog, status: Running, wepoch: 0, cp: { has: false, pos: 0, dig: 0 } }

  // The keys that a record seals, and the keys that can open them.
  pure def sealedKeys(r: LogRec): Set[int] = match r.kind {
    | Genesis => Set(r.key)
    | Grant => r.sealed
    | Epoch => Set(r.key)
    | Change => Set()
  }

  pure def sealTo(r: LogRec): Set[Key] = match r.kind {
    | Genesis => Set(r.subject, RK)
    | Grant => Set(r.subject)
    | Epoch => r.stay.union(Set(RK))
    | Change => Set()
  }

  // The space state after one entry.
  // Rules: [LOG-8]
  pure def applyRec(sp: Space, r: LogRec, pos: int, bug: str): Space = match r.kind {
    | Genesis => { active: Set(r.subject), removed: Set(), epoch: 1, keys: Set(r.key), lastSec: pos }
    | Grant => { ...sp, active: sp.active.union(Set(r.subject)), lastSec: pos }
    | Epoch => {
        ...sp,
        active: if (bug == "verifierIgnoresRemovals") sp.active else sp.active.exclude(r.removed),
        removed: if (bug == "verifierIgnoresRemovals") sp.removed else sp.removed.union(r.removed),
        epoch: r.epoch,
        keys: sp.keys.union(Set(r.key)),
        lastSec: pos,
      }
    | Change => sp
  }

  pure def appendRec(l: Log, r: LogRec, bug: str): Log =
    { recs: l.recs.append(r), sp: applyRec(l.sp, r, l.recs.length() + 1, bug) }

  pure def rebuild(recs: List[LogRec], bug: str): Log =
    recs.foldl(emptyLog, (l, r) => appendRec(l, r, bug))

  // Who can sign a record, judged against the state before it.
  // Rules: [LOG-2] [LOG-8]
  pure def authorOk(sp: Space, r: LogRec, bug: str): bool = match r.kind {
    | Genesis => r.author == RK
    | Grant => sp.active.contains(r.author) or r.author == RK
               or (bug == "grantFromRemoved" and sp.removed.contains(r.author))
    | Epoch => sp.active.contains(r.author) or r.author == RK
    | Change => sp.active.contains(r.author)
  }

  // What each record must hold, judged against the state before it.
  // Rules: [LOG-8]
  pure def stateOk(sp: Space, r: LogRec, bug: str): bool = match r.kind {
    | Genesis => true
    | Grant => not(sp.active.contains(r.subject))
               and (bug == "regrantRemoved" or not(sp.removed.contains(r.subject)))
               and r.sealed == sp.keys
    | Epoch => r.removed.subseteq(sp.active) and not(r.removed.contains(r.author))
               and r.epoch == sp.epoch + 1
               and (bug == "epochSealsToAll" or r.stay == sp.active.exclude(r.removed))
    | Change => bug == "epochUnchecked" or r.epoch == sp.epoch
  }

  // The base is a position before the record, and its digest is in the log.
  // Rules: [LOG-6]
  pure def baseOk(l: Log, r: LogRec, bug: str): bool = {
    val pos = l.recs.length() + 1
    r.bpos >= 1 and r.bpos < pos
      and (bug == "baseUnchecked" or r.bdig == dig(l.recs.slice(0, r.bpos)))
  }

  // The shared `protocol` crate: the relay and each device call this function.
  // Rules: [LOG-1] [LOG-2] [LOG-7] [LOG-8] [LOG-9]
  // `l` holds the log before the record. The order of the checks fixes which
  // verdict a record gets. A device stops with fork on BadBase.
  pure def check(l: Log, r: LogRec, signed: Set[LogRec], bug: str): Verdict = {
    val pos = l.recs.length() + 1
    if (bug != "noSigCheck" and not(signed.contains(r))) BadSig
    else if (r.kind == Genesis)
      (if (pos == 1 and r.author == RK and r.bpos == 0 and r.bdig == 0 and r.epoch == 1) Ok else BadState)
    else if (pos == 1 or anyRec(l.recs, x => x.id == r.id)) BadState
    else if (not(baseOk(l, r, bug))) BadBase
    else if (not(authorOk(l.sp, r, bug))) BadAuthor
    else if (isSec(r) and bug != "noBaseRule" and r.bpos < l.sp.lastSec) BaseRule
    else if (not(stateOk(l.sp, r, bug))) BadState
    else Ok
  }

  // ---- reference definitions for the invariants. They do not use `check` or the
  // device state, so a wrong device state cannot hide a wrong check.

  // The glossary: an active device has a grant and no later removal.
  pure def refActive(recs: List[LogRec]): Set[Key] =
    recs.foldl(Set(), (a, r) => match r.kind {
      | Genesis => Set(r.subject)
      | Grant => a.union(Set(r.subject))
      | Epoch => a.exclude(r.removed)
      | Change => a
    })

  pure def refRemoved(recs: List[LogRec]): Set[Key] =
    recs.foldl(Set(), (a, r) => if (r.kind == Epoch) a.union(r.removed) else a)

  pure def refEpoch(recs: List[LogRec]): int =
    if (recs == List()) 0 else recs.foldl(1, (e, r) => if (r.kind == Epoch) e + 1 else e)

  // The position of the last security record in a prefix. 0 if none.
  pure def refLastSec(recs: List[LogRec]): int =
    recs.indices().fold(0, (m, j) => if (isSec(recs.nth(j))) j + 1 else m)

  // The devices that hold a key, after each record that was signed. A record that
  // the relay refused still counts, because the relay saw it.
  pure def holders(k: int, signed: Set[LogRec]): Set[Key] =
    signed.fold(Set(), (s, x) => if (sealedKeys(x).contains(k)) s.union(sealTo(x)) else s)

  // Does a record carry a base that is not in the log before it?
  pure def baseConflict(recs: List[LogRec], r: LogRec): bool =
    r.kind != Genesis and not(
      r.bpos >= 1 and r.bpos <= recs.length() and r.bdig == dig(recs.slice(0, r.bpos)))

  pure def isPrefix(a: List[LogRec], b: List[LogRec]): bool =
    a.length() <= b.length() and b.slice(0, a.length()) == a

  // Does a correct verifier accept every record of a log, in order?
  pure def verifiesAll(recs: List[LogRec], signed: Set[LogRec]): bool =
    recs.foldl({ ok: true, log: emptyLog }, (acc, r) =>
      if (acc.ok and check(acc.log, r, signed, "none") == Ok)
        { ok: true, log: appendRec(acc.log, r, "none") }
      else { ok: false, log: acc.log }).ok

  // ---------------------------------------------------------------- state

  var devs: Key -> Device
  var branches: int -> Log
  var pending: Set[LogRec]   // records that the honest relay got and has not yet appended or refused
  var env: Env

  def dev(d: Key): Device = devs.get(d)
  def ev(e: Event): Env = { ...env, events: env.events.union(Set(e)) }
  def evs(es: Set[Event]): Env = { ...env, events: env.events.union(es) }
  def ready(d: Key): bool =
    dev(d).status == Running and dev(d).cp.has and dev(d).log.recs.length() >= max2(1, dev(d).cp.pos)

  // The highest epoch that any branch of the relay holds.
  val relayEpoch: int = BR.fold(0, (m, b) => max2(m, branches.get(b).sp.epoch))

  // ---------------------------------------------------------------- actions

  action init: bool = all {
    BUGS.contains(BUG),
    FAULTS.subseteq(FAULT_CLASSES),
    BAD.subseteq(DEVS),
    devs' = DEVS.mapBy(_ => freshDevice),
    branches' = BR.mapBy(_ => emptyLog),
    pending' = Set(),
    env' = { nextId: 1, attacks: 0, signed: Set(), conflictSeen: Set(),
             badWrite: false, staleStored: false, lastKey: DEVS.mapBy(_ => 0), events: Set() },
  }

  // The recovery key signs the genesis record. It holds the first grant.
  // The first device holds the genesis record at once.
  action createSpace(d: Key): bool = {
    val id = env.nextId
    val g = { id: id, kind: Genesis, author: RK, bpos: 0, bdig: 0, subject: d,
              removed: Set(), stay: Set(), sealed: Set(), epoch: 1, key: id }
    all {
      id == 1,
      id <= MAX_REC,
      devs' = devs.set(d, { log: appendRec(emptyLog, g, deviceBug(BUG)), status: Running, wepoch: 1,
                            cp: { has: true, pos: 0, dig: 0 } }),
      branches' = branches,
      pending' = pending.union(Set(g)),
      env' = { ...ev(EvGenesis), nextId: id + 1, signed: env.signed.union(Set(g)) },
    }
  }

  // The base of a new record: the tip of the verified log of the author.
  pure def blank(id: int, kind: Kind, author: Key, view: Log): LogRec =
    { id: id, kind: kind, author: author, bpos: view.recs.length(), bdig: dig(view.recs),
      subject: 0, removed: Set(), stay: Set(), sealed: Set(), epoch: 0, key: 0 }

  // A device signs a record that is valid in its own view. A device that an
  // attacker controls also signs after its own removal: it checks the record as
  // if it were still active.
  // A change carries the write epoch of the device. The device does not check
  // that epoch against its own log, so a stale write epoch stays possible.
  def selfOk(d: Key, r: LogRec): bool = {
    val view = dev(d).log
    val seen = if (HON.contains(d)) view
               else { recs: view.recs, sp: { ...view.sp, active: view.sp.active.union(Set(r.author)) } }
    val judged = if (r.kind == Change) { ...r, epoch: view.sp.epoch } else r
    check(seen, judged, Set(judged), deviceBug(BUG)) == Ok
  }

  def signerOk(d: Key, signer: Key): bool =
    ready(d) and (signer == d or (FAULTS.contains("recovery") and signer == RK))

  // The signed record goes to the relay.
  action submit(d: Key, r: LogRec, es: Set[Event], nextKey: Key -> int, bw: bool): bool = all {
    r.id <= MAX_REC,
    selfOk(d, r),
    devs' = devs,
    branches' = branches,
    pending' = pending.union(Set(r)),
    env' = { ...evs(es.union(if (BAD.contains(d) and dev(d).log.sp.removed.contains(d)) Set(EvThiefSigned) else Set())),
             nextId: env.nextId + 1, signed: env.signed.union(Set(r)), lastKey: nextKey,
             badWrite: env.badWrite or bw },
  }

  // Enrollment, step 8: a trusted device appends a grant for the new device.
  action signGrant(d: Key, signer: Key, subject: Key): bool = {
    val r = { ...blank(env.nextId, Grant, signer, dev(d).log), subject: subject, sealed: dev(d).log.sp.keys }
    all {
      signerOk(d, signer),
      subject != RK,
      submit(d, r, if (signer == RK) Set(EvRecoveryGrant) else Set(), env.lastKey, false),
    }
  }

  // Removal and key rotation. The honest author seals the new key to each device
  // that stays. The key is new, except under BUG resignReusesKey, where the engine
  // signs a refused record again with the key of the refused one.
  action signEpoch(d: Key, signer: Key, gone: Key): bool = {
    val removed = Set(gone)
    val view = dev(d).log
    val reuse = BUG == "resignReusesKey" and env.lastKey.get(d) != 0
                and not(anyRec(view.recs, x => x.kind == Epoch and x.key == env.lastKey.get(d)))
    val key = if (reuse) env.lastKey.get(d) else env.nextId
    val stay = if (BUG == "epochSealsToAll") view.sp.active else view.sp.active.exclude(removed)
    val r = { ...blank(env.nextId, Epoch, signer, view), removed: removed, stay: stay,
              epoch: view.sp.epoch + 1, key: key }
    all {
      signerOk(d, signer),
      submit(d, r, if (signer == RK) Set(EvRecoveryGrant) else Set(), env.lastKey.set(d, key), false),
    }
  }

  // A device encrypts a change with its write epoch. A device that has not yet
  // verified a new epoch record can still write with the old epoch (T8 limit).
  action signChange(d: Key): bool = {
    val view = dev(d).log
    val r = { ...blank(env.nextId, Change, d, view), epoch: dev(d).wepoch }
    all {
      signerOk(d, d),
      submit(d, r, if (dev(d).wepoch < relayEpoch) Set(EvStaleWrite) else Set(), env.lastKey,
             HON.contains(d) and dev(d).wepoch != view.sp.epoch),
    }
  }

  // Enrollment, step 8: the trusted device sends a checkpoint at or after the grant.
  action sendCheckpoint(t: Key, n: Key): bool = all {
    ready(t),
    t != n,
    not(dev(n).cp.has),
    anyRec(dev(t).log.recs, r => r.kind == Grant and r.subject == n),
    devs' = devs.set(n, { ...dev(n), cp: { has: true, pos: dev(t).log.recs.length(), dig: dig(dev(t).log.recs) } }),
    branches' = branches,
    pending' = pending,
    env' = ev(EvCheckpoint),
  }

  // ---- the honest relay: one branch, the shared check

  // Rules: [LOG-9]
  def relayVerdict(r: LogRec): Verdict = check(branches.get(0), r, env.signed, relayBug(BUG))

  def storedEnv(r: LogRec): Env = {
    val es = Set(
      if (r.kind == Genesis) Set(EvGenesis) else Set(),
      if (r.kind == Grant) Set(EvGrantAppended) else Set(),
      if (r.kind == Grant and r.author == RK) Set(EvRecoveryGrant) else Set(),
      if (r.kind == Epoch) Set(EvEpochAppended) else Set(),
      if (r.kind == Epoch and r.removed != Set()) Set(EvRemovalAppended) else Set(),
      if (r.kind == Change) Set(EvChangeAppended) else Set(),
      if (r.kind == Change and r.epoch >= 2) Set(EvNewEpochChange) else Set(),
    ).flatten()
    { ...evs(es), staleStored: env.staleStored or (r.kind == Change and r.epoch < relayEpoch) }
  }

  action relayAppend(r: LogRec): bool = all {
    pending.contains(r),
    relayVerdict(r) == Ok or BUG == "relaySkipsCheck",
    branches' = branches.set(0, appendRec(branches.get(0), r, relayBug(BUG))),
    pending' = pending.exclude(Set(r)),
    devs' = devs,
    env' = storedEnv(r),
  }

  // A refused record changes no stored state. The relay keeps it only in ghost state.
  action relayRefuse(r: LogRec): bool = {
    val v = relayVerdict(r)
    all {
      pending.contains(r),
      v != Ok,
      BUG != "relaySkipsCheck",
      pending' = pending.exclude(Set(r)),
      branches' = branches,
      devs' = devs,
      env' = ev(if (v == BaseRule) EvRefusedBaseRule else if (v == BadAuthor) EvRefusedAuthor else EvRefusedOther),
    }
  }

  // ---- the malicious relay. It cannot sign. It can keep a second branch,
  // append any signed record anywhere, and append a record with no signature.

  action forkBranch(n: int): bool = all {
    FAULTS.contains("fork"),
    env.attacks < MAX_ATTACKS,
    branches.get(1).recs.length() == 0,
    1 <= n, n <= branches.get(0).recs.length(),
    branches' = branches.set(1, rebuild(branches.get(0).recs.slice(0, n), relayBug(BUG))),
    devs' = devs,
    pending' = pending,
    env' = { ...ev(EvForkBranch), attacks: env.attacks + 1 },
  }

  // The relay appends a record that a key signed, to any branch. With "reorder" it
  // can append in any order, replay a record, and append a record from a removed
  // device. With only "fork" it appends to branch 1 the records that pass the check.
  action appendAny(r: LogRec, b: int): bool = all {
    FAULTS.contains("reorder")
      or (FAULTS.contains("fork") and b == 1 and check(branches.get(b), r, env.signed, relayBug(BUG)) == Ok),
    env.attacks < MAX_ATTACKS,
    env.signed.contains(r),
    not(anyRec(branches.get(b).recs, x => x.id == r.id)),
    branches' = branches.set(b, appendRec(branches.get(b), r, relayBug(BUG))),
    pending' = pending.exclude(Set(r)),
    devs' = devs,
    env' = { ...storedEnv(r), events: storedEnv(r).events.union(Set(EvReplayed)), attacks: env.attacks + 1 },
  }

  // The relay appends a grant or a change that names a real author, with a signature that
  // nobody made. Its base and its sealed keys are correct for the branch.
  action forgeRecord(b: int, kind: Kind, author: Key, subject: Key): bool = {
    val br = branches.get(b)
    val base = blank(50 + env.attacks, kind, author, br)
    val r = if (kind == Grant) { ...base, subject: subject, sealed: br.sp.keys }
            else if (kind == Epoch)
              { ...base, removed: Set(subject), stay: br.sp.active.exclude(Set(subject)),
                         epoch: br.sp.epoch + 1, key: base.id }
            else { ...base, epoch: br.sp.epoch }
    all {
      FAULTS.contains("forge"),
      kind != Genesis,
      env.attacks < MAX_ATTACKS,
      br.recs.length() >= 1,
      author == RK or DEVS.contains(author),
      subject != RK,
      branches' = branches.set(b, appendRec(br, r, relayBug(BUG))),
      devs' = devs,
      pending' = pending,
      env' = { ...ev(EvForged), attacks: env.attacks + 1 },
    }
  }

  // ---- devices

  // Rules: [LOG-9]
  // A device fetches the record after its tip. The relay chooses the branch.
  // A device verifies the record before it applies it. A record whose base is
  // not in the log, or a log that differs from the checkpoint, stops the device
  // with fork. Any other failure stops it with rejected.
  action fetchOne(d: Key, b: int): bool = {
    val dv = dev(d)
    val l = dv.log
    val br = branches.get(b)
    val rec = br.recs.nth(l.recs.length())
    val v = check(l, rec, env.signed, deviceBug(BUG))
    val ok = BUG == "trustsRelayVerdict" or v == Ok
    val nsp = applyRec(l.sp, rec, l.recs.length() + 1, deviceBug(BUG))
    val nl = { recs: l.recs.append(rec), sp: nsp }
    val newLen = nl.recs.length()
    val cpFail = dv.cp.pos == newLen and dig(nl.recs) != dv.cp.dig
    val wep = if (BUG == "staleWriteEpoch" and newLen > dv.cp.pos) dv.wepoch else nsp.epoch
    val saw = baseConflict(l.recs, rec) or (ok and cpFail)
    all {
      dv.status == Running,
      dv.cp.has,
      l.recs.length() < br.recs.length(),
      devs' = devs.set(d,
        if (ok and cpFail) { ...dv, status: Forked }
        else if (ok) { ...dv, log: nl, wepoch: wep }
        else { ...dv, status: if (v == BadBase) Forked else Rejected }),
      branches' = branches,
      pending' = pending,
      env' = { ...evs(Set(
                if (ok and not(cpFail) and rec.kind == Epoch and rec.stay.contains(d)) Set(EvEpochVerified) else Set(),
                if (ok and not(cpFail) and dv.cp.pos > 0 and newLen == dv.cp.pos) Set(EvEnrolled) else Set(),
                if ((not(ok) and v == BadBase) or (ok and cpFail)) Set(EvForkDetected) else Set(),
                if (not(ok) and v == BadSig) Set(EvForgedRejected) else Set(),
                if (not(ok) and v != BadSig and v != BadBase) Set(EvDeviceRejected) else Set(),
              ).flatten()),
               conflictSeen: if (saw and HON.contains(d)) env.conflictSeen.union(Set(d)) else env.conflictSeen },
    }
  }

  action step: bool = {
    nondet d = DEVS.oneOf()
    nondet signer = (if (FAULTS.contains("recovery")) Set(d, RK) else Set(d)).oneOf()
    nondet subject = DEVS.oneOf()
    nondet gone = DEVS.oneOf()
    nondet b = BR.oneOf()
    nondet n = 1.to(MAX_REC).oneOf()
    nondet kind = Set(Grant, Epoch, Change).oneOf()
    nondet author = DEVS.union(Set(RK)).oneOf()
    any {
      createSpace(d),
      signGrant(d, signer, subject),
      signEpoch(d, signer, gone),
      signChange(d),
      sendCheckpoint(d, subject),
      { nondet r = pending.oneOf() relayAppend(r) },
      { nondet r = pending.oneOf() relayRefuse(r) },
      { nondet r = env.signed.oneOf() appendAny(r, b) },
      forkBranch(n),
      forgeRecord(b, kind, author, subject),
      fetchOne(d, b),
    }
  }

  // ---------------------------------------------------------------- invariants

  // Each invariant ranges over the honest devices: the others are under attack.

  // I1. A record from a device after its removal is never in a verified log.
  val authorActive: bool = HON.forall(d => {
    val recs = dev(d).log.recs
    recs.indices().forall(i => {
      val r = recs.nth(i)
      r.kind == Genesis or refActive(recs.slice(0, i)).contains(r.author)
        or (r.author == RK and isSec(r))
    })
  })

  // I2. No record in a verified log seals a key to a device that an earlier
  // record, or the record itself, removes.
  val noKeyToRemoved: bool = HON.forall(d => {
    val recs = dev(d).log.recs
    recs.indices().forall(i => {
      val r = recs.nth(i)
      sealTo(r).intersect(refRemoved(recs.slice(0, i)).union(r.removed)) == Set()
    })
  })

  // I2b. The key of an epoch record in a verified log reaches no removed device
  // through any record that a key signed, also a record that the relay refused.
  val removedKeyIsolation: bool = HON.forall(d => {
    val recs = dev(d).log.recs
    recs.indices().forall(i => {
      val r = recs.nth(i)
      r.kind == Epoch implies
        holders(r.key, env.signed).intersect(refRemoved(recs.slice(0, i)).union(r.removed)) == Set()
    })
  })

  // I3. A security record in a verified log has its base at or after the last
  // security record, so no two security records share a base state.
  val baseRule: bool = HON.forall(d => {
    val recs = dev(d).log.recs
    recs.indices().forall(i => {
      val r = recs.nth(i)
      r.kind != Genesis and isSec(r) implies r.bpos >= refLastSec(recs.slice(0, i))
    })
  })

  // I4. The state of a device is a function of its verified log, as the glossary
  // defines it: active devices, removed devices and epoch. Two devices with the
  // same verified prefix therefore compute the same active set.
  val activeSetDeterministic: bool = HON.forall(d => and {
    dev(d).log.sp.active == refActive(dev(d).log.recs),
    dev(d).log.sp.removed == refRemoved(dev(d).log.recs),
    dev(d).log.sp.epoch == refEpoch(dev(d).log.recs),
  })

  // I5. A grant in a verified log has a signature, and its author was an active
  // device or the recovery key.
  val grantAuthorized: bool = HON.forall(d => {
    val recs = dev(d).log.recs
    recs.indices().forall(i => {
      val r = recs.nth(i)
      r.kind == Grant implies
        (env.signed.contains(r) and (refActive(recs.slice(0, i)).contains(r.author) or r.author == RK))
    })
  })

  // I6a. An honest device that received a record whose base is not in its log
  // has stopped.
  val forkStops: bool = env.conflictSeen.forall(d => dev(d).status != Running)

  // I6b. Each record in a verified log has its base in that log.
  val baseInOwnLog: bool = HON.forall(d => {
    val recs = dev(d).log.recs
    recs.indices().forall(i => {
      val r = recs.nth(i)
      r.kind == Genesis or (r.bpos >= 1 and r.bpos <= i and r.bdig == dig(recs.slice(0, r.bpos)))
    })
  })

  // I7. An honest device never writes a change with an epoch that differs from
  // the epoch of its verified log. After it verifies an epoch record, it uses
  // the new epoch.
  val writeEpochCurrent: bool = not(env.badWrite)

  // I8. The honest relay holds only records that a correct verifier accepts.
  val relayLogValid: bool = BR.forall(b => verifiesAll(branches.get(b).recs, env.signed))

  // I9. A change in a verified log has the epoch of the log at its position.
  val logChangeEpoch: bool = HON.forall(d => {
    val recs = dev(d).log.recs
    recs.indices().forall(i => {
      val r = recs.nth(i)
      r.kind == Change implies r.epoch == refEpoch(recs.slice(0, i))
    })
  })

  // I10. Limit (T7). Running honest devices hold logs that agree.
  val noFork: bool = tuples(HON, HON).forall(((d1, d2)) =>
    (dev(d1).status == Running and dev(d2).status == Running)
      implies (isPrefix(dev(d1).log.recs, dev(d2).log.recs) or isPrefix(dev(d2).log.recs, dev(d1).log.recs)))

  // I11. Limit (T8). The relay never stores a change with an epoch below a stored
  // epoch record. A stayed device that has not verified the epoch record writes
  // such a change, and a relay that withholds the record can store it.
  val noStaleChangeStored: bool = not(env.staleStored)

  // ---------------------------------------------------------------- witnesses

  def happened(e: Event): bool = env.events.contains(e)
  val wGenesis: bool = happened(EvGenesis)
  val wGrant: bool = happened(EvGrantAppended)
  val wEnrolled: bool = happened(EvEnrolled)
  val wRecoveryGrant: bool = happened(EvRecoveryGrant)
  val wRemoval: bool = happened(EvRemovalAppended)
  val wEpochVerified: bool = happened(EvEpochVerified)
  val wNewEpochChange: bool = happened(EvNewEpochChange)
  val wRefusedBaseRule: bool = happened(EvRefusedBaseRule)
  val wRefusedRemoved: bool = happened(EvRefusedAuthor)
  val wThiefSigned: bool = happened(EvThiefSigned)
  val wForkBranch: bool = happened(EvForkBranch)
  val wForkDetected: bool = happened(EvForkDetected)
  val wForged: bool = happened(EvForged)
  val wForgedRejected: bool = happened(EvForgedRejected)
  val wReplayed: bool = happened(EvReplayed)
  val wStaleWrite: bool = happened(EvStaleWrite)
  // A relay stored a change under an old epoch (T8 limit, a relay that withholds the epoch record).
  val wStaleStored: bool = env.staleStored
  // A device stopped on a record that is not a fork, for example a record from a removed device.
  val wDeviceRejected: bool = happened(EvDeviceRejected)
}
