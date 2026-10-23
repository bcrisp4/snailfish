// Mutants of delivery.qnt. Each m_* module binds one BUG value. Each base_*
// module binds the same consts with BUG = "none". specs/check.sh requires that
// each base passes its invariant list and that each mutant fails it.
//
// base_restore: an honest relay that the relay operator can restore.
// base_fork: a silent rollback, so that forks can occur.
// base_engine: engine state loss and a relay restore, so that ResetRequired occurs
// and a hold release can lose a change (F3).


module base_restore {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4, MAX_FAULTS = 2, FAULTS = Set("appRestore", "relayRestore"),
                  BUG = "none").* from "./delivery"
}

module base_fork {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4, MAX_FAULTS = 2, FAULTS = Set("silentRollback", "appRestore"),
                  BUG = "none").* from "./delivery"
}

module base_engine {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4, MAX_FAULTS = 2, FAULTS = Set("engineLoss", "relayRestore", "warnedRelease"),
                  BUG = "none").* from "./delivery"
}

module m_editSplitTxn {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4, MAX_FAULTS = 2, FAULTS = Set("appRestore", "relayRestore"),
                  BUG = "editSplitTxn").* from "./delivery"
}

module m_appDropsRowOnEnqueue {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4, MAX_FAULTS = 2, FAULTS = Set("appRestore", "relayRestore"),
                  BUG = "appDropsRowOnEnqueue").* from "./delivery"
}

module m_engineDropsOnAccept {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4, MAX_FAULTS = 2, FAULTS = Set("appRestore", "relayRestore"),
                  BUG = "engineDropsOnAccept").* from "./delivery"
}

module m_relayNoDedupe {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4, MAX_FAULTS = 2, FAULTS = Set("appRestore", "relayRestore"),
                  BUG = "relayNoDedupe").* from "./delivery"
}

module m_sizeBeforeDedupe {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4, MAX_FAULTS = 2, FAULTS = Set("appRestore", "relayRestore"),
                  BUG = "sizeBeforeDedupe").* from "./delivery"
}

module m_pullSplitTxn {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4, MAX_FAULTS = 2, FAULTS = Set("appRestore", "relayRestore"),
                  BUG = "pullSplitTxn").* from "./delivery"
}

module m_noRepair {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4, MAX_FAULTS = 2, FAULTS = Set("appRestore", "relayRestore"),
                  BUG = "noRepair").* from "./delivery"
}

module m_noHold {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4, MAX_FAULTS = 2, FAULTS = Set("appRestore", "relayRestore"),
                  BUG = "noHold").* from "./delivery"
}

module m_adoptFork {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4, MAX_FAULTS = 2, FAULTS = Set("silentRollback", "appRestore"),
                  BUG = "adoptFork").* from "./delivery"
}

module m_resetDropsOutbox {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4, MAX_FAULTS = 2, FAULTS = Set("engineLoss", "relayRestore", "warnedRelease"),
                  BUG = "resetDropsOutbox").* from "./delivery"
}

module m_enqueueChecksSize {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4, MAX_FAULTS = 2, FAULTS = Set("engineLoss"),
                  BUG = "enqueueChecksSize").* from "./delivery"
}

module m_noAheadReset {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4, MAX_FAULTS = 2, FAULTS = Set("engineLoss", "relayRestore", "warnedRelease"),
                  BUG = "noAheadReset").* from "./delivery"
}

module m_releaseIgnoresFresh {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4, MAX_FAULTS = 2, FAULTS = Set("engineLoss", "relayRestore", "warnedRelease"),
                  BUG = "releaseIgnoresFresh").* from "./delivery"
}

module m_freshClearsOnFetch {
  import delivery(DEVS = Set(1, 2), MAX_IDS = 4, MAX_FAULTS = 2, FAULTS = Set("engineLoss", "relayRestore", "warnedRelease"),
                  BUG = "freshClearsOnFetch").* from "./delivery"
}
