module quotaTest {
  import quota(QUOTA = 2, MAX_QUOTA = 3, MAX_RECORDS = 4, BUG = "none").* from "./model"

  // [QTA-1] [QTA-4] S7: a change past the quota is refused. The engine keeps
  // it in its outbox and reports `paused: quota`.
  run fullQuotaKeepsOutboxTest =
    init.then(enqueue(1, Change, 2)).then(push(1))
      .then(enqueue(1, Change, 1)).then(push(1))
      .expect(wQuotaRefused and client(1).paused and client(1).outbox.length() == 1)
      .expect(s.relay.length() == 1 and withinQuota and noLostChange)

  // [QTA-2] The relay serves the stored changes at a full quota.
  run fetchAtFullQuotaTest =
    init.then(enqueue(1, Change, 2)).then(push(1)).then(fetch(2))
      .expect(wFetchedAtFull and client(2).log == List(1) and servesStored)

  // [QTA-3] A security record is stored at a full quota.
  run securityAtFullQuotaTest =
    init.then(enqueue(1, Change, 2)).then(push(1))
      .then(enqueue(2, Security, 1)).then(push(2))
      .expect(wSecurityAtFull and s.relay.length() == 2 and securityNotBlocked)

  // [QTA-4] S7: after the operator raises the quota, the next push stores the
  // queued change and the pause ends.
  run raiseStoresQueuedTest =
    init.then(enqueue(1, Change, 2)).then(push(1))
      .then(enqueue(1, Change, 1)).then(push(1)).then(raise).then(push(1))
      .expect(wStoredAfterRaise and not(client(1).paused) and client(1).outbox.length() == 0)
      .expect(s.relay.length() == 2 and withinQuota)

  // [DLV-7] A retry of a stored change is Known, also at a full quota.
  run knownBeforeQuotaTest =
    init.then(enqueue(1, Change, 2))
      .then(all { s' = { ...s, relay: s.relay.append(client(1).outbox.head()) } })
      .then(push(1))
      .expect(not(wQuotaRefused) and client(1).outbox.length() == 0 and not(client(1).paused))
}
