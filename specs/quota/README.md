# Quota model

This model checks the space quota on the relay and the outbox of each device (DESIGN.md S7 and "Quotas", [QTA-1] to [QTA-4]).

It uses one space and two devices. A record has an ID, a kind (change or security record) and a size of 1 or 2. Each device holds an outbox and a fetched log.

## Coverage

| Rule | Model behaviour | Scenario |
| --- | --- | --- |
| `[QTA-1]` | The relay refuses a change that takes the stored change bytes past the quota, and stores nothing. | `fullQuotaKeepsOutboxTest` |
| `[QTA-2]` | A fetch at a full quota returns the stored log. | `fetchAtFullQuotaTest` |
| `[QTA-3]` | A security record does not count, and the relay stores it at a full quota. | `securityAtFullQuotaTest` |
| `[QTA-4]` | After `quota`, the engine keeps the record in its outbox and reports `paused: quota`. A push after a larger quota stores it and ends the pause. | `fullQuotaKeepsOutboxTest`, `raiseStoresQueuedTest` |
| `[DLV-7]` | A known record is `Known`, also at a full quota. | `knownBeforeQuotaTest` |
| `[STO-15]` | Security records count against the reserve. The relay refuses a security record past the reserve, or past the daily limit of its author. Both refusals are transient. | `thiefLimitedTest` |
| `[STO-12]` (part) | After the block, the relay refuses every request of the thief. | `thiefLimitedTest` |

## Invariants

| Name | Property | Mutant |
| --- | --- | --- |
| `withinQuota` | The stored change bytes never exceed the quota. | `noQuota` |
| `noLostChange` | Each record that a device made is in the relay log or in the outbox of its device. | `quotaDrops` |
| `servesStored` | No fetch is refused for quota. | `quotaBlocksFetch` |
| `securityNotBlocked` | No security record is refused for quota. | `quotaBlocksSecurity` |
| `quotaReported` | Each quota refusal sets `paused: quota`. | `quotaNoPause` |
| `withinReserve` | The stored security records never exceed the reserve. | `noReserve` (config `reserveSmall`) |
| `honestSecurityStored` | T10: the relay never refuses the security record of an honest device. The thief config has a reserve that holds the daily limit of the thief and one removal. | `noSecurityLimit` |

The six witnesses are a thief at its daily limit, a removal after a flood, a quota refusal, a security record at a full quota, a store after a quota raise and a fetch at a full quota.

## Results

`make verify MODEL=quota` samples each config, each mutant and each witness. `make verify-deep MODEL=quota` runs Apalache to 6 steps and TLC on the `tiny` config. The results of the M5 run are in the pull request.

## Not covered

- Log compaction. Stubs do not count against the quota, and compaction lowers the usage (S7). The model has only the operator quota raise. Compaction comes with M8.
- The day boundary of the daily limit. One run is one relay day.
- The 16 MiB default. The thief config scales the reserve to the limit.
- The space count limit ([QTA-5], `specs/coverage.toml`).
- The other append checks: signatures, bases, epochs and the restore hold. Other models check them.
- Concurrent appends. The relay checks each append in one transaction ([STO-11]), so one action is one append.
- Liveness.

## Rust conformance (M5)

| Model scenario | Rust and demo tests |
| --- | --- |
| `fullQuotaKeepsOutboxTest`, `raiseStoresQueuedTest` | `crates/engine/src/tests.rs::quota_refusal_keeps_the_outbox_and_pauses`, `demo/tests/test_users.py::test_full_quota_pauses_sync_and_serves_stored_changes` |
| `fetchAtFullQuotaTest` | `crates/relay/tests/user.rs::full_quota_refuses_changes_and_serves_fetches` |
| `securityAtFullQuotaTest` | `crates/relay/tests/user.rs::full_quota_stores_a_grant` |
| `knownBeforeQuotaTest` | `crates/relay/tests/user.rs::full_quota_answers_known_for_a_retry` |
