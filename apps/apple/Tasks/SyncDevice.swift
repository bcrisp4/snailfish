import Foundation
import Snailfish

/// One device of the task app: the app database, the engine and the
/// delivery loop of DESIGN.md "App integration". It follows `Device` in
/// demo/src/snailfish_demo/app.py.
///
/// The layout of the data directory:
///
/// - `app.sqlite3`: the tasks, the app outbox and the applied position.
/// - `engine/`: the engine state. Excluded from backups, so a state file
///   never arrives on a device without its keys (T14).
/// - `space.json`: the space reference, after sync is on.
/// - `measure.jsonl`: the sync delay log (`Measurements`), unless the
///   caller puts the log in another place.
///
/// The keys are in the key store, never in this directory.
actor SyncDevice {
    let root: URL
    let keyStore: KeyStore
    let store: TaskStore
    let measurements: Measurements
    private(set) var space: SpaceRef?
    private(set) var engine: Engine?
    /// The change IDs that the engine refused, for the user ([DLV-5]).
    private(set) var refused: [Data] = []
    private(set) var repairs: [Repair] = []

    nonisolated var engineDir: URL { root.appendingPathComponent("engine", isDirectory: true) }
    private nonisolated var spaceFile: URL { root.appendingPathComponent("space.json") }

    init(root: URL, keyStore: KeyStore, measurements: Measurements? = nil) throws {
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        self.root = root
        self.keyStore = keyStore
        let db = try AppDatabase(path: root.appendingPathComponent("app.sqlite3").path)
        store = TaskStore(db: db, deviceID: try Self.localID(root))
        self.measurements = measurements ?? Measurements(file: root.appendingPathComponent("measure.jsonl"))
        if let data = try? Data(contentsOf: root.appendingPathComponent("space.json")) {
            let sp = try JSONDecoder().decode(SpaceFile.self, from: data).ref
            space = sp
            let e = try Engine.open(dataDir: engineDir.path, space: sp, keyStore: keyStore)
            engine = e
            store.deviceID = try e.deviceId()
        }
        try excludeEngineFromBackup()
        // [DLV-2]: give the outbox rows to the engine at every startup.
        flushOutbox()
    }

    /// The device ID of the stamps before sync: random, kept in a file.
    private static func localID(_ root: URL) throws -> String {
        let f = root.appendingPathComponent("local-id")
        if let s = try? String(contentsOf: f, encoding: .utf8) { return s }
        var b = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, b.count, &b) == errSecSuccess else {
            throw CocoaError(.fileWriteUnknown)
        }
        let s = "local_" + b.map { String(format: "%02x", $0) }.joined()
        try s.write(to: f, atomically: true, encoding: .utf8)
        return s
    }

    private func excludeEngineFromBackup() throws {
        try FileManager.default.createDirectory(at: engineDir, withIntermediateDirectories: true)
        var url = engineDir
        var v = URLResourceValues()
        v.isExcludedFromBackup = true
        try url.setResourceValues(v)
    }

    var syncOn: Bool { engine != nil }

    func tasks() throws -> [TaskItem] { try store.tasks() }

    /// Apply an edit and write its outbox row in one transaction, then give
    /// the outbox to the engine ([DLV-2]).
    func edit(task: String, field: String, value: JSONValue) throws {
        let cid = try engine?.newChangeId()
        try store.edit(task: task, field: field, value: value, changeID: cid)
        if let cid { measurements.edit(changeID: cid) }
        flushOutbox()
    }

    /// The last error of a flush outside a sync, for the UI.
    private(set) var flushError: String?

    /// `flushOutboxNow` after an edit or at startup. The rows stay in the app
    /// outbox on an error, and the next flush gives them to the engine
    /// again. A new device cannot encrypt until its first sync opens the app
    /// key from its grant ([ENR-9]), so an error here is expected then.
    private func flushOutbox() {
        do {
            try flushOutboxNow()
            flushError = nil
        } catch {
            flushError = "\(error)"
        }
    }

    /// Give the outbox rows to the engine, in batches of 500 ([DLV-4]). A
    /// refused change is reverted: the app removes its row ([DLV-5]).
    private func flushOutboxNow() throws {
        guard let engine else { return }
        let rows = try store.outboxRows()
        for i in stride(from: 0, to: rows.count, by: Int(batchSize)) {
            let result = try engine.enqueueMany(rows: Array(rows[i..<min(i + Int(batchSize), rows.count)]))
            for cid in result.refused {
                try store.db.transaction { try store.db.query("DELETE FROM outbox WHERE change_id = ?", [.blob(cid)]) }
                refused.append(cid)
            }
        }
    }

    /// Exchange with the relay, then pull. Returns the engine status.
    func sync(_ transport: Transport, background: Bool = false) async throws -> Status {
        guard let engine else { throw SetupError.syncOff }
        let exchange = try engine.startSync()
        while let req = try exchange.nextRequest() {
            let (status, headers, body) = try await transport.send(req)
            try exchange.handleResponse(status: status, headers: headers, body: body)
        }
        repairs = try engine.takeRepairs()
        try pull(background: background)
        try flushOutboxNow()
        return try engine.status()
    }

    /// Apply the changes after the applied position ([DLV-10], [DLV-11]).
    /// Each batch is one durable transaction, and the position check is
    /// inside it, so a crash between batches applies no change twice.
    @discardableResult
    func pull(background: Bool = false) throws -> Int {
        guard let engine else { return 0 }
        var applied = 0
        while true {
            let at = try store.applied() ?? engine.genesisBase()
            let batch: [Change]
            do {
                batch = try engine.changesAfter(applied: at, maxChanges: batchSize)
            } catch SnailfishError.ResetRequired {
                try reset()
                continue
            }
            if batch.isEmpty { return applied }
            var arrived: [(Data, Int64)] = []
            try store.db.transaction {
                for c in batch {
                    let pos = try store.applied()?.position ?? 0
                    if c.position <= pos { continue }
                    let own = try store.db.query("SELECT 1 FROM outbox WHERE change_id = ?", [.blob(c.changeId)])
                    if !own.isEmpty {
                        try store.db.query("DELETE FROM outbox WHERE change_id = ?", [.blob(c.changeId)])
                    } else {
                        let ch = try TaskChange.decode(c.changeBytes)
                        try store.observe(ch.stamp)
                        try store.merge(ch)
                        arrived.append((c.changeId, ch.stamp.wall))
                        applied += 1
                    }
                    try store.db.query(
                        "INSERT INTO applied (id, position, digest) VALUES (1, ?, ?) "
                            + "ON CONFLICT (id) DO UPDATE SET position = excluded.position, digest = excluded.digest",
                        [.int(Int64(c.position)), .blob(c.digest)])
                }
            }
            for (cid, wall) in arrived {
                measurements.arrival(changeID: cid, editWallMs: wall, background: background)
            }
        }
    }

    /// `ResetRequired`: delete the synced data, apply each outbox row again,
    /// and pull from the start ([DLV-12]). M6 has no snapshot.
    private func reset() throws {
        try store.db.transaction {
            try store.db.exec("DELETE FROM fields; DELETE FROM applied;")
            for r in try store.outboxRows() {
                try store.merge(try TaskChange.decode(r.changeBytes))
            }
        }
    }

    func statusText() throws -> String {
        guard let engine else { return "sync off" }
        let s = try engine.status()
        switch s {
        case .degraded(let cause), .fork(let cause), .setupFailed(let cause):
            return "\(Snailfish.statusText(status: s)): \(cause)"
        default:
            return Snailfish.statusText(status: s)
        }
    }

    // MARK: Setup

    /// Turn on sync on the first device (S1). The engine writes its state
    /// and the keys. The app then writes an outbox row for each field that
    /// exists, in one transaction ([MRG-5]), and the next sync creates the
    /// space on the relay.
    func turnOnSync(space sp: SpaceRef, keys: DeviceKeys, envelopes: [String], setupToken: String) throws {
        try installSetup(
            dataDir: engineDir.path, space: sp, keys: keys, envelopes: envelopes, setupToken: setupToken,
            keyStore: keyStore)
        let e = try openEngine(sp)
        try store.db.transaction {
            // Rows of an earlier space that the relay refused to create.
            try store.db.exec("DELETE FROM outbox; DELETE FROM applied;")
            try store.outboxEveryField { try e.newChangeId() }
        }
        flushOutbox()
    }

    /// Finish the enrollment of a new device (S2). The engine state comes
    /// first, so no stored keys exist without the checkpoint ([ENR-9]).
    /// The tasks of the device before sync get outbox rows ([MRG-5]). The
    /// engine takes them after the first sync opens the app key.
    func finishJoin(space sp: SpaceRef, keys: DeviceKeys, joined: Joined) throws {
        try installEnrollment(dataDir: engineDir.path, space: sp, keys: keys, joined: joined, keyStore: keyStore)
        let e = try openEngine(sp)
        try store.db.transaction {
            try store.db.exec("DELETE FROM outbox; DELETE FROM applied;")
            try store.outboxEveryField { try e.newChangeId() }
        }
    }

    @discardableResult
    private func openEngine(_ sp: SpaceRef) throws -> Engine {
        let e = try Engine.open(dataDir: engineDir.path, space: sp, keyStore: keyStore)
        try JSONEncoder().encode(SpaceFile(sp)).write(to: spaceFile, options: .atomic)
        space = sp
        engine = e
        store.deviceID = try e.deviceId()
        return e
    }

    /// Leave a space that the relay refused to create (`stopped: setup
    /// failed`). The relay holds no record of it, so the app deletes the
    /// engine state and the user turns on sync again. The app keeps its
    /// tasks, and the next `turnOnSync` writes their outbox rows again.
    func leaveFailedSetup() throws {
        engine = nil
        space = nil
        try? FileManager.default.removeItem(at: spaceFile)
        try FileManager.default.removeItem(at: engineDir)
        try excludeEngineFromBackup()
    }
}

enum SetupError: Error, CustomStringConvertible {
    case syncOff
    case cancelled
    case message(String)

    var description: String {
        switch self {
        case .syncOff: return "sync is off"
        case .cancelled: return "cancelled"
        case .message(let m): return m
        }
    }
}

/// The JSON form of `space.json`, with the field names of the demo.
struct SpaceFile: Codable {
    var relay_url: String
    var tenant: String
    var log_id: String
    var app_id: String

    init(_ s: SpaceRef) {
        relay_url = s.relayUrl
        tenant = s.tenant
        log_id = s.logId
        app_id = s.appId
    }

    var ref: SpaceRef { SpaceRef(relayUrl: relay_url, tenant: tenant, logId: log_id, appId: app_id) }
}
