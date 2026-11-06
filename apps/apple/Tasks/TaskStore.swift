import Foundation
import Snailfish

/// The app ID that the genesis record names. The Python demo uses the same
/// ID and change format, so a demo device and this app can share a space.
let appID = "com.example.tasks"
let changeFormat = 1
let fields = ["title", "done"]
let batchSize: UInt32 = 500

/// A hybrid logical clock value with the device ID as the tie-break. The
/// field order is the merge order ([MRG-2]).
struct Stamp: Comparable, Equatable {
    var wall: Int64
    var counter: Int64
    var device: String

    static func < (a: Stamp, b: Stamp) -> Bool {
        (a.wall, a.counter, a.device) < (b.wall, b.counter, b.device)
    }
}

/// One change: one field of one task, in the JSON form of the demo.
struct TaskChange: Equatable {
    var task: String
    var field: String
    var value: JSONValue
    var stamp: Stamp

    /// The change bytes: JSON with sorted keys and no spaces, as the demo
    /// writes them.
    func encode() -> Data {
        let body: [String: Any] = [
            "v": changeFormat, "task": task, "field": field, "value": value.any,
            "hlc": [stamp.wall, stamp.counter, stamp.device],
        ]
        // Sorted keys and no whitespace are the defaults of this call.
        return try! JSONSerialization.data(withJSONObject: body, options: [.sortedKeys, .withoutEscapingSlashes, .fragmentsAllowed])
    }

    /// Read the bytes of one change.
    ///
    /// - Throws: `UnknownFormat` for an app format that this app cannot read
    ///   ([DLV-14]).
    static func decode(_ b: Data) throws -> TaskChange {
        guard let d = try JSONSerialization.jsonObject(with: b, options: [.fragmentsAllowed]) as? [String: Any],
            d["v"] as? Int == changeFormat, let field = d["field"] as? String, fields.contains(field),
            let task = d["task"] as? String, let hlc = d["hlc"] as? [Any], hlc.count == 3,
            let wall = (hlc[0] as? NSNumber)?.int64Value, let counter = (hlc[1] as? NSNumber)?.int64Value,
            let device = hlc[2] as? String
        else { throw UnknownFormat() }
        return TaskChange(
            task: task, field: field, value: JSONValue(any: d["value"] ?? NSNull()),
            stamp: Stamp(wall: wall, counter: counter, device: device))
    }
}

struct UnknownFormat: Error, CustomStringConvertible {
    var description: String { "a change with an app format that this app cannot read" }
}

/// The two value types of a task field.
enum JSONValue: Equatable {
    case string(String)
    case bool(Bool)
    case null

    init(any: Any) {
        if let n = any as? NSNumber, CFGetTypeID(n) == CFBooleanGetTypeID() {
            self = .bool(n.boolValue)
        } else if let s = any as? String {
            self = .string(s)
        } else {
            self = .null
        }
    }

    var any: Any {
        switch self {
        case .string(let s): return s
        case .bool(let b): return b
        case .null: return NSNull()
        }
    }

    /// The JSON text form that the `fields` table stores.
    var json: String {
        String(decoding: try! JSONSerialization.data(withJSONObject: any, options: [.fragmentsAllowed]), as: UTF8.self)
    }

    init(json: String) {
        let v = try? JSONSerialization.jsonObject(with: Data(json.utf8), options: [.fragmentsAllowed])
        self.init(any: v ?? NSNull())
    }
}

/// One task for the UI.
struct TaskItem: Identifiable, Equatable {
    var id: String
    var title: String
    var done: Bool
}

/// The task data and its merge rules, on the app database. The methods
/// follow `Device` in demo/src/snailfish_demo/app.py.
final class TaskStore {
    let db: AppDatabase
    /// The device ID of the stamps. Before sync, a random local ID.
    var deviceID: String
    var now: () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) }

    init(db: AppDatabase, deviceID: String) {
        self.db = db
        self.deviceID = deviceID
    }

    /// Advance the hybrid logical clock for a local edit.
    func tick() throws -> Stamp {
        let row = try db.query("SELECT wall, counter FROM clock").first
        let (wall, counter) = (row?.int(0) ?? 0, row?.int(1) ?? 0)
        let now = now()
        let s =
            now > wall
            ? Stamp(wall: now, counter: 0, device: deviceID)
            : Stamp(wall: wall, counter: counter + 1, device: deviceID)
        try saveClock(s)
        return s
    }

    /// Move the clock past a remote stamp.
    func observe(_ s: Stamp) throws {
        let row = try db.query("SELECT wall, counter FROM clock").first
        let (wall, counter) = (row?.int(0) ?? 0, row?.int(1) ?? 0)
        if (s.wall, s.counter) > (wall, counter) {
            try saveClock(Stamp(wall: s.wall, counter: s.counter, device: deviceID))
        }
    }

    private func saveClock(_ s: Stamp) throws {
        try db.query(
            "INSERT INTO clock (id, wall, counter) VALUES (1, ?, ?) "
                + "ON CONFLICT (id) DO UPDATE SET wall = excluded.wall, counter = excluded.counter",
            [.int(s.wall), .int(s.counter)])
    }

    /// Apply one field change if its stamp is newer ([MRG-2]).
    func merge(_ c: TaskChange) throws {
        if let row = try db.query(
            "SELECT wall, counter, device FROM fields WHERE task = ? AND field = ?", [.text(c.task), .text(c.field)]
        ).first, Stamp(wall: row.int(0), counter: row.int(1), device: row.text(2)) >= c.stamp {
            return
        }
        try db.query(
            "INSERT INTO fields (task, field, value, wall, counter, device) VALUES (?, ?, ?, ?, ?, ?) "
                + "ON CONFLICT (task, field) DO UPDATE SET value = excluded.value, wall = excluded.wall, "
                + "counter = excluded.counter, device = excluded.device",
            [
                .text(c.task), .text(c.field), .text(c.value.json), .int(c.stamp.wall), .int(c.stamp.counter),
                .text(c.stamp.device),
            ])
    }

    /// Apply an edit, and write its outbox row in the same transaction if
    /// `changeID` is set ([DLV-2]). Before sync, the app has no outbox.
    func edit(task: String, field: String, value: JSONValue, changeID: Data?) throws {
        precondition(fields.contains(field))
        try db.transaction {
            let c = TaskChange(task: task, field: field, value: value, stamp: try tick())
            try merge(c)
            if let changeID {
                try addOutbox(changeID, c.encode())
            }
        }
    }

    func addOutbox(_ changeID: Data, _ bytes: Data) throws {
        let seq = try db.query("SELECT coalesce(max(seq), 0) + 1 FROM outbox").first?.int(0) ?? 1
        try db.query(
            "INSERT INTO outbox (change_id, change_bytes, seq) VALUES (?, ?, ?)",
            [.blob(changeID), .blob(bytes), .int(seq)])
    }

    /// Write an outbox row for each field that exists ([MRG-5]). The caller
    /// runs it in the transaction that turns on sync.
    func outboxEveryField(newChangeID: () throws -> Data) throws {
        for r in try db.query("SELECT task, field, value, wall, counter, device FROM fields ORDER BY task, field") {
            let c = TaskChange(
                task: r.text(0), field: r.text(1), value: JSONValue(json: r.text(2)),
                stamp: Stamp(wall: r.int(3), counter: r.int(4), device: r.text(5)))
            try addOutbox(try newChangeID(), c.encode())
        }
    }

    /// The app state with its merge metadata, in the snapshot form of the
    /// demo ([CMP-2], [MRG-4]): `{"v":1,"fields":[[task, field, value JSON,
    /// wall, counter, device], ...]}`, sorted by task and field.
    func exportState() throws -> Data {
        let rows: [[Any]] = try db.query(
            "SELECT task, field, value, wall, counter, device FROM fields ORDER BY task, field"
        ).map { [$0.text(0), $0.text(1), $0.text(2), $0.int(3), $0.int(4), $0.text(5)] }
        let body: [String: Any] = ["v": changeFormat, "fields": rows]
        return try JSONSerialization.data(withJSONObject: body, options: [.withoutEscapingSlashes])
    }

    /// Check a snapshot state without a change to the app database ([CMP-2]).
    static func canImport(_ state: Data) -> Bool {
        (try? parseState(state)) != nil
    }

    private static func parseState(_ state: Data) throws -> [(TaskChange, String)] {
        guard let d = try JSONSerialization.jsonObject(with: state) as? [String: Any],
            d["v"] as? Int == changeFormat, let rows = d["fields"] as? [[Any]]
        else { throw UnknownFormat() }
        return try rows.map { r in
            guard r.count == 6, let task = r[0] as? String, let field = r[1] as? String, fields.contains(field),
                let value = r[2] as? String,
                (try? JSONSerialization.jsonObject(with: Data(value.utf8), options: [.fragmentsAllowed])) != nil,
                let wall = (r[3] as? NSNumber)?.int64Value, let counter = (r[4] as? NSNumber)?.int64Value,
                let device = r[5] as? String
            else { throw UnknownFormat() }
            let c = TaskChange(
                task: task, field: field, value: JSONValue(json: value),
                stamp: Stamp(wall: wall, counter: counter, device: device))
            return (c, value)
        }
    }

    /// Replace the synced data with a snapshot state, inside the caller's
    /// transaction ([CMP-2]).
    func importState(_ state: Data) throws {
        try db.exec("DELETE FROM fields;")
        for (c, value) in try Self.parseState(state) {
            try db.query(
                "INSERT INTO fields (task, field, value, wall, counter, device) VALUES (?, ?, ?, ?, ?, ?)",
                [.text(c.task), .text(c.field), .text(value), .int(c.stamp.wall), .int(c.stamp.counter), .text(c.stamp.device)])
            try observe(c.stamp)
        }
    }

    func outboxRows() throws -> [OutboxRow] {
        try db.query("SELECT change_id, change_bytes FROM outbox ORDER BY seq").map {
            OutboxRow(changeId: $0.blob(0), changeBytes: $0.blob(1))
        }
    }

    func applied() throws -> Applied? {
        try db.query("SELECT position, digest FROM applied").first.map {
            Applied(position: UInt64($0.int(0)), digest: $0.blob(1))
        }
    }

    func tasks() throws -> [TaskItem] {
        var out: [String: TaskItem] = [:]
        for r in try db.query("SELECT task, field, value FROM fields ORDER BY task, field") {
            var t = out[r.text(0)] ?? TaskItem(id: r.text(0), title: "", done: false)
            switch (r.text(1), JSONValue(json: r.text(2))) {
            case ("title", .string(let s)): t.title = s
            case ("done", .bool(let b)): t.done = b
            default: break
            }
            out[t.id] = t
        }
        return out.values.sorted { $0.id < $1.id }
    }
}
