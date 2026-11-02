import Snailfish
import XCTest

@testable import Tasks

final class DeliveryTests: XCTestCase {
    private var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    /// [DLV-1]: the app database commits durably. Without these settings a
    /// power loss after a commit can lose an edit and its outbox row.
    func testAppDatabaseIsDurable() throws {
        let db = try AppDatabase(path: dir.appendingPathComponent("app.sqlite3").path)
        XCTAssertEqual(try db.query("PRAGMA journal_mode").first?.text(0), "wal")
        XCTAssertEqual(try db.query("PRAGMA synchronous").first?.int(0), 2, "FULL")
        XCTAssertEqual(try db.query("PRAGMA fullfsync").first?.int(0), 1)
    }

    /// The change bytes are the bytes of the Python demo
    /// (`encode_change` in demo/src/snailfish_demo/app.py), so a demo
    /// device and this app can share a space and read each other's changes.
    func testChangeBytesMatchTheDemoFormat() throws {
        let c = TaskChange(
            task: "t1", field: "title", value: .string("a/b \"c\""),
            stamp: Stamp(wall: 1_767_225_600_000, counter: 2, device: "d_x"))
        XCTAssertEqual(
            String(decoding: c.encode(), as: UTF8.self),
            #"{"field":"title","hlc":[1767225600000,2,"d_x"],"task":"t1","v":1,"value":"a/b \"c\""}"#)
        let done = Data(#"{"field":"done","hlc":[5,0,"d_y"],"task":"t2","v":1,"value":true}"#.utf8)
        XCTAssertEqual(
            try TaskChange.decode(done),
            TaskChange(task: "t2", field: "done", value: .bool(true), stamp: Stamp(wall: 5, counter: 0, device: "d_y")))
    }

    /// [DLV-14]: a change with an unknown app format stops the pull. A skip
    /// makes the device diverge.
    func testUnknownFormatIsRefused() {
        let v2 = Data(#"{"field":"title","hlc":[5,0,"d"],"task":"t","v":2,"value":"x"}"#.utf8)
        XCTAssertThrowsError(try TaskChange.decode(v2)) { XCTAssertTrue($0 is UnknownFormat) }
        let field = Data(#"{"field":"colour","hlc":[5,0,"d"],"task":"t","v":1,"value":"x"}"#.utf8)
        XCTAssertThrowsError(try TaskChange.decode(field)) { XCTAssertTrue($0 is UnknownFormat) }
    }

    /// [MRG-2]: the same set of changes in any order gives the same state.
    /// A wall time tie falls to the counter, then to the device ID.
    func testMergeIsOrderIndependent() throws {
        let changes = [
            TaskChange(task: "t", field: "title", value: .string("a"), stamp: Stamp(wall: 10, counter: 0, device: "d_a")),
            TaskChange(task: "t", field: "title", value: .string("b"), stamp: Stamp(wall: 10, counter: 0, device: "d_b")),
            TaskChange(task: "t", field: "title", value: .string("c"), stamp: Stamp(wall: 9, counter: 5, device: "d_c")),
            TaskChange(task: "t", field: "done", value: .bool(true), stamp: Stamp(wall: 8, counter: 0, device: "d_a")),
            TaskChange(task: "t", field: "done", value: .bool(false), stamp: Stamp(wall: 8, counter: 1, device: "d_a")),
        ]
        var results: [[TaskItem]] = []
        for order in [changes, changes.reversed(), [changes[2], changes[4], changes[0], changes[3], changes[1]]] {
            let path = dir.appendingPathComponent(UUID().uuidString).path
            let store = TaskStore(db: try AppDatabase(path: path), deviceID: "d_local")
            for c in order { try store.merge(c) }
            results.append(try store.tasks())
        }
        XCTAssertEqual(results[0], [TaskItem(id: "t", title: "b", done: false)])
        XCTAssertEqual(results[1], results[0])
        XCTAssertEqual(results[2], results[0])
    }

    /// [DLV-2]: an edit and its outbox row commit in one transaction. A
    /// failed edit leaves neither.
    func testEditAndOutboxRowCommitTogether() throws {
        let store = TaskStore(db: try AppDatabase(path: dir.appendingPathComponent("a.sqlite3").path), deviceID: "d")
        try store.edit(task: "t", field: "title", value: .string("x"), changeID: Data(repeating: 1, count: 16))
        XCTAssertEqual(try store.outboxRows().count, 1)
        // The same change ID again breaks the outbox primary key, so the
        // transaction rolls back the field write too.
        XCTAssertThrowsError(
            try store.edit(task: "t", field: "title", value: .string("y"), changeID: Data(repeating: 1, count: 16)))
        XCTAssertEqual(try store.tasks(), [TaskItem(id: "t", title: "x", done: false)])
        XCTAssertEqual(try store.outboxRows().count, 1)
    }

    /// S1, [MRG-5]: an edit before sync has no outbox row. When sync turns
    /// on, each field that exists gets an outbox row with its own stamp.
    func testTurnOnSyncWritesEachFieldOnce() throws {
        let store = TaskStore(db: try AppDatabase(path: dir.appendingPathComponent("a.sqlite3").path), deviceID: "d")
        try store.edit(task: "t1", field: "title", value: .string("milk"), changeID: nil)
        try store.edit(task: "t1", field: "done", value: .bool(true), changeID: nil)
        XCTAssertEqual(try store.outboxRows().count, 0)
        var n: UInt8 = 0
        try store.db.transaction {
            try store.outboxEveryField {
                n += 1
                return Data(repeating: n, count: 16)
            }
        }
        let rows = try store.outboxRows().map { try TaskChange.decode($0.changeBytes) }
        XCTAssertEqual(rows.map(\.field).sorted(), ["done", "title"])
        XCTAssertEqual(rows.first { $0.field == "title" }?.value, .string("milk"))
    }

    /// S1: the recovery key check accepts the reader forms of PROTOCOL.md
    /// section 9 and refuses a different key.
    func testRecoveryKeyCheck() throws {
        let setup = try createSpace(appId: appID, first: NewDevice(keys: try newDeviceKeys(), name: "A"))
        let key = setup.recoveryKey
        XCTAssertTrue(RecoveryCheck.matches(typed: key, shown: key))
        XCTAssertTrue(RecoveryCheck.matches(typed: key.lowercased().replacingOccurrences(of: "-", with: ""), shown: key))
        let other = try createSpace(appId: appID, first: NewDevice(keys: try newDeviceKeys(), name: "A")).recoveryKey
        XCTAssertFalse(RecoveryCheck.matches(typed: other, shown: key))
        XCTAssertFalse(RecoveryCheck.matches(typed: "", shown: key))
    }
}
