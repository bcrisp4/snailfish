import Foundation
import SQLite3

/// The app database: the tasks, the app outbox, the applied position and the
/// clock (DESIGN.md "App integration"). The schema is the schema of the
/// Python demo (demo/src/snailfish_demo/app.py), so both apps meet the same
/// delivery rules.
///
/// The database uses WAL with `synchronous=FULL` and `fullfsync=ON`
/// ([DLV-1]). One connection, used from one actor.
final class AppDatabase {
    struct SQLiteError: Error, CustomStringConvertible {
        let code: Int32
        let message: String
        var description: String { "sqlite \(code): \(message)" }
    }

    private var db: OpaquePointer?

    init(path: String) throws {
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil) == SQLITE_OK else {
            let e = SQLiteError(code: sqlite3_errcode(db), message: String(cString: sqlite3_errmsg(db)))
            sqlite3_close(db)
            throw e
        }
        try exec("PRAGMA journal_mode=WAL")
        try exec("PRAGMA synchronous=FULL")
        try exec("PRAGMA fullfsync=ON")
        try exec(Self.schema)
    }

    deinit { sqlite3_close(db) }

    static let schema = """
        CREATE TABLE IF NOT EXISTS fields (
          task TEXT NOT NULL, field TEXT NOT NULL, value TEXT NOT NULL,
          wall INTEGER NOT NULL, counter INTEGER NOT NULL, device TEXT NOT NULL,
          PRIMARY KEY (task, field)
        );
        CREATE TABLE IF NOT EXISTS outbox (
          change_id BLOB PRIMARY KEY, change_bytes BLOB NOT NULL, seq INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS applied (
          id INTEGER PRIMARY KEY CHECK (id = 1), position INTEGER NOT NULL, digest BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS clock (
          id INTEGER PRIMARY KEY CHECK (id = 1), wall INTEGER NOT NULL, counter INTEGER NOT NULL
        );
        """

    func exec(_ sql: String) throws {
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw error() }
    }

    private func error() -> SQLiteError {
        SQLiteError(code: sqlite3_errcode(db), message: String(cString: sqlite3_errmsg(db)))
    }

    /// A bound value of one statement.
    enum Value {
        case int(Int64)
        case text(String)
        case blob(Data)
        case null
    }

    /// One result row.
    struct Row {
        fileprivate let values: [Value]

        func int(_ i: Int) -> Int64 {
            if case .int(let v) = values[i] { return v }
            return 0
        }

        func text(_ i: Int) -> String {
            if case .text(let v) = values[i] { return v }
            return ""
        }

        func blob(_ i: Int) -> Data {
            if case .blob(let v) = values[i] { return v }
            return Data()
        }
    }

    // SQLite copies each text and blob at bind time with this destructor.
    private static let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    @discardableResult
    func query(_ sql: String, _ args: [Value] = []) throws -> [Row] {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { throw error() }
        defer { sqlite3_finalize(stmt) }
        for (i, a) in args.enumerated() {
            let n = Int32(i + 1)
            let rc: Int32
            switch a {
            case .int(let v): rc = sqlite3_bind_int64(stmt, n, v)
            case .text(let v): rc = sqlite3_bind_text(stmt, n, v, -1, Self.transient)
            case .blob(let v):
                rc = v.withUnsafeBytes { sqlite3_bind_blob(stmt, n, $0.baseAddress, Int32(v.count), Self.transient) }
            case .null: rc = sqlite3_bind_null(stmt, n)
            }
            guard rc == SQLITE_OK else { throw error() }
        }
        var rows: [Row] = []
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW else { throw error() }
            var values: [Value] = []
            for c in 0..<sqlite3_column_count(stmt) {
                switch sqlite3_column_type(stmt, c) {
                case SQLITE_INTEGER: values.append(.int(sqlite3_column_int64(stmt, c)))
                case SQLITE_TEXT: values.append(.text(String(cString: sqlite3_column_text(stmt, c))))
                case SQLITE_BLOB:
                    let n = Int(sqlite3_column_bytes(stmt, c))
                    let p = sqlite3_column_blob(stmt, c)
                    values.append(.blob(p.map { Data(bytes: $0, count: n) } ?? Data()))
                default: values.append(.null)
                }
            }
            rows.append(Row(values: values))
        }
        return rows
    }

    /// Run `body` in one `BEGIN IMMEDIATE` transaction, and commit durably.
    /// An error rolls the transaction back.
    func transaction<T>(_ body: () throws -> T) throws -> T {
        try exec("BEGIN IMMEDIATE")
        do {
            let r = try body()
            try exec("COMMIT")
            return r
        } catch {
            try? exec("ROLLBACK")
            throw error
        }
    }
}
