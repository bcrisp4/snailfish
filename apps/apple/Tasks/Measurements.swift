import Foundation
import SQLite3

/// The M6 measurements, as JSON lines in `measure.jsonl` (DESIGN.md M6,
/// C44, [DLV-3]).
///
/// - `edit`: a local edit, with its change ID and wall time in ms.
/// - `arrival`: a change of another device that a pull applied. The delay
///   is the arrival time minus the wall time of the edit, from the hybrid
///   logical clock of the change. Both clocks follow NTP, so the delay has
///   the error of the two clocks.
/// - `refresh`: one iOS background refresh, with its start and end time.
/// - `commit`: the result of a durable commit benchmark.
///
/// The log is a measurement aid, not app state: a write failure loses a
/// line and does not stop sync.
final class Measurements: @unchecked Sendable {
    let file: URL
    private let lock = NSLock()

    init(file: URL) {
        self.file = file
    }

    static func nowMs() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    func write(_ fields: [String: Any]) {
        guard let line = try? JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys]) else { return }
        lock.withLock {
            if !FileManager.default.fileExists(atPath: file.path) {
                FileManager.default.createFile(atPath: file.path, contents: nil)
            }
            guard let h = try? FileHandle(forWritingTo: file) else { return }
            defer { try? h.close() }
            _ = try? h.seekToEnd()
            try? h.write(contentsOf: line + Data("\n".utf8))
        }
    }

    func edit(changeID: Data) {
        write(["kind": "edit", "change_id": changeID.hex, "t_ms": Self.nowMs()])
    }

    func arrival(changeID: Data, editWallMs: Int64, background: Bool) {
        let now = Self.nowMs()
        write([
            "kind": "arrival", "change_id": changeID.hex, "edit_ms": editWallMs, "t_ms": now,
            "delay_ms": now - editWallMs, "background": background,
        ])
    }

    func refresh(startMs: Int64, endMs: Int64, result: String) {
        write(["kind": "refresh", "start_ms": startMs, "end_ms": endMs, "result": result])
    }

    func lines() -> [[String: Any]] {
        guard let data = try? Data(contentsOf: file) else { return [] }
        return data.split(separator: UInt8(ascii: "\n")).compactMap {
            try? JSONSerialization.jsonObject(with: Data($0)) as? [String: Any]
        }
    }

    /// A short summary of the arrival delays, for the UI.
    func summary() -> String {
        let delays = lines().filter { $0["kind"] as? String == "arrival" && $0["background"] as? Bool == true }
            .compactMap { ($0["delay_ms"] as? NSNumber)?.int64Value }.sorted()
        guard !delays.isEmpty else { return "no background arrivals yet" }
        let median = delays[delays.count / 2]
        return "background arrivals: \(delays.count), median delay \(median / 1000) s, max \(delays.last! / 1000) s"
    }
}

extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}

/// The durable commit cost of [DLV-3]: one row insert for each commit, on
/// a new SQLite file in `dir`, with WAL, `synchronous=FULL` and
/// `fullfsync=ON` ([DLV-1]). Returns the commit times in ms.
func commitBenchmark(dir: URL, commits: Int) throws -> [Double] {
    let path = dir.appendingPathComponent("bench-\(UUID().uuidString).sqlite3").path
    defer {
        for s in ["", "-wal", "-shm"] { try? FileManager.default.removeItem(atPath: path + s) }
    }
    let db = try AppDatabase(path: path)
    try db.exec("CREATE TABLE bench (id INTEGER PRIMARY KEY, body BLOB NOT NULL)")
    let body = Data(repeating: 0xab, count: 200)
    var times: [Double] = []
    for _ in 0..<commits {
        let t0 = DispatchTime.now().uptimeNanoseconds
        try db.transaction { try db.query("INSERT INTO bench (body) VALUES (?)", [.blob(body)]) }
        times.append(Double(DispatchTime.now().uptimeNanoseconds - t0) / 1e6)
    }
    return times
}

/// Run the benchmark and write its result to the measurement log.
func runCommitBenchmark(dir: URL, log: Measurements, commits: Int = 500) throws -> String {
    let t = try commitBenchmark(dir: dir, commits: commits).sorted()
    let p = { (q: Double) in t[min(t.count - 1, Int(Double(t.count) * q))] }
    var info = utsname()
    uname(&info)
    let machine = withUnsafeBytes(of: &info.machine) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
    log.write([
        "kind": "commit", "commits": t.count, "median_ms": p(0.5), "p95_ms": p(0.95), "max_ms": t.last ?? 0,
        "machine": machine, "os": ProcessInfo.processInfo.operatingSystemVersionString,
        "sqlite": String(cString: sqlite3_libversion()), "t_ms": Measurements.nowMs(),
    ])
    return String(format: "%d durable commits on %@: median %.2f ms, p95 %.2f ms", t.count, machine, p(0.5), p(0.95))
}
