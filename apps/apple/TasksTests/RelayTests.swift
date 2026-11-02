import Snailfish
import XCTest

@testable import Tasks

/// A key store in memory, for a macOS build with no keychain entitlement.
final class MemKeyStore: KeyStore, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: Data] = [:]

    func load(account: String) throws -> Data? { lock.withLock { items[account] } }
    func store(account: String, secret: Data) throws { lock.withLock { items[account] = secret } }
    func delete(account: String) throws { _ = lock.withLock { items.removeValue(forKey: account) } }
}

/// The two sides of one enrollment. The device that shows the session puts
/// its QR payload here. Each side answers the code comparison only after
/// both sides show a code, and says yes only if the codes match ([ENR-7]).
actor CodeMatch {
    private var codes: [String: String] = [:]
    private(set) var payload: String?

    func show(_ p: String) { payload = p }

    func compare(_ side: String, _ code: String) async -> Bool {
        codes[side] = code
        while codes.count < 2, !Task.isCancelled {
            try? await Task.sleep(nanoseconds: 50_000_000)
        }
        return codes.count == 2 && Set(codes.values).count == 1
    }

    /// Wait for the QR payload of the side that shows the session.
    func waitForPayload() async throws -> String {
        while payload == nil {
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        return payload!
    }
}

final class SideUI: EnrollmentUI, @unchecked Sendable {
    let side: String
    let match: CodeMatch
    let answer: Bool

    init(_ side: String, _ match: CodeMatch, answer: Bool = true) {
        self.side = side
        self.match = match
        self.answer = answer
    }

    func show(payload: String, code: String) async { await match.show(payload) }

    func compare(code: String) async -> Bool {
        let same = await match.compare(side, code)
        return same && answer
    }

    func confirmAgain() async -> Bool { false }
}

/// One device of the Python demo, driven through the `/py/` requests of
/// apps/apple/tools/approver.py.
struct PythonDevice: Sendable {
    let base: String

    @discardableResult
    func call(_ method: String, _ path: String, _ query: [String: String] = [:]) async throws -> String {
        var c = URLComponents(string: base + "/py/" + path)!
        if !query.isEmpty { c.queryItems = query.map { URLQueryItem(name: $0.key, value: $0.value) } }
        var r = URLRequest(url: c.url!)
        r.httpMethod = method
        r.timeoutInterval = 90
        let (data, resp) = try await URLSession.shared.data(for: r)
        let text = String(decoding: data, as: UTF8.self)
        guard (resp as? HTTPURLResponse)?.statusCode == 200 else {
            throw SetupError.message("python device \(method) \(path): \(text)")
        }
        return text
    }
}

/// The new device side of an enrollment with a Python demo device. Each side
/// gets the code of the other, and says yes only if the codes match ([ENR-7]).
final class PythonCompareUI: EnrollmentUI, @unchecked Sendable {
    let py: PythonDevice

    init(_ py: PythonDevice) { self.py = py }

    func show(payload: String, code: String) async {}

    func compare(code: String) async -> Bool {
        (try? await py.call("POST", "compare", ["code": code])) == code
    }

    func confirmAgain() async -> Bool { false }
}

/// The app flows against a relay process (S1, S2): the native sign-in, the
/// space creation, QR enrollment in both directions, and sync both ways.
///
/// `make test-app` starts the relay and the sign-in approver
/// (apps/apple/tools/approver.py), and passes their URLs in
/// SNAILFISH_RELAY_URL and SNAILFISH_APPROVER.
final class RelayTests: XCTestCase {
    private var dirs: [URL] = []
    private let transport = Transport()

    override func tearDown() {
        for d in dirs { try? FileManager.default.removeItem(at: d) }
    }

    private func env(_ name: String) throws -> String {
        guard let v = ProcessInfo.processInfo.environment[name], !v.isEmpty else {
            throw XCTSkip("\(name) is not set: run `make test-app`")
        }
        return v
    }

    private func device(_ name: String) throws -> SyncDevice {
        let d = FileManager.default.temporaryDirectory.appendingPathComponent("tasks-\(name)-\(UUID().uuidString)")
        dirs.append(d)
        if hasKeychainEntitlement() {
            let store = KeychainKeyStore(service: "snailfish.tests." + UUID().uuidString)
            return try SyncDevice(root: d, keyStore: store, deleteKeys: { try store.delete(account: $0) })
        }
        let store = MemKeyStore()
        return try SyncDevice(root: d, keyStore: store, deleteKeys: { try store.delete(account: $0) })
    }

    /// The browser step: the approver signs in and allows the request, and
    /// returns the redirect URL to the private-use scheme.
    private func browser(_ approver: String) -> (URL) async throws -> URL {
        { url in
            var c = URLComponents(string: approver + "/approve")!
            c.queryItems = [URLQueryItem(name: "url", value: url.absoluteString)]
            let (data, resp) = try await URLSession.shared.data(from: c.url!)
            let text = String(decoding: data, as: UTF8.self)
            guard (resp as? HTTPURLResponse)?.statusCode == 200, let u = URL(string: text) else {
                throw SetupError.message("approver: \(text)")
            }
            return u
        }
    }

    private func sorted(_ d: SyncDevice) async throws -> [TaskItem] {
        try await d.tasks().sorted { $0.title < $1.title }
    }

    func testSignInEnrollBothWaysAndSync() async throws {
        let relay = try env("SNAILFISH_RELAY_URL")
        let approver = try env("SNAILFISH_APPROVER")
        let transport = transport

        // S1: an edit before sync, then the sign-in creates the space.
        let a = try device("a")
        try await a.edit(task: "t1", field: "title", value: .string("offline milk"))
        let key = try await createSpace(
            device: a, relayURL: relay, name: "A", transport: transport, browser: browser(approver))
        XCTAssertTrue(RecoveryCheck.matches(typed: key, shown: key))
        let v1 = try await a.sync(transport)
        XCTAssertEqual(v1, .ok)
        let v2 = try await a.statusText()
        XCTAssertEqual(v2, "ok")

        // S2: the trusted device shows the QR code, and the new device
        // reads it from the image.
        let b = try device("b")
        try await b.edit(task: "t0", field: "title", value: .string("b offline"))
        let m1 = CodeMatch()
        let engineAOpt = await a.engine
        let engineA = try XCTUnwrap(engineAOpt)
        let shown = Task { try await invite(engine: engineA, scanned: nil, transport: transport, ui: SideUI("a", m1)) }
        let payload = try await m1.waitForPayload()
        let scanned = try QRCode.decode(XCTUnwrap(QRCode.image(payload)))
        XCTAssertEqual(scanned, [payload])
        let joined = try await join(
            device: b, relayURL: relay, name: "B", scanned: try XCTUnwrap(scanned.first), transport: transport, ui: SideUI("b", m1))
        let invited = try await shown.value
        XCTAssertEqual([invited, joined], ["", ""])
        let v3 = try await b.sync(transport)
        XCTAssertEqual(v3, .ok)
        let v4 = try await b.tasks().map(\.title)
        XCTAssertEqual(v4.sorted(), ["b offline", "offline milk"], "[MRG-5]: the edit before sync arrives")

        // The other direction: the new device shows the QR code, and the
        // trusted device B scans it.
        let c = try device("c")
        let m2 = CodeMatch()
        let joining = Task {
            try await join(device: c, relayURL: relay, name: "C", scanned: nil, transport: transport, ui: SideUI("c", m2))
        }
        let payloadC = try await m2.waitForPayload()
        let engineBOpt = await b.engine
        let engineB = try XCTUnwrap(engineBOpt)
        let scannedC = try QRCode.decode(XCTUnwrap(QRCode.image(payloadC)))
        let invitedC = try await invite(engine: engineB, scanned: try XCTUnwrap(scannedC.first), transport: transport, ui: SideUI("b", m2))
        let joinedC = try await joining.value
        XCTAssertEqual([invitedC, joinedC], ["", ""])

        // Edits sync both ways.
        let v5 = try await c.sync(transport)
        XCTAssertEqual(v5, .ok)
        try await c.edit(task: "t2", field: "title", value: .string("from c"))
        let v6 = try await c.sync(transport)
        XCTAssertEqual(v6, .ok)
        try await a.edit(task: "t1", field: "done", value: .bool(true))
        let v7 = try await a.sync(transport)
        XCTAssertEqual(v7, .ok)
        let v8 = try await c.sync(transport)
        XCTAssertEqual(v8, .ok)
        let v9 = try await b.sync(transport)
        XCTAssertEqual(v9, .ok)
        // B queued its edit from before sync at the end of its first sync,
        // so A and C get it after the last sync of B.
        _ = try await a.sync(transport)
        _ = try await c.sync(transport)
        let gotA = try await sorted(a)
        XCTAssertEqual(gotA.map(\.title), ["b offline", "from c", "offline milk"])
        XCTAssertEqual(gotA.map(\.done), [false, false, true])
        let gotB = try await sorted(b)
        let gotC = try await sorted(c)
        XCTAssertEqual(gotB, gotA)
        XCTAssertEqual(gotC, gotA)
    }

    /// [ENR-7], T6: a code mismatch on the new device ends its enrollment,
    /// the new device stores no engine state, and the trusted device
    /// appends no grant.
    func testCodeMismatchStoresNothing() async throws {
        let relay = try env("SNAILFISH_RELAY_URL")
        let approver = try env("SNAILFISH_APPROVER")
        let transport = transport
        let a = try device("a")
        _ = try await createSpace(device: a, relayURL: relay, name: "A", transport: transport, browser: browser(approver))
        let v10 = try await a.sync(transport)
        XCTAssertEqual(v10, .ok)
        let engineAOpt = await a.engine
        let engineA = try XCTUnwrap(engineAOpt)
        let head = try engineA.verifiedHead().position

        let b = try device("b")
        let m = CodeMatch()
        let trusted = Task { try await invite(engine: engineA, scanned: nil, transport: transport, ui: SideUI("a", m)) }
        let payload = try await m.waitForPayload()
        let joined = try await join(
            device: b, relayURL: relay, name: "B", scanned: payload, transport: transport,
            ui: SideUI("b", m, answer: false))
        XCTAssertFalse(joined.isEmpty, "the new device reports the mismatch")
        let syncOn = await b.syncOn
        XCTAssertFalse(syncOn)
        XCTAssertFalse(FileManager.default.fileExists(atPath: b.engineDir.appendingPathComponent("engine.sqlite3").path))
        // The trusted side waits for a confirmation that never comes.
        trusted.cancel()
        _ = await trusted.result
        let v11 = try await a.sync(transport)
        XCTAssertEqual(v11, .ok)
        XCTAssertEqual(try engineA.verifiedHead().position, head, "no grant")
    }

    /// The Swift app and the Python demo share one space: the app uses the
    /// app ID and the change format of the demo. The titles hold non-ASCII
    /// text, because the JSON encoders of the two apps write it as different
    /// bytes.
    func testSwiftAppAndPythonDemoShareASpace() async throws {
        let relay = try env("SNAILFISH_RELAY_URL")
        let py = PythonDevice(base: try env("SNAILFISH_APPROVER"))
        let transport = transport

        try await py.call("POST", "setup")
        try await py.call("POST", "edit", ["task": "p1", "field": "title", "value": #""café from python""#])
        let v1 = try await py.call("POST", "sync")
        XCTAssertEqual(v1, "ok")

        // S2 with the Python device as the trusted device. It shows the
        // session, and the app reads the payload. The app has an edit from
        // before sync ([MRG-5]).
        let s = try device("s")
        try await s.edit(task: "s1", field: "title", value: .string("naïve from swift ✓"))
        let payload = try await py.call("POST", "invite")
        let joined = try await join(
            device: s, relayURL: relay, name: "S", scanned: payload, transport: transport, ui: PythonCompareUI(py))
        let invited = try await py.call("GET", "invite/result")
        XCTAssertEqual([invited, joined], ["", ""])

        // The first sync opens the app key and queues the edit from before
        // sync. The second sync uploads it.
        for _ in 0..<2 {
            let v = try await s.sync(transport)
            XCTAssertEqual(v, .ok)
        }
        let v2 = try await py.call("POST", "sync")
        XCTAssertEqual(v2, "ok")

        // Edits both ways: Swift edits a Python task, and Python edits a
        // Swift task.
        try await s.edit(task: "p1", field: "done", value: .bool(true))
        _ = try await s.sync(transport)
        try await py.call("POST", "edit", ["task": "s1", "field": "title", "value": #""naïve, renamed in python""#])
        _ = try await py.call("POST", "sync")
        let v3 = try await s.sync(transport)
        XCTAssertEqual(v3, .ok)

        let want = [
            TaskItem(id: "p1", title: "café from python", done: true),
            TaskItem(id: "s1", title: "naïve, renamed in python", done: false),
        ]
        let gotSwift = try await s.tasks()
        XCTAssertEqual(gotSwift, want)
        let data = Data(try await py.call("GET", "tasks").utf8)
        let gotPy = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: [String: Any]])
        XCTAssertEqual(Set(gotPy.keys), ["p1", "s1"])
        XCTAssertEqual(gotPy["p1"]?["title"] as? String, "café from python")
        XCTAssertEqual(gotPy["p1"]?["done"] as? Bool, true)
        XCTAssertEqual(gotPy["s1"]?["title"] as? String, "naïve, renamed in python")
    }
}
