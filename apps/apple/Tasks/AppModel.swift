import Foundation
import Snailfish
import SwiftUI

/// The state of the UI, on the main actor. Each data call goes to the
/// `SyncDevice` actor.
@MainActor
final class AppModel: ObservableObject {
    enum Step: Equatable {
        case none
        /// This device shows the session: the QR payload and the typed code.
        case showing(payload: String, code: String)
        /// This device scans the QR code of the other device.
        case scanning(trusted: Bool)
        /// Both devices show the 6-digit code ([ENR-7]).
        case comparing(code: String)
        case confirmAgain
        /// The recovery key of a new space, shown once (S1).
        case recoveryKey(String)
        case working(String)
    }

    @Published var tasks: [TaskItem] = []
    @Published var status = "sync off"
    @Published var syncOn = false
    @Published var step: Step = .none
    @Published var message: String?
    @Published var relayURL: String {
        didSet { UserDefaults.standard.set(relayURL, forKey: "relayURL") }
    }

    let device: SyncDevice
    let transport = Transport()
    let measurements: Measurements
    private var answer: CheckedContinuation<Bool, Never>?
    private var flow: Task<Void, Never>?
    private var syncing = false

    init(device: SyncDevice, measurements: Measurements) {
        self.device = device
        self.measurements = measurements
        relayURL =
            UserDefaults.standard.string(forKey: "relayURL")
            ?? ProcessInfo.processInfo.environment["SNAILFISH_RELAY_URL"] ?? "http://localhost:8080"
    }

    /// The data directory, the key store and the measurement log of the
    /// app. The launch argument `-data-dir <path>` selects another data
    /// directory, so two devices can run on one Mac.
    static func make() throws -> AppModel {
        let args = UserDefaults.standard
        let fm = FileManager.default
        let support = try fm.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let root = args.string(forKey: "data-dir").map { URL(fileURLWithPath: $0) }
            ?? support.appendingPathComponent("Tasks", isDirectory: true)
        // One keychain service for each data directory: two devices of one
        // space on one Mac must not share a key item.
        let service = "snailfish." + (Bundle.main.bundleIdentifier ?? appID) + "." + root.lastPathComponent
        #if os(iOS)
            // Documents is visible in Finder file sharing, so the log can be
            // copied off the iPhone.
            let logDir = try fm.url(for: .documentDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        #else
            let logDir = root
        #endif
        let log = Measurements(file: logDir.appendingPathComponent("measure.jsonl"))
        let device = try SyncDevice(root: root, keyStore: KeychainKeyStore(service: service), measurements: log)
        return AppModel(device: device, measurements: log)
    }

    func refresh() async {
        do {
            tasks = try await device.tasks()
            syncOn = await device.syncOn
            status = try await device.statusText()
        } catch {
            message = "\(error)"
        }
    }

    private func run(_ what: String, _ body: @escaping () async throws -> Void) {
        flow?.cancel()
        flow = Task {
            do {
                try await body()
            } catch SetupError.cancelled {
            } catch is CancellationError {
            } catch {
                message = "\(what): \(error)"
            }
            if case .working = step { step = .none }
            await refresh()
        }
    }

    // MARK: Tasks

    func add(title: String) {
        let id = "t" + UUID().uuidString.prefix(8).lowercased()
        edit(id, "title", .string(title))
    }

    func toggle(_ t: TaskItem) { edit(t.id, "done", .bool(!t.done)) }

    func rename(_ t: TaskItem, to title: String) { edit(t.id, "title", .string(title)) }

    private func edit(_ task: String, _ field: String, _ value: JSONValue) {
        Task {
            do {
                try await device.edit(task: task, field: field, value: value)
            } catch {
                message = "edit: \(error)"
            }
            await refresh()
            await syncNow()
        }
    }

    // MARK: Sync

    func syncNow(background: Bool = false) async {
        guard await device.syncOn, !syncing else { return }
        syncing = true
        defer { syncing = false }
        do {
            _ = try await device.sync(transport, background: background)
        } catch {
            // A connection failure is the app's error. The engine status
            // shows a relay error.
            message = "sync: \(error.localizedDescription)"
        }
        await refresh()
    }

    /// Sync every few seconds while the app is in the foreground.
    func syncLoop() async {
        while !Task.isCancelled {
            await syncNow()
            try? await Task.sleep(nanoseconds: 5_000_000_000)
        }
    }

    // MARK: Setup

    /// Turn on sync on the first device: sign in, create the space and show
    /// the recovery key once (S1).
    func turnOnSync(browser: @escaping (URL) async throws -> URL) {
        let relay = relayURL
        run("turn on sync") { [self] in
            step = .working("Signing in")
            let key = try await createSpace(
                device: device, relayURL: relay, name: deviceName(), transport: transport, browser: browser)
            step = .recoveryKey(key)
            await syncNow()
        }
    }

    /// Leave a space that the relay refused to create, so the user can turn
    /// on sync again.
    func leaveFailedSetup() {
        run("reset sync") { [self] in try await device.leaveFailedSetup() }
    }

    /// Add another device from this trusted device. With `scan`, this
    /// device scans the QR code of the new device. Otherwise it shows its
    /// own.
    func addDevice(scan: Bool) {
        if scan {
            step = .scanning(trusted: true)
            return
        }
        startInvite(scanned: nil)
    }

    /// Join a space as a new device. With `scan`, this device scans the QR
    /// code of the trusted device. Otherwise it shows its own.
    func joinSpace(scan: Bool) {
        if scan {
            step = .scanning(trusted: false)
            return
        }
        startJoin(scanned: nil)
    }

    func scanned(_ text: String, trusted: Bool) {
        if trusted { startInvite(scanned: text) } else { startJoin(scanned: text) }
    }

    private func startInvite(scanned: String?) {
        run("add device") { [self] in
            guard let engine = await device.engine else { throw SetupError.syncOff }
            step = .working("Waiting for the other device")
            let cause = try await invite(engine: engine, scanned: scanned, transport: transport, ui: self)
            step = .none
            message = cause.isEmpty ? "The device joined." : "The enrollment failed: \(cause)"
            await syncNow()
        }
    }

    private func startJoin(scanned: String?) {
        let relay = relayURL
        run("join") { [self] in
            step = .working("Waiting for the other device")
            let cause = try await join(
                device: device, relayURL: relay, name: deviceName(), scanned: scanned, transport: transport, ui: self)
            step = .none
            message = cause.isEmpty ? "This device joined." : "The enrollment failed: \(cause)"
            await syncNow()
        }
    }

    func cancelFlow() {
        flow?.cancel()
        answer?.resume(returning: false)
        answer = nil
        step = .none
    }

    func answer(_ yes: Bool) {
        answer?.resume(returning: yes)
        answer = nil
        step = .working("Waiting for the other device")
    }

    private func deviceName() -> String {
        #if os(iOS)
            return UIDevice.current.name
        #else
            return Host.current().localizedName ?? "Mac"
        #endif
    }

    // MARK: Measurements

    func runBenchmark() {
        run("benchmark") { [self] in
            step = .working("Measuring durable commits")
            let dir = measurements.file.deletingLastPathComponent()
            let log = measurements
            message = try await Task.detached { try runCommitBenchmark(dir: dir, log: log) }.value
        }
    }
}

extension AppModel: EnrollmentUI {
    nonisolated func show(payload: String, code: String) async {
        await MainActor.run { step = .showing(payload: payload, code: code) }
    }

    nonisolated func compare(code: String) async -> Bool {
        await ask(.comparing(code: code))
    }

    nonisolated func confirmAgain() async -> Bool {
        await ask(.confirmAgain)
    }

    private func ask(_ s: Step) async -> Bool {
        await withCheckedContinuation { cont in
            answer = cont
            step = s
        }
    }
}
