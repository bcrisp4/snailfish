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
        /// This device scans the QR code of the other device. With `rejoin`,
        /// this device enrolls again after a fork ([FRK-6]).
        case scanning(trusted: Bool, rejoin: Bool = false)
        /// Both devices show the 6-digit code ([ENR-7]).
        case comparing(code: String)
        case confirmAgain
        /// The recovery key of a new space, shown once (S1).
        case recoveryKey(String)
        /// The user picks the devices to remove and confirms the devices
        /// that stay (S4, PROTOCOL.md 13.2).
        case removal([ActiveDevice])
        /// A replacement recovery key, shown once, then typed back, then the
        /// current key (T9, PROTOCOL.md 13.3).
        case newRecoveryKey(String)
        /// The user confirms the deletion of the space on the relay before
        /// this device imports its copy ([FRK-4], [FRK-5]).
        case confirmDelete
        case working(String)
    }

    @Published var tasks: [TaskItem] = []
    @Published var status = "sync off"
    @Published var syncOn = false
    /// A full recovery did not grant this device before the app stopped.
    @Published var recoveryWaits = false
    /// An enrollment again after a fork did not finish ([FRK-6]).
    @Published var rejoinWaits = false
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
    // The last error of a sync, for the status text. An alert on each
    // failure would return every 5 s while the device is offline.
    @Published private(set) var syncError: String?
    // A setup or an enrollment uses the engine. The sync loop waits, so two
    // state machines never drive one engine at the same time.
    private var flows = 0
    private var flowActive: Bool { flows > 0 }

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
        var dataDir = args.string(forKey: "data-dir")
        #if DEBUG
            if let seam = UITestSeam.current { dataDir = seam.dataDir.path }
        #endif
        let root = dataDir.map { URL(fileURLWithPath: $0) } ?? support.appendingPathComponent("Tasks", isDirectory: true)
        // One keychain service for each `-data-dir`: two devices of one space
        // on one Mac must not share a key item. The default directory has no
        // path in the name, because the iOS container path changes after an
        // app update.
        let service = "snailfish." + (Bundle.main.bundleIdentifier ?? appID) + (dataDir.map { ":" + $0 } ?? "")
        #if os(iOS)
            // Documents is visible in Finder file sharing, so the log can be
            // copied off the iPhone.
            let logDir = try fm.url(for: .documentDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        #else
            let logDir = root
        #endif
        let log = Measurements(file: logDir.appendingPathComponent("measure.jsonl"))
        let keychain = KeychainKeyStore(service: service)
        var keyStore: KeyStore = keychain
        var deleteKeys: (String) throws -> Void = { try keychain.delete(account: $0) }
        #if DEBUG && os(macOS)
            if UITestSeam.current != nil {
                let files = try FileKeyStore(dir: root.appendingPathComponent("uitest-keys"))
                keyStore = files
                deleteKeys = { try files.delete(account: $0) }
            }
        #endif
        let device = try SyncDevice(root: root, keyStore: keyStore, deleteKeys: deleteKeys, measurements: log)
        return AppModel(device: device, measurements: log)
    }

    func refresh() async {
        do {
            tasks = try await device.tasks()
            syncOn = await device.syncOn
            recoveryWaits = try await device.recoveryWaits()
            rejoinWaits = await device.rejoinWaits
            status = try await device.statusText()
            if let syncError { status += " (last sync: \(syncError))" }
        } catch {
            message = "\(error)"
        }
    }

    private func run(_ what: String, _ body: @escaping () async throws -> Void) {
        // A flow that waits for an answer cannot see the cancel.
        answer?.resume(returning: false)
        answer = nil
        flow?.cancel()
        flow = Task {
            flows += 1
            do {
                // A sync that started before the flow ends first.
                while syncing { try await Task.sleep(nanoseconds: 50_000_000) }
                try await body()
            } catch SetupError.cancelled {
            } catch is CancellationError {
            } catch {
                message = "\(what): \(error)"
            }
            if case .working = step { step = .none }
            flows -= 1
            await syncNow()
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
        guard await device.syncOn, !syncing, !flowActive else { return }
        syncing = true
        defer { syncing = false }
        do {
            _ = try await device.sync(transport, background: background)
            syncError = nil
        } catch {
            // A connection failure is the app's error. The engine status
            // shows a relay error.
            syncError = (error as? URLError)?.localizedDescription ?? "\(error)"
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
        }
    }

    /// Recover the space of this app onto this device with the paper
    /// recovery key (S5). After the sync grants this device, the user
    /// removes the lost devices.
    func recover(recoveryKey: String, browser: @escaping (URL) async throws -> URL) {
        run("recover") { [self] in
            try await recoverFlow(recoveryKey: recoveryKey, browser: browser)
        }
    }

    private func recoverFlow(recoveryKey: String, browser: @escaping (URL) async throws -> URL) async throws {
        let relay = relayURL
        step = .working("Signing in")
        try await recoverSpace(
            device: device, relayURL: relay, name: deviceName(), recoveryKey: recoveryKey,
            transport: transport, browser: browser)
        try await waitForGrant()
    }

    /// Sync until the verified log holds the grant of this device, then show
    /// the removal. A lost answer or a `stale_base` refusal leaves the grant
    /// for a later sync, so the flow waits and the user can cancel it. A
    /// status that another sync does not change ends the flow.
    private func waitForGrant() async throws {
        step = .working("Checking the log")
        while true {
            let cause: String
            do {
                let st = try await device.sync(transport, background: false)
                try Task.checkCancellation()
                if try await device.activeDevices().contains(where: \.thisDevice) { break }
                guard ([.ok, .relayUnavailable, .restoreHold, .quota] as [Status]).contains(st) else {
                    throw SetupError.message("the relay did not grant this device: \(try await device.statusText())")
                }
                cause = try await device.statusText()
            } catch let e as URLError where e.code != .cancelled {
                cause = e.localizedDescription
            }
            step = .working("Waiting for the grant of this device (last sync: \(cause))")
            try await Task.sleep(nanoseconds: 5_000_000_000)
        }
        _ = try await device.recoveryWaits()
        step = .removal(try await device.activeDevices())
    }

    /// Start a full recovery again after it stopped before the grant (the
    /// engine keeps the recovery key in memory only). If the relay granted
    /// this device already, the flow continues with the removal.
    func recoverAgain(recoveryKey: String, browser: @escaping (URL) async throws -> URL) {
        run("recover") { [self] in
            step = .working("Checking the log")
            if try await device.abandonRecovery(transport) {
                try await recoverFlow(recoveryKey: recoveryKey, browser: browser)
            } else {
                step = .removal(try await device.activeDevices())
            }
        }
    }

    /// Show the active devices, so the user picks the lost ones (S4).
    func showRemoval() {
        run("remove devices") { [self] in
            step = .removal(try await device.activeDevices())
        }
    }

    /// Remove `ids` after the user confirmed the devices that stay, and sync
    /// so the epoch record goes to the relay. If a device joined first, the
    /// list shows again ([LOG-7]).
    func remove(ids: [String]) {
        run("remove devices") { [self] in
            step = .working("Removing")
            try await device.removeDevices(ids)
            _ = try await device.sync(transport, background: false)
            if try await device.removalToConfirm() != nil {
                message = "The device list changed. Confirm the devices that stay again."
                step = .removal(try await device.activeDevices())
            } else if try await device.removalPending() {
                step = .none
                let st = try await device.statusText()
                message = "The removal is not finished: \(st). The next sync sends it again."
            } else {
                step = .none
                message = "The devices are removed, and the key is new."
            }
        }
    }

    /// Show a new recovery key for a replacement (T9).
    func startKeyReplacement() {
        run("replace the recovery key") { [self] in
            step = .newRecoveryKey(try newRecoveryKey())
        }
    }

    /// Replace the recovery key after the user typed the new key back and
    /// gave the current key. Two syncs: the recovery record, then the
    /// rotation after it.
    func replaceRecoveryKey(current: String, new: String) {
        run("replace the recovery key") { [self] in
            step = .working("Replacing the recovery key")
            try await device.replaceRecoveryKey(current: current, new: new)
            _ = try await device.sync(transport, background: false)
            _ = try await device.sync(transport, background: false)
            step = .none
            // The old key stays current until the relay stores the recovery
            // record, so the user keeps the old paper until then.
            if try await device.recoveryKeyNeeded() {
                message = "Another device changed the space first, so the recovery key is not replaced. "
                    + "Keep your current paper, and replace the key again."
            } else if try await device.removalPending() {
                let st = try await device.statusText()
                message = "The replacement is not finished: \(st). Keep your current paper. "
                    + "The next sync sends it again."
            } else {
                message = "The recovery key is replaced. Keep the new paper and destroy the old one."
            }
        }
    }

    /// Sign in again after `stopped: setup failed`, with the keys of this
    /// device, so the next sync creates the same space.
    func signInAgain(browser: @escaping (URL) async throws -> URL) {
        let relay = relayURL
        run("sign in again") { [self] in
            step = .working("Signing in")
            try await Tasks.signInAgain(device: device, relayURL: relay, transport: transport, browser: browser)
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

    func scanned(_ text: String, trusted: Bool, rejoin: Bool = false) {
        if trusted { startInvite(scanned: text) } else { startJoin(scanned: text, rejoin: rejoin) }
    }

    private func startInvite(scanned: String?) {
        run("add device") { [self] in
            guard let engine = await device.engine else { throw SetupError.syncOff }
            step = .working("Waiting for the other device")
            let cause = try await invite(engine: engine, scanned: scanned, transport: transport, ui: self)
            step = .none
            message = cause.isEmpty ? "The device joined." : "The enrollment failed: \(cause)"
        }
    }

    private func startJoin(scanned: String?, rejoin: Bool = false) {
        let relay = relayURL
        run(rejoin ? "join again" : "join") { [self] in
            if rejoin { try await device.prepareRejoin() }
            step = .working("Waiting for the other device")
            // The source lists the old and the new device of this device,
            // and the user removes the old one there.
            let name = rejoin ? deviceName() + " again" : deviceName()
            let cause = try await join(
                device: device, relayURL: relay, name: name, scanned: scanned, transport: transport, ui: self,
                rejoin: rejoin)
            guard cause.isEmpty else {
                step = .none
                message = "The enrollment failed: \(cause)"
                return
            }
            guard rejoin else {
                step = .none
                message = "This device joined."
                return
            }
            try await sendOwnChangesAgain()
        }
    }

    // MARK: Fork repair (DESIGN.md "Fork repair", PROTOCOL.md 10.12, 10.13)

    /// The next step for the user at `stopped: fork` or `stopped: deleted`
    /// ([FRK-1], [LOG-13]).
    var nextStep: String? {
        if rejoinWaits || status.hasPrefix("stopped: fork") {
            return "The relay showed your devices different copies of the data. Pick one device as the source, "
                + "and on it select \"Delete and import this device's copy\". Then join again from the source "
                + "on each other device."
        }
        if status.hasPrefix("stopped: deleted") {
            return "The space is deleted on the relay. Sync continues after a device imports its copy. "
                + "To import the copy of this device, select \"Delete and import this device's copy\"."
        }
        return nil
    }

    /// Ask the user to confirm the deletion of the space on the relay.
    func confirmDeleteAndImport() {
        step = .confirmDelete
    }

    /// [FRK-4], [FRK-5]: delete the space on the relay, sign in, and import
    /// the verified log of this device. After a deletion that stopped before
    /// the import, only the import runs.
    func deleteAndImport(browser: @escaping (URL) async throws -> URL) {
        run("delete and import") { [self] in
            guard let relay = await device.space?.relayUrl else { throw SetupError.syncOff }
            let deleted = try await device.statusText().hasPrefix("stopped: deleted")
            if !deleted {
                step = .working("Deleting the space on the relay")
                let st: Status
                do {
                    st = try await device.deleteSpace(transport)
                } catch SnailfishError.Refused(let code) where code == "bad_head" {
                    // PROTOCOL.md 10.12: after a fork, the head of this
                    // device can be outside the relay log.
                    throw SetupError.message(
                        "the relay log does not hold the last record of this device. Pick another device as "
                            + "the source, or ask the relay operator to delete the space")
                }
                guard st == .deleted else {
                    throw SetupError.message("the relay did not delete the space: \(try await device.statusText())")
                }
            }
            step = .working("Importing the copy of this device")
            try await importSpace(device: device, relayURL: relay, transport: transport, browser: browser)
            _ = try await device.sync(transport, background: false)
            step = .none
            message = "The relay holds the copy of this device again. On each other device, join again from this device."
        }
    }

    /// Enroll this device again from the source after a fork ([FRK-6]).
    /// With `scan`, this device scans the QR code of the source.
    func joinAgain(scan: Bool) {
        if scan {
            step = .scanning(trusted: false, rejoin: true)
            return
        }
        startJoin(scanned: nil, rejoin: true)
    }

    /// [FRK-7], [FRK-8]: the first sync recovers the own changes of the old
    /// engine state into the outbox, then the pull resets the app data and
    /// applies the outbox again. The second sync sends these changes.
    private func sendOwnChangesAgain() async throws {
        step = .working("Sending the changes of this device again")
        _ = try await device.sync(transport, background: false)
        _ = try await device.sync(transport, background: false)
        step = .none
        if await device.forkRecoveryWaits {
            let st = try await device.statusText()
            message = "This device joined again. Its own changes wait for the next sync: \(st)."
        } else {
            let n = await device.recovered ?? 0
            message = "This device joined again and sent \(n) of its own changes again. "
                + "On the source device, remove the old entry of this device."
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
