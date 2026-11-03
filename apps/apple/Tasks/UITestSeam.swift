#if DEBUG
    import Foundation
    import Snailfish
    import SwiftUI

    /// The seam of the UI tests (TasksUITests). It is in Debug builds only,
    /// and `make test-app` checks that the Release build does not contain
    /// it.
    ///
    /// The UI test sets SNAILFISH_UITEST_APPROVER in the launch environment
    /// to the URL of apps/apple/tools/approver.py. Then:
    ///
    /// - The browser step of the sign-in goes to the approver, because the
    ///   simulator cannot make a passkey.
    /// - The scan screen takes the QR payload as text, because the simulator
    ///   has no camera.
    /// - The data is in the directory SNAILFISH_UITEST_DATA of the temporary
    ///   directory, so a test never uses the data of a person.
    /// - On macOS, the keys are in files in that directory, because an
    ///   unsigned build has no keychain (C62). iOS uses the keychain.
    /// - SNAILFISH_UITEST_FAULT=offline-after-first-append makes the
    ///   transport lose the answer of the first append, and fail each later
    ///   request. The relay stores the append.
    struct UITestSeam: Sendable {
        let approver: String
        let dataDir: URL
        let offlineAfterFirstAppend: Bool

        static let current: UITestSeam? = {
            let env = ProcessInfo.processInfo.environment
            guard let approver = env["SNAILFISH_UITEST_APPROVER"], !approver.isEmpty else { return nil }
            let name = env["SNAILFISH_UITEST_DATA"] ?? UUID().uuidString
            return UITestSeam(
                approver: approver,
                dataDir: FileManager.default.temporaryDirectory.appendingPathComponent("tasks-uitest-" + name),
                offlineAfterFirstAppend: env["SNAILFISH_UITEST_FAULT"] == "offline-after-first-append")
        }()

        /// The browser step: the approver signs in, allows the request, and
        /// returns the redirect URL to the private-use scheme.
        func approve(_ url: URL) async throws -> URL {
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

    /// The network fault of SNAILFISH_UITEST_FAULT.
    final class FaultState: @unchecked Sendable {
        private let lock = NSLock()
        private var offline = false

        func before() throws {
            if lock.withLock({ offline }) { throw URLError(.notConnectedToInternet) }
        }

        /// After the relay answered `path`: an append goes offline and loses
        /// its answer.
        func after(path: String) throws {
            guard path.hasSuffix("/append") else { return }
            lock.withLock { offline = true }
            throw URLError(.networkConnectionLost)
        }
    }

    /// A key store in files, for the unsigned macOS build of the UI tests.
    final class FileKeyStore: KeyStore, @unchecked Sendable {
        let dir: URL

        init(dir: URL) throws {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            self.dir = dir
        }

        func load(account: String) throws -> Data? {
            let f = dir.appendingPathComponent(account)
            guard FileManager.default.fileExists(atPath: f.path) else { return nil }
            return try Data(contentsOf: f)
        }

        func store(account: String, secret: Data) throws {
            try secret.write(to: dir.appendingPathComponent(account), options: .atomic)
        }

        func delete(account: String) throws {
            do {
                try FileManager.default.removeItem(at: dir.appendingPathComponent(account))
            } catch let e as CocoaError where e.code == .fileNoSuchFile {}
        }
    }

    /// The scan screen of the UI tests: the QR payload as text.
    struct PayloadEntry: View {
        let scanned: (String) -> Void
        @State private var payload = ""

        var body: some View {
            TextField("QR payload", text: $payload)
                .textFieldStyle(.roundedBorder)
                .autocorrectionDisabled()
                .noAutocapitalization()
                .accessibilityIdentifier("scan-payload")
            Button("Use the payload") { scanned(payload) }
                .accessibilityIdentifier("scan-use")
        }
    }
#endif
