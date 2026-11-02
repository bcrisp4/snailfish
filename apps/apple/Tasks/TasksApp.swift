import Snailfish
import SwiftUI

#if os(iOS)
    import BackgroundTasks
#endif

@main
struct TasksApp: App {
    // The app data and the engine open at launch. If the key store refuses
    // the keys, the app fails closed and shows the cause (C62).
    private let opened: Result<AppModel, Error>

    init() {
        opened = Result { try AppModel.make() }
        if case .success(let m) = opened {
            #if os(iOS)
                BackgroundSync.register(model: m)
            #endif
            LaunchActions.run(model: m)
        }
    }

    var body: some Scene {
        WindowGroup {
            switch opened {
            case .success(let model): ContentView(model: model)
            case .failure(let error):
                Text("The app cannot open its data: \(String(describing: error))")
                    .padding()
                    .textSelection(.enabled)
            }
        }
        #if os(iOS)
            .backgroundTask(.appRefresh(BackgroundSync.identifier)) {
                if case .success(let model) = opened {
                    await BackgroundSync.handle(model: model)
                }
            }
        #endif
    }
}

/// The recovery key check of S1: the typed copy must read as the same key
/// with the reader steps of PROTOCOL.md section 9.
enum RecoveryCheck {
    static func matches(typed: String, shown: String) -> Bool {
        guard let a = try? recoveryParse(text: typed), let b = try? recoveryParse(text: shown) else { return false }
        return a == b
    }
}

/// Actions for a launch from the command line, for measurements that run
/// with no user, for example `xcrun devicectl device process launch ...
/// <bundle id> -bench-commit YES`.
enum LaunchActions {
    @MainActor
    static func run(model: AppModel) {
        if UserDefaults.standard.bool(forKey: "bench-commit") {
            model.runBenchmark()
        }
    }
}

#if os(iOS)
    /// iOS background sync with `BGAppRefreshTask` only (M6 decision 4). The
    /// system decides when a refresh runs. Each refresh syncs once and logs
    /// its times, and each arrival logs its delay (`Measurements`).
    enum BackgroundSync {
        static var identifier: String { (Bundle.main.bundleIdentifier ?? appID) + ".refresh" }

        /// The earliest start of the next refresh. iOS can run it later.
        static let interval: TimeInterval = 15 * 60

        @MainActor
        static func register(model: AppModel) {
            NotificationCenter.default.addObserver(
                forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: .main
            ) { _ in schedule() }
        }

        static func schedule() {
            let req = BGAppRefreshTaskRequest(identifier: identifier)
            req.earliestBeginDate = Date(timeIntervalSinceNow: interval)
            do {
                try BGTaskScheduler.shared.submit(req)
            } catch {
                // The simulator refuses background tasks. A device with
                // Background App Refresh off refuses them too.
                print("background refresh not scheduled: \(error)")
            }
        }

        /// One refresh. SwiftUI cancels the task when the time runs out.
        static func handle(model: AppModel) async {
            schedule()
            let start = Measurements.nowMs()
            await model.syncNow(background: true)
            let result = Task.isCancelled ? "expired" : await model.status
            model.measurements.refresh(startMs: start, endMs: Measurements.nowMs(), result: result)
        }
    }
#endif
