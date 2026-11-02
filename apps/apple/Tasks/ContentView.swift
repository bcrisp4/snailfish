import SwiftUI

struct ContentView: View {
    @ObservedObject var model: AppModel
    @State private var newTitle = ""
    // One sheet at a time. SwiftUI drops a sheet that opens while another
    // one closes, so an action of the settings sheet runs after it closes.
    enum Sheet: Identifiable {
        case settings, flow
        var id: Self { self }
    }
    @State private var sheet: Sheet?
    @State private var afterSettings: (() -> Void)?
    @Environment(\.scenePhase) private var phase
    @StateObject private var web = WebSignInBox()

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                List {
                    Section {
                        HStack {
                            TextField("New task", text: $newTitle)
                                .onSubmit(add)
                                .accessibilityIdentifier("new-task")
                            Button("Add", action: add)
                                .disabled(newTitle.isEmpty)
                                .accessibilityIdentifier("add-task")
                        }
                    }
                    Section {
                        ForEach(model.tasks) { t in
                            TaskRow(task: t, model: model)
                        }
                    }
                }
                StatusBar(model: model)
            }
            .navigationTitle("Tasks")
            .toolbar {
                ToolbarItem {
                    Button {
                        sheet = .settings
                    } label: {
                        Label("Sync", systemImage: model.syncOn ? "arrow.triangle.2.circlepath" : "icloud.slash")
                    }
                    .accessibilityIdentifier("sync-settings")
                }
            }
            .sheet(item: $sheet, onDismiss: sheetClosed) { which in
                switch which {
                case .settings: SyncSettings(model: model, web: web) { afterSettings = $0 }
                case .flow: FlowSheet(model: model)
                }
            }
            .onChange(of: model.step) { _, step in
                if step != .none, sheet == nil { sheet = .flow }
                if step == .none, sheet == .flow { sheet = nil }
            }
            .alert(
                model.message ?? "", isPresented: Binding(get: { model.message != nil }, set: { _ in model.message = nil })
            ) {
                Button("OK") {}
            }
        }
        .task { await model.refresh() }
        .task(id: phase) {
            if phase == .active { await model.syncLoop() }
        }
    }

    private func sheetClosed() {
        if let action = afterSettings {
            afterSettings = nil
            action()
        } else if model.step != .none {
            // The user closed the flow sheet with a swipe.
            model.cancelFlow()
        }
    }

    private func add() {
        guard !newTitle.isEmpty else { return }
        model.add(title: newTitle)
        newTitle = ""
    }
}

/// Holds the presentation context of the browser sign-in.
@MainActor
final class WebSignInBox: ObservableObject {
    let web = WebSignIn()
}

struct TaskRow: View {
    let task: TaskItem
    @ObservedObject var model: AppModel
    @State private var editing = false
    @State private var title = ""

    var body: some View {
        HStack {
            Button {
                model.toggle(task)
            } label: {
                Image(systemName: task.done ? "checkmark.circle.fill" : "circle")
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("toggle-\(task.id)")
            if editing {
                TextField("Title", text: $title)
                    .onSubmit {
                        model.rename(task, to: title)
                        editing = false
                    }
            } else {
                Text(task.title)
                    .strikethrough(task.done)
                    .onTapGesture(count: 2) {
                        title = task.title
                        editing = true
                    }
            }
        }
    }
}

struct StatusBar: View {
    @ObservedObject var model: AppModel

    var body: some View {
        HStack {
            Circle().fill(color).frame(width: 8, height: 8)
            Text("Sync: \(model.status)")
                .font(.footnote)
                .accessibilityIdentifier("sync-status")
            Spacer()
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
        .background(.bar)
    }

    private var color: Color {
        if model.status.hasPrefix("ok") { return .green }
        if model.status.hasPrefix("paused") || model.status.hasPrefix("degraded") { return .orange }
        if model.status.hasPrefix("stopped") { return .red }
        return .gray
    }
}

struct SyncSettings: View {
    @ObservedObject var model: AppModel
    @ObservedObject var web: WebSignInBox
    /// Keeps an action to run after the sheet closes.
    let later: (@escaping () -> Void) -> Void
    @Environment(\.dismiss) private var dismiss

    private func then(_ action: @escaping () -> Void) {
        later(action)
        dismiss()
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Relay") {
                    TextField("Relay URL", text: $model.relayURL)
                        .autocorrectionDisabled()
                        .noAutocapitalization()
                        .disabled(model.syncOn)
                        .accessibilityIdentifier("relay-url")
                    Text("Sync: \(model.status)")
                }
                if !model.syncOn {
                    Section("First device") {
                        Button("Turn on sync") {
                            let w = web.web
                            then { model.turnOnSync { try await w.redirect(for: $0) } }
                        }
                        .accessibilityIdentifier("turn-on-sync")
                    }
                    Section("Add to my account") {
                        Button("Scan the code of my other device") {
                            then { model.joinSpace(scan: true) }
                        }
                        Button("Show a code for my other device") {
                            then { model.joinSpace(scan: false) }
                        }
                        .accessibilityIdentifier("join-show")
                    }
                } else {
                    Section("Add a device") {
                        Button("Show a code for the new device") {
                            then { model.addDevice(scan: false) }
                        }
                        .accessibilityIdentifier("invite-show")
                        Button("Scan the code of the new device") {
                            then { model.addDevice(scan: true) }
                        }
                    }
                    if model.status.hasPrefix("stopped: setup failed") {
                        Section {
                            Button("Sign in again") {
                                then { model.leaveFailedSetup() }
                            }
                        }
                    }
                    Section("Sync now") {
                        Button("Sync now") { Task { await model.syncNow() } }
                    }
                }
                Section("Measurements") {
                    Text(model.measurements.summary()).font(.footnote)
                    Button("Measure the durable commit cost") {
                        then { model.runBenchmark() }
                    }
                    ShareLink(item: model.measurements.file) {
                        Label("Export the measurement log", systemImage: "square.and.arrow.up")
                    }
                }
            }
            .navigationTitle("Sync")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
        }
        #if os(macOS)
            .frame(minWidth: 420, minHeight: 480)
        #endif
    }
}

/// The steps of an enrollment or a setup.
struct FlowSheet: View {
    @ObservedObject var model: AppModel
    @State private var typedKey = ""

    var body: some View {
        VStack(spacing: 16) {
            switch model.step {
            case .none:
                EmptyView()
            case .working(let text):
                ProgressView(text)
            case .showing(let payload, let code):
                Text("Scan this code on your other device").font(.headline)
                QRView(text: payload)
                Text(code)
                    .font(.system(.footnote, design: .monospaced))
                    .textSelection(.enabled)
                    .accessibilityIdentifier("typed-code")
                Text(payload)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .accessibilityIdentifier("enroll-payload")
                ProgressView("Waiting for the other device")
            case .scanning(let trusted):
                Text("Scan the code on your other device").font(.headline)
                ScanView { model.scanned($0, trusted: trusted) }
            case .comparing(let code):
                Text("Does the other device show this code?").font(.headline)
                Text(code)
                    .font(.system(size: 44, weight: .semibold, design: .monospaced))
                    .accessibilityIdentifier("compare-code")
                HStack(spacing: 24) {
                    Button("No, the codes differ", role: .destructive) { model.answer(false) }
                        .accessibilityIdentifier("compare-no")
                    Button("Yes, they match") { model.answer(true) }
                        .buttonStyle(.borderedProminent)
                        .accessibilityIdentifier("compare-yes")
                }
            case .confirmAgain:
                Text("The device list changed. Add the new device?").font(.headline)
                HStack(spacing: 24) {
                    Button("No", role: .destructive) { model.answer(false) }
                    Button("Yes") { model.answer(true) }.buttonStyle(.borderedProminent)
                }
            case .recoveryKey(let key):
                RecoveryKeyView(key: key) { model.step = .none }
            }
            if !isRecovery {
                Button("Cancel", role: .cancel) { model.cancelFlow() }
            }
        }
        .padding()
        // The app shows the recovery key once, so a swipe must not close it
        // before the check (S1).
        .interactiveDismissDisabled(isRecovery)
        #if os(macOS)
            .frame(minWidth: 420, minHeight: 420)
        #endif
    }

    private var isRecovery: Bool {
        if case .recoveryKey = model.step { return true }
        return false
    }
}

/// Shows the recovery key once. The user writes it on paper and types it
/// back, and the app checks the copy (S1).
struct RecoveryKeyView: View {
    let key: String
    let done: () -> Void
    @State private var typed = ""
    @State private var wrong = false

    var body: some View {
        VStack(spacing: 12) {
            Text("Recovery key").font(.headline)
            Text("Write this key on paper. The app shows it only once.")
            Text(key)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
                .accessibilityIdentifier("recovery-key")
            TextField("Type the key from your paper", text: $typed)
                .textFieldStyle(.roundedBorder)
                .autocorrectionDisabled()
                .noAutocapitalization()
                .accessibilityIdentifier("recovery-typed")
            if wrong { Text("The key does not match. Check your paper.").foregroundStyle(.red) }
            Button("Check") {
                if RecoveryCheck.matches(typed: typed, shown: key) { done() } else { wrong = true }
            }
            .buttonStyle(.borderedProminent)
            .accessibilityIdentifier("recovery-check")
        }
    }
}
