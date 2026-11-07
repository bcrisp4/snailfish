import XCTest

/// The M7 app flows through the SwiftUI screens, against a relay process
/// (DESIGN.md S4 and S5, PROTOCOL.md section 13). The other device is a
/// Python demo device of the approver, which also blocks and unblocks
/// devices on the user page.
///
/// `make test-app` starts the relay and the approver, and passes their URLs
/// in SNAILFISH_RELAY_URL and SNAILFISH_APPROVER. The app gets the test seam
/// of Tasks/UITestSeam.swift: the approver does the passkey step, and the
/// scan screen takes the QR payload as text.
@MainActor
final class AppFlowTests: XCTestCase {
    private var relay = ""
    private var approver = ""
    private var py: PythonDevice!
    /// Flows that sign in and sync take some seconds. A sync of the sync
    /// loop comes every 5 s.
    private let timeout: TimeInterval = 60

    override func setUpWithError() throws {
        continueAfterFailure = false
        relay = try env("SNAILFISH_RELAY_URL")
        approver = try env("SNAILFISH_APPROVER")
        py = PythonDevice(base: approver)
    }

    private func env(_ name: String) throws -> String {
        guard let v = ProcessInfo.processInfo.environment[name], !v.isEmpty else {
            throw XCTSkip("\(name) is not set: run `make test-app`")
        }
        return v
    }

    // MARK: S4

    /// S4, [STO-12], T8: the user blocks the app device on the user page,
    /// and the app shows `paused: blocked`. A key replacement on the blocked
    /// device does not finish, and the app tells the user to keep the
    /// current paper. The Python device removes the app device and rotates
    /// the key, and after the unblock the app shows `stopped: removed`.
    func testBlockedDeviceShowsBlockedThenRemoved() async throws {
        try await pythonSpace()
        let app = launch()
        try await joinPythonSpace(app)
        let appID = try await py.deviceID(this: false)

        try await py.call("POST", "block", ["id": appID])
        syncNow(app)
        waitForStatus(app, "paused: blocked")

        let current = try await py.call("GET", "recovery-key")
        replaceRecoveryKey(app, current: current)
        waitForMessage(app, "The replacement is not finished: paused: blocked. Keep your current paper.")

        let removed = try await py.call("POST", "remove", ["ids": appID])
        XCTAssertEqual(removed, "ok")
        try await py.call("POST", "unblock", ["id": appID])
        syncNow(app)
        waitForStatus(app, "stopped: removed")
    }

    /// S4, T8 on the trusted device: the user blocks the stolen Python
    /// device, picks it in the app, checks the devices that stay, and
    /// removes it. After the unblock the relay refuses the stolen device.
    func testRemoveAStolenDeviceInTheApp() async throws {
        try await pythonSpace()
        let app = launch()
        try await joinPythonSpace(app)
        let stolen = try await py.deviceID(this: true)
        try await py.call("POST", "block", ["id": stolen])
        let blocked = try await py.call("POST", "sync")
        XCTAssertTrue(blocked.contains("BLOCKED"), blocked)

        openSettings(app)
        tap(app, "remove-devices")
        removeDevice(app, "A", devices: 2)
        waitForMessage(app, "The devices are removed, and the key is new.")

        try await py.call("POST", "unblock", ["id": stolen])
        let after = try await py.call("POST", "sync")
        XCTAssertTrue(after.contains("REMOVED"), after)
        syncNow(app)
        waitForStatus(app, "ok")
    }

    // MARK: T9

    /// T9, PROTOCOL.md 13.3: the app makes the space and shows its recovery
    /// key once (S1). The user cancels a replacement, then shows a new key,
    /// types it back with the current key, and replaces it. The old key
    /// then recovers nothing, and the new key recovers the space.
    func testReplaceTheRecoveryKey() async throws {
        try await py.call("POST", "user")
        let app = launch()
        let old = turnOnSync(app)
        waitForStatus(app, "ok")

        openSettings(app)
        tap(app, "replace-recovery-key")
        XCTAssertTrue(texts(app)["new-recovery-key"].waitForExistence(timeout: timeout))
        tap(app, "flow-cancel")
        XCTAssertTrue(texts(app)["new-recovery-key"].waitForNonExistence(timeout: timeout))

        let new = replaceRecoveryKey(app, current: old)
        waitForMessage(app, "The recovery key is replaced. Keep the new paper and destroy the old one.")
        XCTAssertNotEqual(new, old)

        do {
            try await py.call("POST", "recover", ["key": old])
            XCTFail("the old recovery key recovered the space")
        } catch let e as PythonError {
            XCTAssertTrue(e.text.contains("RecoveryError"), e.text)
        }
        try await py.call("POST", "recover", ["key": new])
        let status = try await py.call("POST", "sync")
        XCTAssertEqual(status, "ok")
    }

    // MARK: S5

    /// S5, PROTOCOL.md 13.4: all devices are lost. The app recovers the
    /// space with the paper recovery key, shows the tasks, and removes the
    /// lost device.
    func testRecoverWhenAllDevicesAreLost() async throws {
        let key = try await pythonSpaceWithTask()
        let app = launch()
        recover(app, key: key)
        removeDevice(app, "A", devices: 2)
        waitForMessage(app, "The devices are removed, and the key is new.")
        XCTAssertTrue(texts(app)["before the fire"].waitForExistence(timeout: timeout))
        let lost = try await py.call("POST", "sync")
        XCTAssertTrue(lost.contains("REMOVED"), lost)
    }

    /// S5 with a lost answer: the relay stores the grant of the app device,
    /// and the answer does not arrive. The app waits for the grant and does
    /// not fail. The user cancels, and "Recover again" while offline keeps
    /// the keys of the granted device. After a restart with a network, the
    /// sync finds the grant, and the removal shows one lost device and no
    /// second app device.
    func testRecoveryKeepsAGrantWithALostAnswer() async throws {
        let key = try await pythonSpaceWithTask()
        let data = UUID().uuidString
        let app = launch(data: data, fault: "offline-after-first-append")
        recover(app, key: key)
        let working = ui(app)["flow-working"]
        waitFor(working, "label CONTAINS 'Waiting for the grant of this device' OR value CONTAINS 'Waiting for the grant of this device'")
        tap(app, "flow-cancel")

        openSettings(app)
        type(app, "recover-again-key", key)
        tap(app, "recover-again")
        waitForMessage(app, "recover: ")
        app.terminate()

        let again = launch(data: data)
        waitForStatus(again, "ok")
        openSettings(again)
        tap(again, "remove-devices")
        removeDevice(again, "A", devices: 2)
        waitForMessage(again, "The devices are removed, and the key is new.")
    }

    // MARK: Fork repair

    /// `specs/forkrepair/test.qnt::repairTest` ([FRK-1] to [FRK-8]): the app
    /// writes "only on the app", applies it back, and the relay loses it
    /// with no hold. The Python device writes "on python" at the same
    /// position, and the app shows `stopped: fork` with the next step. The
    /// Python device is the source: it deletes the space and imports its
    /// log. The app joins again from it through the screens, gets its own
    /// change back from the old engine state, and sends it again with its
    /// old change ID. Both devices end with both tasks.
    func testForkRepairJoinsAgainFromTheSource() async throws {
        try await pythonSpace()
        let app = launch()
        try await joinPythonSpace(app)
        let synced = try await py.call("POST", "sync")
        XCTAssertEqual(synced, "ok")
        let head = try await py.call("GET", "head")

        // The edit starts a sync. The cut waits until the app reports that
        // it applied the change back, so its app outbox row is gone.
        type(app, "new-task", "only on the app")
        tap(app, "add-task")
        XCTAssertTrue(texts(app)["only on the app"].waitForExistence(timeout: timeout))
        try await py.call("POST", "cut", ["keep": head, "wait": "1"])
        try await py.call("POST", "edit", ["task": "p1", "field": "title", "value": #""on python""#])
        let wrote = try await py.call("POST", "sync")
        XCTAssertEqual(wrote, "ok")

        // [FRK-1]: the sync loop finds the fork.
        waitForStatus(app, "stopped: fork")
        XCTAssertTrue(texts(app)["sync-next-step"].exists)

        // [FRK-4], [FRK-5] on the source.
        let deleted = try await py.call("POST", "delete")
        XCTAssertTrue(deleted.contains("DELETED"), deleted)
        try await py.call("POST", "import")
        let imported = try await py.call("POST", "sync")
        XCTAssertEqual(imported, "ok")

        // [FRK-6] to [FRK-8] on the app.
        try await enrollFromPython(app, button: "rejoin-scan")
        waitForMessage(app, "This device joined again and sent 1 of its own changes again.")
        waitForStatus(app, "ok")
        XCTAssertFalse(texts(app)["sync-next-step"].exists)
        XCTAssertTrue(texts(app)["on python"].waitForExistence(timeout: timeout))
        XCTAssertTrue(texts(app)["only on the app"].exists)

        let after = try await py.call("POST", "sync")
        XCTAssertEqual(after, "ok")
        let data = Data(try await py.call("GET", "tasks").utf8)
        let got = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: [String: Any]])
        XCTAssertEqual(Set(got.values.compactMap { $0["title"] as? String }), ["on python", "only on the app"])
    }

    // MARK: Steps

    private func launch(data: String = UUID().uuidString, fault: String? = nil) -> XCUIApplication {
        let app = XCUIApplication()
        // The argument domain wins over a relay URL that a person saved. A
        // macOS app that stopped with no window restores no window.
        app.launchArguments = ["-relayURL", relay, "-ApplePersistenceIgnoreState", "YES"]
        app.launchEnvironment = ["SNAILFISH_UITEST_APPROVER": approver, "SNAILFISH_UITEST_DATA": data]
        if let fault { app.launchEnvironment["SNAILFISH_UITEST_FAULT"] = fault }
        app.launch()
        return app
    }

    /// A Python space with one task. Returns the recovery key.
    private func pythonSpaceWithTask() async throws -> String {
        try await pythonSpace(task: "before the fire")
        return try await py.call("GET", "recovery-key")
    }

    /// A Python device of a new user makes the space. The first sync
    /// creates it on the relay.
    private func pythonSpace(task: String? = nil) async throws {
        try await py.call("POST", "user")
        try await py.call("POST", "setup")
        if let task {
            try await py.call("POST", "edit", ["task": "p1", "field": "title", "value": "\"\(task)\""])
        }
        let synced = try await py.call("POST", "sync")
        XCTAssertEqual(synced, "ok")
    }

    /// S2: the Python device shows the session, and the app scans its
    /// payload. Each side confirms only if the codes match ([ENR-7]).
    private func joinPythonSpace(_ app: XCUIApplication) async throws {
        try await enrollFromPython(app, button: "join-scan")
        waitForMessage(app, "This device joined.")
        waitForStatus(app, "ok")
    }

    /// The enrollment of S2 with the Python device as the trusted device.
    /// `button` starts the scan in the sync settings of the app.
    private func enrollFromPython(_ app: XCUIApplication, button: String) async throws {
        let payload = try await py.call("POST", "invite")
        openSettings(app)
        tap(app, button)
        type(app, "scan-payload", payload)
        tap(app, "scan-use")
        let code = texts(app)["compare-code"]
        XCTAssertTrue(code.waitForExistence(timeout: timeout))
        let theirs = try await py.call("POST", "compare", ["code": text(code)])
        XCTAssertEqual(theirs, text(code))
        tap(app, "compare-yes")
        let result = try await py.call("GET", "invite/result")
        XCTAssertEqual(result, "")
    }

    /// S1: sign in, make the space, and type the recovery key back.
    /// Returns the recovery key.
    private func turnOnSync(_ app: XCUIApplication) -> String {
        openSettings(app)
        tap(app, "turn-on-sync")
        let shown = texts(app)["recovery-key"]
        XCTAssertTrue(shown.waitForExistence(timeout: timeout))
        let key = text(shown)
        type(app, "recovery-typed", key)
        tap(app, "recovery-check")
        XCTAssertTrue(shown.waitForNonExistence(timeout: timeout))
        return key
    }

    /// Show a new recovery key, type it back with the current key, and
    /// replace. Returns the new key.
    @discardableResult
    private func replaceRecoveryKey(_ app: XCUIApplication, current: String) -> String {
        openSettings(app)
        tap(app, "replace-recovery-key")
        let shown = texts(app)["new-recovery-key"]
        XCTAssertTrue(shown.waitForExistence(timeout: timeout))
        let new = text(shown)
        type(app, "replace-typed", new)
        type(app, "replace-current", current)
        tap(app, "replace-key")
        return new
    }

    private func recover(_ app: XCUIApplication, key: String) {
        openSettings(app)
        type(app, "recover-key", key)
        tap(app, "recover")
    }

    /// Pick the device `name` on the removal screen, check that it leaves
    /// the list of the devices that stay, and remove it. `devices` is the
    /// number of active devices that the screen must list.
    private func removeDevice(_ app: XCUIApplication, _ name: String, devices: Int) {
        let toggle = ui(app)["remove-\(name)"]
        XCTAssertTrue(toggle.waitForExistence(timeout: timeout))
        let toggles = ui(app).matching(
            NSPredicate(format: "identifier BEGINSWITH 'remove-' AND NOT identifier IN {'remove-confirm', 'remove-devices'}"))
        XCTAssertEqual(toggles.count, devices, toggles.debugDescription)
        let stays = texts(app)["• \(name)"]
        XCTAssertTrue(stays.exists)
        #if os(iOS)
            // The switch is at the trailing edge of the toggle row.
            toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.95, dy: 0.5)).tap()
        #else
            toggle.click()
        #endif
        XCTAssertTrue(stays.waitForNonExistence(timeout: timeout), "the device still stays")
        tap(app, "remove-confirm")
    }

    private func openSettings(_ app: XCUIApplication) {
        tap(app, "sync-settings")
    }

    private func syncNow(_ app: XCUIApplication) {
        openSettings(app)
        tap(app, "sync-now")
        tap(app, "Done")
    }

    // MARK: Elements

    /// The elements of the app. On macOS only the windows, because a
    /// toolbar button also has a Touch Bar element, and a click refuses it.
    private func ui(_ app: XCUIApplication) -> XCUIElementQuery {
        #if os(macOS)
            app.windows.descendants(matching: .any)
        #else
            app.descendants(matching: .any)
        #endif
    }

    private func texts(_ app: XCUIApplication) -> XCUIElementQuery {
        #if os(macOS)
            app.windows.staticTexts
        #else
            app.staticTexts
        #endif
    }

    private func element(_ app: XCUIApplication, _ id: String) -> XCUIElement {
        let e = ui(app)[id].firstMatch
        #if os(iOS)
            // A form has no element for a row far below the screen. A tap
            // scrolls to an element that exists.
            for _ in 0..<3 {
                if e.exists || e.waitForExistence(timeout: 2) { break }
                app.swipeUp()
            }
        #endif
        XCTAssertTrue(e.waitForExistence(timeout: timeout), "no element \(id)")
        return e
    }

    /// The string of a SwiftUI `Text`: its label on iOS, its value on macOS.
    private func text(_ e: XCUIElement) -> String {
        e.label.isEmpty ? (e.value as? String ?? "") : e.label
    }

    private func tap(_ app: XCUIApplication, _ id: String) {
        let e = element(app, id)
        waitFor(e, "enabled == true")
        #if os(iOS)
            e.tap()
        #else
            e.click()
        #endif
    }

    private func type(_ app: XCUIApplication, _ id: String, _ text: String) {
        let e = element(app, id)
        #if os(iOS)
            e.tap()
        #else
            e.click()
        #endif
        e.typeText(text)
    }

    private func waitFor(_ e: XCUIElement, _ predicate: String, file: StaticString = #filePath, line: UInt = #line) {
        let x = XCTNSPredicateExpectation(predicate: NSPredicate(format: predicate), object: e)
        let r = XCTWaiter().wait(for: [x], timeout: timeout)
        XCTAssertEqual(r, .completed, "\(predicate): \(e.debugDescription)", file: file, line: line)
    }

    /// Wait for the status bar text "Sync: <status>".
    private func waitForStatus(_ app: XCUIApplication, _ status: String, file: StaticString = #filePath, line: UInt = #line) {
        waitFor(texts(app)["sync-status"], "label BEGINSWITH 'Sync: \(status)' OR value BEGINSWITH 'Sync: \(status)'", file: file, line: line)
    }

    /// Wait for the alert of the app message that contains `text`, and close
    /// it.
    private func waitForMessage(_ app: XCUIApplication, _ text: String, file: StaticString = #filePath, line: UInt = #line) {
        let m = texts(app).matching(NSPredicate(format: "label CONTAINS %@ OR value CONTAINS %@", text, text)).firstMatch
        XCTAssertTrue(m.waitForExistence(timeout: timeout), "no message \(text)", file: file, line: line)
        tap(app, "OK")
    }
}
