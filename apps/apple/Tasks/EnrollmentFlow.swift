import Foundation
import Snailfish

/// The questions that an enrollment asks the user.
protocol EnrollmentUI: AnyObject, Sendable {
    /// Show the QR payload and the typed code of this device.
    func show(payload: String, code: String) async
    /// Ask whether the 6-digit code matches the code on the other device
    /// ([ENR-7]).
    func compare(code: String) async -> Bool
    /// Trusted device only: the device list changed after the user
    /// confirmed, so ask again ([LOG-7]).
    func confirmAgain() async -> Bool
}

/// How long an enrollment waits between two reads of the session. The
/// relay limits the rate for each IP address, so do not poll faster.
private let pollNanoseconds: UInt64 = 200_000_000

private func ended(_ s: EnrollState) -> Bool {
    switch s {
    case .done, .failed: return true
    default: return false
    }
}

private func cause(_ s: EnrollState) -> String {
    if case .failed(let c) = s { return c }
    return ""
}

/// Enroll a new device from this trusted device ([ENR-1] to [ENR-8]). If
/// `scanned` is nil, this device shows the session. It follows `invite` in
/// demo/src/snailfish_demo/app.py.
///
/// - Returns: An empty string on success, or the cause of the failure.
func invite(engine: Engine, scanned: String?, transport: Transport, ui: EnrollmentUI) async throws -> String {
    let t = try TrustedEnrollment(engine: engine, scanned: scanned, recoveryKey: nil)
    var shown = scanned != nil
    while case let state = try t.state(), !ended(state) {
        try Task.checkCancellation()
        // The payload exists once the relay opened the session.
        if !shown, let payload = try t.payload(), let code = try t.code() {
            await ui.show(payload: payload, code: code)
            shown = true
        }
        switch state {
        case .compare(let code):
            try t.confirm(yes: await ui.compare(code: code))
            continue
        case .confirmAgain:
            try t.confirm(yes: await ui.confirmAgain())
            continue
        default:
            break
        }
        guard let req = try t.nextRequest() else { break }
        let (status, headers, body) = try await transport.send(req)
        try t.handleResponse(status: status, headers: headers, body: body)
        if try t.state() == .waiting {
            try await Task.sleep(nanoseconds: pollNanoseconds)
        }
    }
    return cause(try t.state())
}

/// Join a space as a new device ([ENR-1] to [ENR-9]). The function makes
/// the device keys. If `scanned` is nil, this device shows the session. On
/// success the device stores its engine state and keys, and its first sync
/// checks the log up to the checkpoint before it uploads anything. It
/// follows `join` in demo/src/snailfish_demo/app.py.
///
/// - Returns: An empty string on success, or the cause of the failure.
func join(
    device: SyncDevice, relayURL: String, name: String, scanned: String?, transport: Transport, ui: EnrollmentUI
) async throws -> String {
    let keys = try newDeviceKeys()
    let n = try NewEnrollment(relayUrl: relayURL, keys: keys, name: name, scanned: scanned)
    if let payload = try n.payload() {
        await ui.show(payload: payload, code: try n.code())
    }
    while case let state = try n.state(), !ended(state) {
        try Task.checkCancellation()
        if case .compare(let code) = state {
            try n.confirm(yes: await ui.compare(code: code))
            continue
        }
        guard let req = try n.nextRequest() else { break }
        let (status, _, body) = try await transport.send(req)
        try n.handleResponse(status: status, body: body)
        if try n.state() == .waiting {
            try await Task.sleep(nanoseconds: pollNanoseconds)
        }
    }
    guard let joined = try n.joined() else {
        let c = cause(try n.state())
        return c.isEmpty ? "the enrollment ended with no result" : c
    }
    let space = SpaceRef(relayUrl: try n.relayUrl(), tenant: joined.tenant, logId: joined.logId, appId: appID)
    try await device.finishJoin(space: space, keys: keys, joined: joined)
    return ""
}
