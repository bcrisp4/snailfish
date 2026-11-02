import AuthenticationServices
import Foundation
import Snailfish

/// The private-use redirect URI of the native sign-in (PROTOCOL.md 12.2). The
/// scheme holds a `.`, and the URI has no authority part.
let redirectScheme = "com.example.tasks"
let redirectURI = "com.example.tasks:/callback"

/// Opens the authorize URL in the system browser and returns the URL that the
/// relay redirects to.
@MainActor
final class WebSignIn: NSObject, ASWebAuthenticationPresentationContextProviding {
    private var session: ASWebAuthenticationSession?

    func redirect(for url: URL) async throws -> URL {
        try await withCheckedThrowingContinuation { cont in
            let s = ASWebAuthenticationSession(url: url, callbackURLScheme: redirectScheme) { url, error in
                if let url {
                    cont.resume(returning: url)
                } else if let e = error as? ASWebAuthenticationSessionError, e.code == .canceledLogin {
                    cont.resume(throwing: SetupError.cancelled)
                } else {
                    cont.resume(throwing: error ?? SetupError.cancelled)
                }
            }
            s.presentationContextProvider = self
            // The passkey session of the relay page persists between
            // sign-ins, as in Safari.
            s.prefersEphemeralWebBrowserSession = false
            session = s
            if !s.start() {
                cont.resume(throwing: SetupError.message("the browser sign-in did not start"))
            }
        }
    }

    nonisolated func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        MainActor.assumeIsolated {
            #if os(iOS)
                let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
                return scenes.flatMap(\.windows).first { $0.isKeyWindow } ?? ASPresentationAnchor()
            #else
                return NSApplication.shared.keyWindow ?? ASPresentationAnchor()
            #endif
        }
    }
}

/// The native sign-in of PROTOCOL.md 12.2 and 12.3: the user signs in with a
/// passkey in the browser and allows the app, and the device key exchanges
/// the code for a setup token and the tenant handle. It follows `sign_in`
/// in demo/src/snailfish_demo/app.py.
func signIn(
    relayURL: String, keys: DeviceKeys, transport: Transport, browser: (URL) async throws -> URL
) async throws -> SetupToken {
    let si = try SignIn(relayUrl: relayURL, redirectUri: redirectURI)
    guard let authorize = URL(string: si.authorizeUrl()) else { throw SetupError.message("bad authorize URL") }
    let redirect = try await browser(authorize).absoluteString
    let now = { UInt64(Date().timeIntervalSince1970) }
    let (status, headers, body) = try await transport.send(try si.tokenRequest(redirect: redirect, keys: keys, now: now()))
    do {
        return try si.readToken(status: status, headers: headers, body: body)
    } catch SnailfishError.Invalid(let message) where message.contains("expired") {
        // PROTOCOL.md 8.5: after `expired`, send once more with the relay time.
        let (status, headers, body) = try await transport.send(
            try si.tokenRequest(redirect: redirect, keys: keys, now: now()))
        return try si.readToken(status: status, headers: headers, body: body)
    }
}

/// The first device creates the space (S1): sign-in, then the genesis record
/// and the recovery key. The next sync creates the space on the relay.
///
/// - Returns: The recovery key in its display form. Show it once.
func createSpace(
    device: SyncDevice, relayURL: String, name: String, transport: Transport,
    browser: (URL) async throws -> URL
) async throws -> String {
    var keys = try newDeviceKeys()
    let token = try await signIn(relayURL: relayURL, keys: keys, transport: transport, browser: browser)
    let setup = try Snailfish.createSpace(appId: appID, first: NewDevice(keys: keys, name: name))
    keys.appKey = setup.appKey
    let space = SpaceRef(relayUrl: relayURL, tenant: token.tenant, logId: setup.logId, appId: appID)
    try await device.turnOnSync(space: space, keys: keys, envelopes: setup.envelopes, setupToken: token.token)
    return setup.recoveryKey
}
