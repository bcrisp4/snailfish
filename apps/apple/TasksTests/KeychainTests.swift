import Security
import Snailfish
import XCTest

@testable import Tasks

/// Whether this process has a keychain access group. An unsigned build has
/// none, so the data protection keychain refuses it on macOS.
func hasKeychainEntitlement() -> Bool {
    #if os(macOS)
        guard let task = SecTaskCreateFromSelf(nil) else { return false }
        return SecTaskCopyValueForEntitlement(task, "keychain-access-groups" as CFString, nil) != nil
    #else
        // The simulator and a device always give an app its own group.
        return true
    #endif
}

final class KeychainTests: XCTestCase {
    private var store: KeychainKeyStore!
    private let account = "l_" + String(repeating: "7", count: 32)

    override func setUp() {
        store = KeychainKeyStore(service: "snailfish.tests." + UUID().uuidString)
    }

    override func tearDown() {
        try? store.delete(account: account)
    }

    /// T14: with the entitlement, an item round-trips, an update replaces
    /// it, and its accessibility is AfterFirstUnlockThisDeviceOnly, so a
    /// backup or a migration does not copy it.
    func testItemRoundTripsWithThisDeviceOnly() throws {
        try XCTSkipUnless(hasKeychainEntitlement(), "covered by testUnsignedMacFailsClosed on this build")
        XCTAssertNil(try store.load(account: account))
        try store.store(account: account, secret: Data(repeating: 1, count: 96))
        try store.store(account: account, secret: Data(repeating: 2, count: 96))
        XCTAssertEqual(try store.load(account: account), Data(repeating: 2, count: 96))

        let q: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword, kSecAttrService: store.service, kSecAttrAccount: account,
            kSecUseDataProtectionKeychain: true, kSecReturnAttributes: true, kSecMatchLimit: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        XCTAssertEqual(SecItemCopyMatching(q as CFDictionary, &out), errSecSuccess)
        let attrs = try XCTUnwrap(out as? [CFString: Any])
        XCTAssertEqual(attrs[kSecAttrAccessible] as? String, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
    }

    /// C62: without the entitlement, the macOS store fails with
    /// errSecMissingEntitlement and writes nothing to the file-based
    /// keychain. The engine then refuses to open or install.
    func testUnsignedMacFailsClosed() throws {
        #if os(macOS)
            try XCTSkipIf(hasKeychainEntitlement(), "covered by testItemRoundTripsWithThisDeviceOnly on this build")
            XCTAssertThrowsError(try store.store(account: account, secret: Data(repeating: 1, count: 96))) {
                guard case KeyStoreError.Failed(let m) = $0 else { return XCTFail("\($0)") }
                XCTAssertTrue(m.contains("errSecMissingEntitlement"), m)
            }
            // A read without the entitlement finds no item: macOS returns
            // errSecItemNotFound, not errSecMissingEntitlement.
            XCTAssertNil(try store.load(account: account))
            // No fallback: the file-based keychain has no item either.
            let legacy: [CFString: Any] = [
                kSecClass: kSecClassGenericPassword, kSecAttrService: store.service, kSecAttrAccount: account,
            ]
            XCTAssertEqual(SecItemCopyMatching(legacy as CFDictionary, nil), errSecItemNotFound)

            let space = SpaceRef(
                relayUrl: "https://r.example", tenant: "t_" + String(repeating: "0", count: 32), logId: account,
                appId: appID)
            let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            defer { try? FileManager.default.removeItem(at: dir) }
            XCTAssertThrowsError(try Engine.open(dataDir: dir.path, space: space, keyStore: store)) {
                guard case SnailfishError.KeyStore = $0 else { return XCTFail("\($0)") }
            }
            var keys = try newDeviceKeys()
            let setup = try createSpace(appId: appID, first: NewDevice(keys: keys, name: "A"))
            keys.appKey = setup.appKey
            var created = space
            created.logId = setup.logId
            XCTAssertThrowsError(
                try installSetup(
                    dataDir: dir.appendingPathComponent("a").path, space: created, keys: keys,
                    envelopes: setup.envelopes, setupToken: "st_" + String(repeating: "0", count: 64), keyStore: store)
            ) {
                guard case SnailfishError.KeyStore(let m) = $0 else { return XCTFail("\($0)") }
                XCTAssertTrue(m.contains("errSecMissingEntitlement"), m)
            }
        #else
            throw XCTSkip("macOS only: iOS has no file-based keychain")
        #endif
    }
}
