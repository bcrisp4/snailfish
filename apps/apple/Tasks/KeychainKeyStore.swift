import Foundation
import Security
import Snailfish

/// The key store of the app: the data protection keychain (DESIGN.md "App
/// integration", T14, C62).
///
/// - Each item is a generic password with
///   `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, so a backup or a
///   migration does not copy the keys to another device. Background sync
///   can read the keys while the device is locked, after the first unlock.
/// - Each query sets `kSecUseDataProtectionKeychain`. On macOS the default
///   is the file-based keychain, which ignores `ThisDeviceOnly`.
/// - The store fails closed. On `errSecMissingEntitlement` (-34018), it
///   throws, and it never retries with the file-based keychain.
final class KeychainKeyStore: KeyStore, @unchecked Sendable {
    let service: String

    init(service: String) {
        self.service = service
    }

    private func base(_ account: String) -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecUseDataProtectionKeychain: true,
        ]
    }

    func load(account: String) throws -> Data? {
        var q = base(account)
        q[kSecReturnData] = true
        q[kSecMatchLimit] = kSecMatchLimitOne
        var out: CFTypeRef?
        let rc = SecItemCopyMatching(q as CFDictionary, &out)
        if rc == errSecItemNotFound { return nil }
        try check(rc, "read")
        guard let data = out as? Data else { throw KeyStoreError.Failed(message: "the keychain item has no data") }
        return data
    }

    func store(account: String, secret: Data) throws {
        let attrs: [CFString: Any] = [
            kSecValueData: secret,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let rc = SecItemUpdate(base(account) as CFDictionary, attrs as CFDictionary)
        if rc != errSecItemNotFound {
            return try check(rc, "update")
        }
        let add = base(account).merging(attrs) { $1 }
        try check(SecItemAdd(add as CFDictionary, nil), "add")
    }

    /// Remove the item, for a test or for a space that the app leaves.
    func delete(account: String) throws {
        let rc = SecItemDelete(base(account) as CFDictionary)
        if rc != errSecItemNotFound { try check(rc, "delete") }
    }

    private func check(_ rc: OSStatus, _ op: String) throws {
        guard rc != errSecSuccess else { return }
        let text = (SecCopyErrorMessageString(rc, nil) as String?) ?? "OSStatus \(rc)"
        if rc == errSecMissingEntitlement {
            throw KeyStoreError.Failed(
                message: "keychain \(op): errSecMissingEntitlement (\(rc)). The build has no "
                    + "keychain-access-groups entitlement, so the data protection keychain is "
                    + "not available. Sign the app with a provisioning profile.")
        }
        throw KeyStoreError.Failed(message: "keychain \(op): \(text) (\(rc))")
    }
}
