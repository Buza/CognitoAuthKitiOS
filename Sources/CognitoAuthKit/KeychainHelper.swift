//
//  KeychainHelper.swift
//  CognitoAuthKit
//
//  Created by Kyle Buza on 1/24/25.
//

import Foundation
import Security

struct KeychainHelper {
    private static let service = "com.buzamoto.cognitoauthkit"

    enum KeychainError: Error {
        case itemNotFound
        case unexpectedData
        case unhandledError(status: OSStatus)
    }

    static func save(_ data: Data, for key: String, accessGroup: String? = nil) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecValueData as String: data
        ]
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }

        // First try to delete any existing item
        SecItemDelete(query as CFDictionary)

        // Then add the new item
        let status = SecItemAdd(query as CFDictionary, nil)

        guard status == errSecSuccess else {
            throw KeychainError.unhandledError(status: status)
        }
    }

    static func load(for key: String, accessGroup: String? = nil) throws -> Data {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status != errSecItemNotFound else {
            throw KeychainError.itemNotFound
        }

        guard status == errSecSuccess else {
            throw KeychainError.unhandledError(status: status)
        }

        guard let data = result as? Data else {
            throw KeychainError.unexpectedData
        }

        return data
    }

    static func delete(for key: String, accessGroup: String? = nil) {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }

        SecItemDelete(query as CFDictionary)
    }

    /// Migrate a keychain item from the default (app-scoped) storage to a shared access group.
    /// Returns true if a migration occurred.
    @discardableResult
    static func migrateToAccessGroup(for key: String, accessGroup: String) -> Bool {
        // Check if item already exists in shared group
        if let _ = try? load(for: key, accessGroup: accessGroup) {
            return false // already migrated
        }
        // Try loading from the old (no access group) location
        guard let data = try? load(for: key, accessGroup: nil) else {
            return false // nothing to migrate
        }
        // Save to the shared group
        do {
            try save(data, for: key, accessGroup: accessGroup)
            // Delete the old entry
            delete(for: key, accessGroup: nil)
            return true
        } catch {
            return false
        }
    }
}
