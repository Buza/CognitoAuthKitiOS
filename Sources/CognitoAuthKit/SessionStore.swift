//
//  SessionStore.swift
//  CognitoAuthKit
//
//  Created by Kyle Buza on 4/17/25.
//

import Foundation
import BLog
@preconcurrency import AWSCognitoIdentityProvider

extension AWSCognitoIdentityUserSession: @unchecked @retroactive Sendable {}
extension AWSCognitoIdentityUser: @unchecked @retroactive Sendable {}

enum AuthError: Error {
    case noTokens
}

struct SessionLogger {
    static let shared = BLog(subsystem: "com.buzamoto.cognitoauthios",
                             category: "SessionStore",
                             prefix: "<SessionStore>")
    static func log(_ message: String, level: LogLevel = .info) {
        switch level {
        case .info:
            shared.pinfo(message)
        case .error, .warning:
            shared.perror(message)
        case .debug:
            shared.pdebug(message)
        }
    }
}

protocol SessionStore: Actor {
    func tokens() async throws -> (id: String, access: String)
    func setCognitoTokens(accessToken: String, idToken: String, refreshToken: String, expiresIn: TimeInterval) async
}

actor CognitoSessionStore: SessionStore {
    private let user: AWSCognitoIdentityUser
    private var sessionTask: Task<AWSCognitoIdentityUserSession, Error>?
    private var externalTokens: (accessToken: String, idToken: String, refreshToken: String, expiresAt: Date)?
    private let keychainKey = "CognitoAuthKit.externalTokens"
    private let keychainAccessGroup: String?

    init(user: AWSCognitoIdentityUser, keychainAccessGroup: String? = nil) {
        self.user = user
        self.keychainAccessGroup = keychainAccessGroup

        // Migrate tokens from app-scoped keychain to shared group if needed
        if let group = keychainAccessGroup {
            if KeychainHelper.migrateToAccessGroup(for: keychainKey, accessGroup: group) {
                SessionLogger.log("Migrated external tokens to shared keychain group")
            }
        }

        // Try to restore external tokens from Keychain
        self.externalTokens = Self.loadExternalTokens(keychainKey: keychainKey, accessGroup: keychainAccessGroup)
    }
    
    func signIn(username: String, password: String) async throws {
        sessionTask = Task { try await fetchSession(username: username, password: password) }
        _ = try await sessionTask!.value
    }
    
    func tokens() async throws -> (id: String, access: String) {
        // Handle external tokens (Apple Sign-In)
        if let tokens = externalTokens {
            // Check if tokens are still valid (with 60 second buffer)
            if tokens.expiresAt.timeIntervalSinceNow > 60 {
                return (tokens.idToken, tokens.accessToken)
            }

            // Tokens expired, try to refresh them
            SessionLogger.log("External tokens expired, attempting refresh")
            do {
                if let refreshedTokens = try await refreshExternalTokens(refreshToken: tokens.refreshToken) {
                    return (refreshedTokens.idToken, refreshedTokens.accessToken)
                }
            } catch {
                SessionLogger.log("External token refresh threw: \(error.localizedDescription)", level: .warning)
            }

            // If refresh failed, clear external tokens and fall through to native session
            SessionLogger.log("External token refresh failed, clearing tokens", level: .warning)
            externalTokens = nil
            Self.clearExternalTokens(keychainKey: keychainKey, accessGroup: keychainAccessGroup)
        }

        // Fall back to native Cognito session
        let session = try await validSession()
        guard let id = session.idToken?.tokenString,
              let access = session.accessToken?.tokenString else {
            throw AuthError.noTokens
        }

        // Persist native session tokens to shared keychain so other apps can read them
        if keychainAccessGroup != nil {
            let refreshToken = session.refreshToken?.tokenString ?? ""
            let expiresAt = session.expirationTime ?? Date().addingTimeInterval(3600)
            Self.saveExternalTokens(
                accessToken: access,
                idToken: id,
                refreshToken: refreshToken,
                expiresAt: expiresAt,
                keychainKey: keychainKey,
                accessGroup: keychainAccessGroup
            )
            externalTokens = (access, id, refreshToken, expiresAt)
            SessionLogger.log("Persisted native session tokens to shared keychain")
        }

        return (id, access)
    }

    func setCognitoTokens(accessToken: String, idToken: String, refreshToken: String, expiresIn: TimeInterval) async {
        let expiresAt = Date().addingTimeInterval(expiresIn)
        externalTokens = (accessToken, idToken, refreshToken, expiresAt)

        // Persist tokens to Keychain
        Self.saveExternalTokens(
            accessToken: accessToken,
            idToken: idToken,
            refreshToken: refreshToken,
            expiresAt: expiresAt,
            keychainKey: keychainKey,
            accessGroup: keychainAccessGroup
        )
    }

    private static func saveExternalTokens(
        accessToken: String,
        idToken: String,
        refreshToken: String,
        expiresAt: Date,
        keychainKey: String,
        accessGroup: String? = nil
    ) {
        let tokenData: [String: Any] = [
            "accessToken": accessToken,
            "idToken": idToken,
            "refreshToken": refreshToken,
            "expiresAt": expiresAt.timeIntervalSince1970
        ]

        do {
            let data = try JSONSerialization.data(withJSONObject: tokenData)
            try KeychainHelper.save(data, for: keychainKey, accessGroup: accessGroup)
        } catch {
            // Log error but don't fail - session will work until app restart
            print("Failed to save external tokens to Keychain: \(error)")
        }
    }

    private static func loadExternalTokens(keychainKey: String, accessGroup: String? = nil) -> (accessToken: String, idToken: String, refreshToken: String, expiresAt: Date)? {
        do {
            let data = try KeychainHelper.load(for: keychainKey, accessGroup: accessGroup)
            guard let tokenData = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let accessToken = tokenData["accessToken"] as? String,
                  let idToken = tokenData["idToken"] as? String,
                  let refreshToken = tokenData["refreshToken"] as? String,
                  let expiresAtInterval = tokenData["expiresAt"] as? TimeInterval else {
                return nil
            }

            let expiresAt = Date(timeIntervalSince1970: expiresAtInterval)
            return (accessToken, idToken, refreshToken, expiresAt)
        } catch {
            // No tokens or error loading - that's OK
            return nil
        }
    }

    static func clearExternalTokens(keychainKey: String, accessGroup: String? = nil) {
        KeychainHelper.delete(for: keychainKey, accessGroup: accessGroup)
    }

    private func refreshExternalTokens(refreshToken: String) async throws -> (accessToken: String, idToken: String)? {
        // Get the user pool instance
        guard let userPool = AWSCognitoIdentityUserPool(forKey: "UserPool") else {
            SessionLogger.log("No user pool available for token refresh", level: .error)
            return nil
        }

        // Guard: AWSCognitoIdentityProvider.default() throws an NSException if
        // no default service configuration exists (e.g. in companion apps that
        // only read shared tokens). Check before calling.
        guard AWSServiceManager.default().defaultServiceConfiguration != nil else {
            SessionLogger.log("No default AWS service config — cannot refresh tokens", level: .warning)
            return nil
        }

        // Create the identity provider service client
        let identityProvider = AWSCognitoIdentityProvider.default()

        // Create refresh request using AWS Cognito's InitiateAuth API
        let request = AWSCognitoIdentityProviderInitiateAuthRequest()
        request?.clientId = userPool.userPoolConfiguration.clientId
        request?.authFlow = .refreshTokenAuth
        request?.authParameters = ["REFRESH_TOKEN": refreshToken]

        do {
            let response = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<AWSCognitoIdentityProviderInitiateAuthResponse, Error>) in
                identityProvider.initiateAuth(request!).continueWith { task in
                    if let error = task.error {
                        SessionLogger.log("Failed to refresh external tokens: \(error.localizedDescription)", level: .error)
                        continuation.resume(throwing: error)
                    } else if let result = task.result {
                        continuation.resume(returning: result)
                    } else {
                        continuation.resume(throwing: AuthError.noTokens)
                    }
                    return nil
                }
            }

            guard let authResult = response.authenticationResult,
                  let newAccessToken = authResult.accessToken,
                  let newIdToken = authResult.idToken,
                  let expiresIn = authResult.expiresIn else {
                SessionLogger.log("Refresh response missing required tokens", level: .error)
                return nil
            }

            // Update stored tokens with refreshed values
            let expiresAt = Date().addingTimeInterval(TimeInterval(truncating: expiresIn))
            externalTokens = (newAccessToken, newIdToken, refreshToken, expiresAt)

            // Persist updated tokens to Keychain
            Self.saveExternalTokens(
                accessToken: newAccessToken,
                idToken: newIdToken,
                refreshToken: refreshToken,
                expiresAt: expiresAt,
                keychainKey: keychainKey,
                accessGroup: keychainAccessGroup
            )

            SessionLogger.log("Successfully refreshed external tokens")
            return (newAccessToken, newIdToken)
        } catch {
            SessionLogger.log("Error refreshing external tokens: \(error.localizedDescription)", level: .error)
            throw error
        }
    }
    
    private func validSession() async throws -> AWSCognitoIdentityUserSession {
        if let task = sessionTask {
            let session = try await task.value
            if let expiry = session.expirationTime, expiry.timeIntervalSinceNow > 60 {
                return session
            }
        }
        sessionTask = Task { try await fetchSession() }
        return try await sessionTask!.value
    }
    
    private func fetchSession(username: String? = nil, password: String? = nil) async throws -> AWSCognitoIdentityUserSession {
        try await withCheckedThrowingContinuation { continuation in
            if let u = username, let p = password {
                user.getSession(u, password: p, validationData: nil).continueWith { task in
                    if let error = task.error {
                        continuation.resume(throwing: error)
                    } else if let result = task.result {
                        continuation.resume(returning: result)
                    }
                    return nil
                }
            } else {
                user.getSession().continueWith { task in
                    if let error = task.error {
                        continuation.resume(throwing: error)
                    } else if let result = task.result {
                        continuation.resume(returning: result)
                    }
                    return nil
                }
            }
        }
    }
}


