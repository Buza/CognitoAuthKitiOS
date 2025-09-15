//
//  SessionStore.swift
//  CognitoAuthKit
//
//  Created by Kyle Buza on 4/17/25.
//

import Foundation
@preconcurrency import AWSCognitoIdentityProvider

extension AWSCognitoIdentityUserSession: @unchecked @retroactive Sendable {}
extension AWSCognitoIdentityUser: @unchecked @retroactive Sendable {}

enum AuthError: Error {
    case noTokens
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

    init(user: AWSCognitoIdentityUser) {
        self.user = user
        // Try to restore external tokens from Keychain
        self.externalTokens = Self.loadExternalTokens(keychainKey: keychainKey)
    }
    
    func signIn(username: String, password: String) async throws {
        sessionTask = Task { try await fetchSession(username: username, password: password) }
        _ = try await sessionTask!.value
    }
    
    func tokens() async throws -> (id: String, access: String) {
        if let tokens = externalTokens, tokens.expiresAt.timeIntervalSinceNow > 60 {
            return (tokens.idToken, tokens.accessToken)
        }

        let session = try await validSession()
        guard let id = session.idToken?.tokenString,
              let access = session.accessToken?.tokenString else {
            throw AuthError.noTokens
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
            keychainKey: keychainKey
        )
    }

    private static func saveExternalTokens(
        accessToken: String,
        idToken: String,
        refreshToken: String,
        expiresAt: Date,
        keychainKey: String
    ) {
        let tokenData: [String: Any] = [
            "accessToken": accessToken,
            "idToken": idToken,
            "refreshToken": refreshToken,
            "expiresAt": expiresAt.timeIntervalSince1970
        ]

        do {
            let data = try JSONSerialization.data(withJSONObject: tokenData)
            try KeychainHelper.save(data, for: keychainKey)
        } catch {
            // Log error but don't fail - session will work until app restart
            print("Failed to save external tokens to Keychain: \(error)")
        }
    }

    private static func loadExternalTokens(keychainKey: String) -> (accessToken: String, idToken: String, refreshToken: String, expiresAt: Date)? {
        do {
            let data = try KeychainHelper.load(for: keychainKey)
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

    static func clearExternalTokens(keychainKey: String) {
        KeychainHelper.delete(for: keychainKey)
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


