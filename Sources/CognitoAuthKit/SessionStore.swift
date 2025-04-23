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

actor CognitoSessionStore {
    private let user: AWSCognitoIdentityUser
    private var sessionTask: Task<AWSCognitoIdentityUserSession, Error>?
    
    init(user: AWSCognitoIdentityUser) { self.user = user }
    
    func signIn(username: String, password: String) async throws {
        sessionTask = Task { try await fetchSession(username: username, password: password) }
        _ = try await sessionTask!.value
    }
    
    func tokens() async throws -> (id: String, access: String) {
        let session = try await validSession()
        guard let id = session.idToken?.tokenString,
              let access = session.accessToken?.tokenString else {
            throw AuthError.noTokens
        }
        return (id, access)
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
