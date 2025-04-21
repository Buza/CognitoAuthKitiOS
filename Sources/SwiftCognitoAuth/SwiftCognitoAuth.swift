//
//  SwiftCognitoAuth.swift
//  SwiftCognitoAuth
//
//  Kyle Buza (2024).
//

import BLog
import AWSCognitoIdentityProvider

struct AuthLogger {
    nonisolated(unsafe) static let shared = BLog(subsystem: "com.buzamoto.cognitoauth",
                                                 category: "Auth",
                                                 prefix: "<CognitoAuth>")
    static func log(_ message: String, level: LogLevel = .info) {
        switch level {
        case .info:
            shared.pinfo(message)
        case .error,. warning:
            shared.perror(message)
        case .debug: 
            shared.pdebug(message)
        }
    }
}

struct APIRequestLogger {
    nonisolated(unsafe) static let shared = BLog(subsystem: "com.buzamoto.cognitoauth",
                                                 category: "APIRequest",
                                                 prefix: "<APIRequest>")
    static func log(_ message: String, level: LogLevel = .info) {
        switch level {
        case .info:
            shared.pinfo(message)
        case .error,. warning:
            shared.perror(message)
        case .debug:
            shared.pdebug(message)
        }
    }
}

final class AuthCoordinator: NSObject, AWSCognitoIdentityInteractiveAuthenticationDelegate, Sendable {
    
    let username : String?
    let password : String?
    
    init(username: String? = nil, password: String? = nil) {
        self.username = username
        self.password = password
    }
    
    func startPasswordAuthentication() -> AWSCognitoIdentityPasswordAuthentication {
        return PasswordAuthHandler(username:username, password:password)
    }
}

final class PasswordAuthHandler: NSObject, AWSCognitoIdentityPasswordAuthentication, Sendable {
    
    let username : String?
    let password : String?
    
    init(username: String? = nil, password: String? = nil) {
        self.username = username
        self.password = password
    }
    
    func getDetails(_ authenticationInput: AWSCognitoIdentityPasswordAuthenticationInput,
                    passwordAuthenticationCompletionSource: AWSTaskCompletionSource<AWSCognitoIdentityPasswordAuthenticationDetails>) {
        
        guard let name = username else {
            AuthLogger.log("Username is nil", level: .error)
            return
        }
        
        guard let pass = password else {
            AuthLogger.log("Password is nil", level: .error)
            return
        }
        
        let authDetails = AWSCognitoIdentityPasswordAuthenticationDetails(username: name, password: pass)
        passwordAuthenticationCompletionSource.set(result: authDetails)
    }
    
    func didCompleteStepWithError(_ error: Error?) {
        if let error = error {
            AuthLogger.log("Authentication failed: \(error.localizedDescription)", level: .error)
        } else {
            AuthLogger.log("Authentication success")
        }
    }
}

final public class Auth: ObservableObject, @unchecked Sendable {

    private let lock = NSLock()
    var authCoordinator: AuthCoordinator?
    private var sessionStore: CognitoSessionStore?
    
    public init(region: AWSRegionType = .USEast1, poolClientId: String, poolId: String) {
        let serviceConfiguration = AWSServiceConfiguration(
            region: region,
            credentialsProvider: nil
        )

        let userPoolConfiguration = AWSCognitoIdentityUserPoolConfiguration(
            clientId: poolClientId, clientSecret: nil,
            poolId: poolId
        )

        AWSCognitoIdentityUserPool.register(
            with: serviceConfiguration,
            userPoolConfiguration: userPoolConfiguration,
            forKey: "UserPool"
        )
    }
    
    private func getCognitoUser(username: String) -> AWSCognitoIdentityUser? {
        guard let user = AWSCognitoIdentityUserPool(forKey: "UserPool")?.getUser(username) else {
            AuthLogger.log("No user found.", level: .error)
            return nil
        }
        return user
    }
    
    public func isUserSignedIn() async -> Bool {
        guard let user = currentUser() else { return false }

        return await withCheckedContinuation { continuation in
            user.getSession().continueWith { task in
                if let session = task.result,
                   let accessToken = session.accessToken?.tokenString,
                   !accessToken.isEmpty,
                   session.expirationTime?.compare(Date()) == .orderedDescending {
                    continuation.resume(returning: true)
                } else {
                    continuation.resume(returning: false)
                }
                return nil
            }
        }
    }
    
    private func cognitoUser(username: String) -> AWSCognitoIdentityUser? {
        AWSCognitoIdentityUserPool(forKey: "UserPool")?.getUser(username)
    }
    private func currentUser() -> AWSCognitoIdentityUser? {
        AWSCognitoIdentityUserPool(forKey: "UserPool")?.currentUser()
    }
    
    public var cognitoUserId: String? {
        guard let user = currentUser() else {
            return nil
        }
        return user.getSession().result?.idToken?.tokenClaims["sub"] as? String
    }
    
    public var username: String? {
        guard let user = currentUser() else {
            return nil
        }
        return user.username
    }
    
    @discardableResult
    public func refreshSessionIfNeeded() async throws -> Bool {
        guard let user = currentUser() else {
            return false
        }
        
        return try await withCheckedThrowingContinuation { continuation in
            user.getSession().continueWith { task in
                if let error = task.error {
                    AuthLogger.log("Error calling API: \(error.localizedDescription)", level: .error)
                    continuation.resume(returning: false)
                } else if let session = task.result, let _ = session.refreshToken?.tokenString {
                    user.getSession().continueWith { refreshTask in
                        if let refreshError = refreshTask.error {
                            AuthLogger.log("Failed to refresh session: \(refreshError.localizedDescription)", level: .error)
                            continuation.resume(returning: false)
                        } else {
                            AuthLogger.log("Session refreshed successfully")
                            continuation.resume(returning: true)
                        }
                        return nil
                    }
                } else {
                    AuthLogger.log("No refresh token available", level: .error)
                    continuation.resume(returning: false)
                }
                return nil
            }
        }
    }
    
    public func tokens() async throws -> (id: String, access: String) {
        guard let store = sessionStore else { throw AuthError.noTokens }
        return try await store.tokens()
    }
    
    public func hasValidatedEmail(username: String) async throws -> Bool {
        guard let user = getCognitoUser(username: username) else {
            throw NSError(domain: "AuthError", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "User not found in user pool"])
        }
        
        return try await withCheckedThrowingContinuation { continuation in
            user.getDetails().continueWith { task in
                if let error = task.error {
                    continuation.resume(throwing: error)
                } else if let result = task.result {
                    if let isEmailVerified = result.userAttributes?.first(where: { $0.name == "email_verified" })?.value, isEmailVerified == "true" {
                        continuation.resume(returning: true)
                    } else {
                        continuation.resume(returning: false)
                    }
                } else {
                    continuation.resume(returning: false)
                }
            }
        }
    }
    
    public func hasValidatedEmail(username: String, completion: @escaping (Bool, Error?) -> Void) {
        guard let user = getCognitoUser(username: username) else {
            completion(false, nil)
            return
        }
        
        user.getDetails().continueWith { task in
            if let error = task.error {
                completion(false, error)
            } else if let result = task.result {
                if let isEmailVerified = result.userAttributes?.first(where: { $0.name == "email_verified" })?.value, isEmailVerified == "true" {
                    completion(true, nil)
                } else {
                    completion(false, nil)
                }
            }
            return nil
        }
    }
    
    public func refreshSessionIfNeeded(completion: @escaping (Bool) -> Void) {
        guard let user = currentUser() else {
            completion(false)
            return
        }
        
        user.getSession().continueWith { task in
            if let error = task.error {
                AuthLogger.log("Error getting session: \(error.localizedDescription)", level: .error)
                completion(false)
            } else if let session = task.result, let _ = session.refreshToken?.tokenString {
                user.getSession().continueWith { refreshTask in
                    if let refreshError = refreshTask.error {
                        AuthLogger.log("Failed to refresh session: \(refreshError.localizedDescription)", level: .error)
                        completion(false)
                    } else {
                        AuthLogger.log("Session refreshed successfully")
                        completion(true)
                    }
                    return nil
                }
            } else {
                AuthLogger.log("No refresh token available", level: .error)
                completion(false)
            }
            return nil
        }
    }
    
    public func validateUser(username: String, confirmationCode: String, completion: @escaping (Bool) -> Void) {
        guard let userPool = AWSCognitoIdentityUserPool(forKey: "UserPool")?.getUser(username) else {
            AuthLogger.log("No user available", level: .error)
            completion(false)
            return
        }
        
        userPool.confirmSignUp(confirmationCode, forceAliasCreation: true).continueWith { task in
            if let error = task.error {
                AuthLogger.log("Failed to validate user: \(error.localizedDescription)", level: .error)
                completion(false)
            } else {
                completion(true)
            }
            return nil
        }
    }
    
    public func validateUser(username: String, confirmationCode: String) async throws -> Bool {
        guard let userPool = AWSCognitoIdentityUserPool(forKey: "UserPool")?.getUser(username) else {
            AuthLogger.log("No user available", level: .error)
            return false
        }
        
        return try await withCheckedThrowingContinuation { continuation in
            userPool.confirmSignUp(confirmationCode, forceAliasCreation: true).continueWith { task in
                if let error = task.error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: true)
                }
            }
        }
    }
    
    public func signUp(username: String, email: String, password: String) async throws {
        
        let (userPool, attributes) = getUserPoolAndAttributes(email: email)
        guard let userPool = userPool, let attributes = attributes else { return }
        
        return try await withCheckedThrowingContinuation { continuation in
            userPool.signUp(username, password: password, userAttributes: attributes, validationData: nil).continueWith { task in
                if let error = task.error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }
    
    public func signUp(username: String, email: String, password: String, completion: @escaping (Bool) -> Void) {
        
        let (userPool, attributes) = getUserPoolAndAttributes(email: email)
        guard let userPool = userPool, let attributes = attributes else { return }
        
        userPool.signUp(username, password: password, userAttributes: attributes, validationData: nil).continueWith { task in
            if let error = task.error {
                AuthLogger.log("Sign up error: \(error.localizedDescription)", level: .error)
                completion(false)
            } else {
                self.setAuthCoordinator(username: username, password: password)
                AuthLogger.log("Sign up successful")
                completion(true)
            }
            return nil
        }
    }
    
    public func setAuthCoordinator(username:String, password:String) {
        lock.lock()
        defer { lock.unlock() }
        let userPool = AWSCognitoIdentityUserPool(forKey: "UserPool")
        let coordinator = AuthCoordinator(username: username, password: password)
        userPool?.delegate = coordinator
        self.authCoordinator = coordinator
    }
    
    @discardableResult
    public func signIn(username: String, password: String) async throws -> Bool {
        guard let user = cognitoUser(username: username) else { return false }
        setAuthCoordinator(username: username, password: password)

        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            user.getSession(username, password: password, validationData: nil)
                .continueWith { task in
                    if let error = task.error { cont.resume(throwing: error) }
                    else { cont.resume(returning: ()) }
                    return nil
                }
        }

        let store = CognitoSessionStore(user: user)
        self.sessionStore = store

        try await store.signIn(username: username, password: password)

        AuthLogger.log("User logged in successfully.")
        return true
    }

    @discardableResult
    public func signOut() -> Bool {
        guard let user = currentUser() else {
            return false
        }

        user.signOut()

        self.sessionStore = nil
        self.authCoordinator = nil

        AWSCognitoIdentityUserPool(forKey: "UserPool")?.clearLastKnownUser()

        AuthLogger.log("User signed out and local state cleared.")
        return true
    }
    
    public func isUserConfirmed(username: String, completion: @escaping (Bool, Error?) -> Void) {
        guard let user = getCognitoUser(username: username) else {
            completion(false, nil)
            return
        }
        
        user.getDetails().continueWith { task in
            if let error = task.error {
                AuthLogger.log("User details error: \(error.localizedDescription)", level: .error)
                completion(false, error)
            } else if let result = task.result {
                if let isEmailVerified = result.userAttributes?.first(where: { $0.name == "email_verified" })?.value, isEmailVerified == "true" {
                    completion(true, nil)
                } else {
                    completion(false, nil)
                }
            }
            return nil
        }
    }
    
    public func confirmSignUp(username: String, confirmationCode: String) async throws -> Bool {
        guard let user = getCognitoUser(username: username) else {
            return false
        }
        
        return try await withCheckedThrowingContinuation { continuation in
            user.confirmSignUp(confirmationCode, forceAliasCreation: true).continueWith { task in
                if let error = task.error {
                    AuthLogger.log("Error confirming sign-up: \(error.localizedDescription)", level: .error)
                    continuation.resume(returning: false)
                } else if task.result != nil {
                    AuthLogger.log("User confirmed successfully")
                    continuation.resume(returning: true)
                } else {
                    continuation.resume(returning: false)
                }
                return nil
            }
        }
    }
    
    public func confirmSignUp(username: String, confirmationCode: String, completion: @escaping (Bool) -> Void) {
        guard let user = getCognitoUser(username: username) else {
            completion(false)
            return
        }
        
        user.confirmSignUp(confirmationCode, forceAliasCreation: true).continueWith { task in
            if let error = task.error {
                AuthLogger.log("Error confirming sign-up: \(error.localizedDescription)", level: .error)
                completion(false)
            } else {
                AuthLogger.log("User confirmed successfully")
                completion(true)
            }
            return nil
        }
    }
}

extension Auth {
    public func forgotPassword(username: String, completion: @escaping (Bool, Error?) -> Void) {
        guard let user = getCognitoUser(username: username) else {
            completion(false, NSError(domain: "AuthError", code: 0, userInfo: [NSLocalizedDescriptionKey:"User not found"]))
            return
        }
        user.forgotPassword().continueWith { task in
            if let error = task.error {
                AuthLogger.log("Forgot password error: \(error.localizedDescription)", level: .error)
                completion(false, error)
            } else {
                completion(true, nil)
            }
            return nil
        }
    }

    public func confirmForgotPassword(username: String, newPassword: String, confirmationCode: String, completion: @escaping (Bool, Error?) -> Void) {
        guard let user = getCognitoUser(username: username) else {
            completion(false, NSError(domain: "AuthError", code: 0, userInfo: [NSLocalizedDescriptionKey:"User not found"]))
            return
        }
        user.confirmForgotPassword(confirmationCode, password: newPassword).continueWith { task in
            if let error = task.error {
                AuthLogger.log("Confirm forgot password error: \(error.localizedDescription)", level: .error)
                completion(false, error)
            } else {
                completion(true, nil)
            }
            return nil
        }
    }

    public func forgotPassword(username: String) async throws {
        guard let user = getCognitoUser(username: username) else {
            throw NSError(domain: "AuthError", code: 0, userInfo: [NSLocalizedDescriptionKey:"User not found"])
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            user.forgotPassword().continueWith { task in
                if let error = task.error {
                    AuthLogger.log("Forgot password error: \(error.localizedDescription)", level: .error)
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
                return nil
            }
        }
    }

    public func confirmForgotPassword(username: String, newPassword: String, confirmationCode: String) async throws {
        guard let user = getCognitoUser(username: username) else {
            throw NSError(domain: "AuthError", code: 0, userInfo: [NSLocalizedDescriptionKey:"User not found"])
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            user.confirmForgotPassword(confirmationCode, password: newPassword).continueWith { task in
                if let error = task.error {
                    AuthLogger.log("Confirm forgot password error: \(error.localizedDescription)", level: .error)
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
                return nil
            }
        }
    }
}

extension Auth {

    private func getUserPoolAndAttributes(email: String) -> (AWSCognitoIdentityUserPool?, [AWSCognitoIdentityUserAttributeType]?) {
        guard let userPool = AWSCognitoIdentityUserPool(forKey: "UserPool") else {
            AuthLogger.log("No user pool found.", level: .error)
            return (nil, nil)
        }
        
        let attributes = [AWSCognitoIdentityUserAttributeType(name: "email", value: email)]
        return (userPool, attributes)
    }
}
