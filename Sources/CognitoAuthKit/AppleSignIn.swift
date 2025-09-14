//
//  AppleSignIn.swift
//  CognitoAuthKit
//
//  Kyle Buza (2025).
//

import Foundation
import BLog
import AuthenticationServices

public enum AppleSignInError: Error, LocalizedError {
    case invalidIdentityToken
    case notConfigured
    case missingRequiredParameter(String)
    case userPoolError(Error)
    case userCancelled

    public var errorDescription: String? {
        switch self {
        case .invalidIdentityToken:
            return "Invalid or missing identity token from Apple"
        case .notConfigured:
            return "Apple Sign In not configured"
        case .missingRequiredParameter(let param):
            return "Missing required parameter: \(param)"
        case .userPoolError(let error):
            return "User pool error: \(error.localizedDescription)"
        case .userCancelled:
            return "User cancelled Apple Sign In"
        }
    }
}

struct AppleSignInLogger {
    static let shared = BLog(subsystem: "com.buzamoto.cognitoauthios",
                             category: "AppleSignIn",
                             prefix: "<AppleSignIn>")
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

public struct AppleSignInResult: Sendable {
    public let userSub: String
    public let identityToken: String
    public let authorizationCode: String
}

@available(iOS 13.0, *)
public class AppleSignInManager: NSObject {
    private var presentationAnchor: ASPresentationAnchor?
    private var signInContinuation: CheckedContinuation<AppleSignInResult, Error>?

    public override init() {
        super.init()
    }

    @MainActor
    public func signInWithApple(presentationAnchor: ASPresentationAnchor) async throws -> AppleSignInResult {
        self.presentationAnchor = presentationAnchor

        return try await withCheckedThrowingContinuation { continuation in
            self.signInContinuation = continuation

            let provider = ASAuthorizationAppleIDProvider()
            let request = provider.createRequest()
            request.requestedScopes = [.fullName, .email]

            let authController = ASAuthorizationController(authorizationRequests: [request])
            authController.delegate = self
            authController.presentationContextProvider = self
            authController.performRequests()

            AppleSignInLogger.log("Started native Apple Sign In flow")
        }
    }

    private func handleAppleCredential(_ credential: ASAuthorizationAppleIDCredential) throws -> AppleSignInResult {
        guard let identityToken = credential.identityToken,
              let identityTokenString = String(data: identityToken, encoding: .utf8) else {
            throw AppleSignInError.invalidIdentityToken
        }

        guard let authorizationCode = credential.authorizationCode,
              let authorizationCodeString = String(data: authorizationCode, encoding: .utf8) else {
            throw AppleSignInError.missingRequiredParameter("authorizationCode")
        }

        AppleSignInLogger.log("Received Apple credentials with user: \(credential.user)")

        let result = AppleSignInResult(
            userSub: credential.user,
            identityToken: identityTokenString,
            authorizationCode: authorizationCodeString
        )

        return result
    }
}

@available(iOS 13.0, *)
extension AppleSignInManager: ASAuthorizationControllerDelegate {
    public func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        guard let appleIDCredential = authorization.credential as? ASAuthorizationAppleIDCredential else {
            signInContinuation?.resume(throwing: AppleSignInError.invalidIdentityToken)
            signInContinuation = nil
            return
        }

        do {
            let result = try handleAppleCredential(appleIDCredential)
            signInContinuation?.resume(returning: result)
        } catch {
            signInContinuation?.resume(throwing: error)
        }
        signInContinuation = nil
    }

    public func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithError error: Error
    ) {
        AppleSignInLogger.log("Apple Sign In failed: \(error.localizedDescription)", level: .error)

        if (error as NSError).code == ASAuthorizationError.canceled.rawValue {
            signInContinuation?.resume(throwing: AppleSignInError.userCancelled)
        } else {
            signInContinuation?.resume(throwing: error)
        }
        signInContinuation = nil
    }
}

@available(iOS 13.0, *)
extension AppleSignInManager: ASAuthorizationControllerPresentationContextProviding {
    public func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        return presentationAnchor ?? ASPresentationAnchor()
    }
}