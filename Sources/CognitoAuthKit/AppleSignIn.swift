//
//  AppleSignIn.swift
//  CognitoAuthKit
//
//  Kyle Buza (2025).
//

import Foundation
import BLog

public struct CognitoOAuthTokenResponse: Codable, Sendable {
    public let idToken: String
    public let accessToken: String
    public let refreshToken: String
    public let expiresIn: Int
    public let tokenType: String

    enum CodingKeys: String, CodingKey {
        case idToken = "id_token"
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case expiresIn = "expires_in"
        case tokenType = "token_type"
    }
}

public enum AppleSignInError: Error, LocalizedError {
    case invalidAuthorizationCode
    case invalidCognitoDomain
    case networkError(Error)
    case decodingError(Error)
    case httpError(statusCode: Int, message: String)

    public var errorDescription: String? {
        switch self {
        case .invalidAuthorizationCode:
            return "Invalid or missing authorization code from Apple"
        case .invalidCognitoDomain:
            return "Invalid Cognito domain configuration"
        case .networkError(let error):
            return "Network error: \(error.localizedDescription)"
        case .decodingError(let error):
            return "Failed to decode response: \(error.localizedDescription)"
        case .httpError(let statusCode, let message):
            return "HTTP error \(statusCode): \(message)"
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

public actor AppleSignInHandler {
    private let cognitoDomain: String
    private let clientId: String
    private let redirectUri: String

    public init(cognitoDomain: String, clientId: String, redirectUri: String = "https://bourbon-bro.com/auth/callback") {
        self.cognitoDomain = cognitoDomain
        self.clientId = clientId
        self.redirectUri = redirectUri
    }

    public func exchangeAuthorizationCode(_ authorizationCode: Data) async throws -> CognitoOAuthTokenResponse {
        guard let codeString = String(data: authorizationCode, encoding: .utf8) else {
            AppleSignInLogger.log("Failed to convert authorization code to string", level: .error)
            throw AppleSignInError.invalidAuthorizationCode
        }

        return try await exchangeAuthorizationCode(codeString)
    }

    public func exchangeAuthorizationCode(_ authorizationCode: String) async throws -> CognitoOAuthTokenResponse {
        let endpoint = "https://\(cognitoDomain)/oauth2/token"

        guard let url = URL(string: endpoint) else {
            AppleSignInLogger.log("Invalid URL: \(endpoint)", level: .error)
            throw AppleSignInError.invalidCognitoDomain
        }

        AppleSignInLogger.log("Exchanging Apple authorization code with Cognito at \(endpoint)")

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        let parameters = [
            "grant_type": "authorization_code",
            "client_id": clientId,
            "code": authorizationCode,
            "redirect_uri": redirectUri
        ]

        let bodyString = parameters
            .map { key, value in
                "\(key)=\(value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? value)"
            }
            .joined(separator: "&")

        request.httpBody = bodyString.data(using: .utf8)

        AppleSignInLogger.log("Request body (with code redacted): grant_type=authorization_code&client_id=\(clientId)&code=<REDACTED>&redirect_uri=\(redirectUri)")

        do {
            let (data, response) = try await URLSession.shared.data(for: request)

            guard let httpResponse = response as? HTTPURLResponse else {
                AppleSignInLogger.log("Invalid response type", level: .error)
                throw AppleSignInError.networkError(URLError(.badServerResponse))
            }

            AppleSignInLogger.log("Response status code: \(httpResponse.statusCode)")

            if httpResponse.statusCode == 200 {
                do {
                    let tokenResponse = try JSONDecoder().decode(CognitoOAuthTokenResponse.self, from: data)
                    AppleSignInLogger.log("Successfully exchanged authorization code for Cognito tokens")
                    return tokenResponse
                } catch {
                    AppleSignInLogger.log("Failed to decode token response: \(error)", level: .error)
                    if let responseString = String(data: data, encoding: .utf8) {
                        AppleSignInLogger.log("Raw response: \(responseString)", level: .debug)
                    }
                    throw AppleSignInError.decodingError(error)
                }
            } else {
                let message = String(data: data, encoding: .utf8) ?? "No error message"
                AppleSignInLogger.log("Token exchange failed with status \(httpResponse.statusCode): \(message)", level: .error)
                throw AppleSignInError.httpError(statusCode: httpResponse.statusCode, message: message)
            }
        } catch let error as AppleSignInError {
            throw error
        } catch {
            AppleSignInLogger.log("Network error during token exchange: \(error)", level: .error)
            throw AppleSignInError.networkError(error)
        }
    }
}