//
//  JWTParser.swift
//  CognitoAuthKit
//
//  Created by Kyle Buza on 1/24/25.
//

import Foundation

struct JWTParser {

    enum JWTError: Error, LocalizedError {
        case invalidToken
        case invalidBase64
        case invalidJSON
        case missingClaim(String)

        var errorDescription: String? {
            switch self {
            case .invalidToken:
                return "Invalid JWT token format"
            case .invalidBase64:
                return "Invalid Base64 encoding in JWT"
            case .invalidJSON:
                return "Invalid JSON in JWT payload"
            case .missingClaim(let claim):
                return "Missing required claim: \(claim)"
            }
        }
    }

    static func extractClaim(from jwt: String, claim: String) throws -> String {
        let parts = jwt.components(separatedBy: ".")
        guard parts.count == 3 else {
            throw JWTError.invalidToken
        }

        let payload = parts[1]
        guard let payloadData = base64UrlDecode(payload) else {
            throw JWTError.invalidBase64
        }

        guard let json = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            throw JWTError.invalidJSON
        }

        guard let claimValue = json[claim] as? String else {
            throw JWTError.missingClaim(claim)
        }

        return claimValue
    }

    static func extractUsername(from idToken: String) throws -> String {
        return try extractClaim(from: idToken, claim: "cognito:username")
    }

    static func extractSubject(from idToken: String) throws -> String {
        return try extractClaim(from: idToken, claim: "sub")
    }

    private static func base64UrlDecode(_ value: String) -> Data? {
        var base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        let remainder = base64.count % 4
        if remainder > 0 {
            base64 = base64.padding(toLength: base64.count + 4 - remainder,
                                   withPad: "=",
                                   startingAt: 0)
        }

        return Data(base64Encoded: base64)
    }
}