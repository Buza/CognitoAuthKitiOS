//
//  APIRequest.swift
//  CognitoAuthKit
//
//  Created by Kyle Buza on 1/24/25.
//

import Foundation
import BLog
import AuthAPICore

public enum APIRequestEnvironment : String, Sendable  {
    case production
    case staging
    case development
}

struct APIRequestLogger {
    static let shared = BLog(subsystem: "com.buzamoto.cognitoauth",
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

public struct APIRequest: Sendable, APIExecutor {
    public let baseURL: URL
    public let tokenProvider: CognitoIdTokenProvider?
    public let additionalHeaders: [String: String]
    private let apiEnvironment : APIRequestEnvironment
    
    public init(
        baseURL: URL,
        tokenProvider: CognitoIdTokenProvider? = nil,
        additionalHeaders: [String: String] = [:],
        apiRequestEnvironment: APIRequestEnvironment = .production
    ) {
        self.baseURL = baseURL
        self.tokenProvider = tokenProvider
        self.additionalHeaders = additionalHeaders
        self.apiEnvironment = apiRequestEnvironment
    }
    
    private func buildURL(path: String, queryItems: [URLQueryItem]?) -> URL? {
        var components = URLComponents(url: baseURL.appendingPathComponent(path), resolvingAgainstBaseURL: false)
        components?.queryItems = queryItems
        return components?.url
    }

    private func redactSensitiveFields(in jsonString: String) -> String {
        guard let jsonData = jsonString.data(using: .utf8),
              let jsonObject = try? JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any] else {
            return jsonString
        }

        var mutableJsonObject = jsonObject

        if mutableJsonObject["receipt_data"] != nil {
            mutableJsonObject["receipt_data"] = "<REDACTED>"
        }

        guard let redactedData = try? JSONSerialization.data(withJSONObject: mutableJsonObject, options: []),
              let redactedString = String(data: redactedData, encoding: .utf8) else {
            return jsonString
        }

        return redactedString
    }
    
    public func execute(request payload: APIRequestPayload) async throws -> Data {
        guard let url = buildURL(path: payload.path, queryItems: payload.queryItems) else {
            APIRequestLogger.log("Failed to build URL for request.", level: .error)
            throw APIError.invalidURL
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = payload.method.rawValue
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        additionalHeaders.forEach { key, value in
            request.setValue(value, forHTTPHeaderField: key)
        }
        
        if let body = payload.body {
            request.httpBody = body
            if let bodyString = String(data: body, encoding: .utf8) {
                let redactedBodyString = redactSensitiveFields(in: bodyString)
                APIRequestLogger.log("[\(apiEnvironment.rawValue)] : [\(payload.path)] Request body: \(redactedBodyString)")
            }
        }

        if let tokenProvider = tokenProvider {
            do {
                let idToken = try await tokenProvider.getIdToken()
                request.setValue("Bearer \(idToken)", forHTTPHeaderField: "Authorization")
                APIRequestLogger.log("[\(apiEnvironment.rawValue)] : [\(payload.path)] Authorization token: <REDACTED>")
            } catch {
                APIRequestLogger.log("[\(apiEnvironment.rawValue)] : [\(payload.path)] Authorization token is missing: \(error.localizedDescription)", level: .error)
                throw APIError.authenticationFailed(error)
            }
        } else {
            APIRequestLogger.log("[\(apiEnvironment.rawValue)] : [\(payload.path)] No authorization token provided (unauthenticated request)")
        }

        APIRequestLogger.log("[\(apiEnvironment.rawValue)] : [\(payload.path)] Executing \(payload.method.rawValue) request to \(url.absoluteString)")
        if let headers = request.allHTTPHeaderFields {
            let redactedHeaders = Dictionary(uniqueKeysWithValues: headers.map { key, value in
                (key, key.lowercased() == "authorization" ? "<REDACTED>" : value)
            })
            APIRequestLogger.log("[\(apiEnvironment.rawValue)] : [\(payload.path)] Request headers: \(redactedHeaders)")
        }

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            APIRequestLogger.log("[\(apiEnvironment.rawValue)] : [\(payload.path)] Invalid response received.", level: .error)
            throw APIError.networkError(URLError(.badServerResponse))
        }
        
        APIRequestLogger.log("[\(apiEnvironment.rawValue)] : [\(payload.path)] Response status code: \(httpResponse.statusCode)")

        guard (200...299).contains(httpResponse.statusCode) else {
            let message = String(data: data, encoding: .utf8) ?? "No additional details"
            APIRequestLogger.log("[\(apiEnvironment.rawValue)] : [\(payload.path)] Request failed with status code: \(httpResponse.statusCode), message: \(message)", level: .error)
            throw APIError.httpError(statusCode: httpResponse.statusCode, message: message)
        }
        
        return data
    }
}
