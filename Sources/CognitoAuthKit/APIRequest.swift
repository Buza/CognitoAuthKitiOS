//
//  APIRequest.swift
//  CognitoAuthKit
//
//  Created by Kyle Buza on 1/24/25.
//

import Foundation
import BLog
import AuthAPICore

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
    public let tokenProvider: CognitoIdTokenProvider
    public let additionalHeaders: [String: String]
    
    public init(
        baseURL: URL,
        tokenProvider: CognitoIdTokenProvider,
        additionalHeaders: [String: String] = [:]
    ) {
        self.baseURL = baseURL
        self.tokenProvider = tokenProvider
        self.additionalHeaders = additionalHeaders
    }
    
    private func buildURL(path: String, queryItems: [URLQueryItem]?) -> URL? {
        var components = URLComponents(url: baseURL.appendingPathComponent(path), resolvingAgainstBaseURL: false)
        components?.queryItems = queryItems
        return components?.url
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
                APIRequestLogger.log("Request body: \(bodyString)")
            }
        }
        
        do {
            let idToken = try await tokenProvider.getIdToken()
            request.setValue("Bearer \(idToken)", forHTTPHeaderField: "Authorization")
            APIRequestLogger.log("Authorization token: Bearer \(idToken)")
        } catch {
            APIRequestLogger.log("Authorization token is missing: \(error.localizedDescription)", level: .error)
            throw APIError.authenticationFailed(error)
        }
        
        APIRequestLogger.log("Executing \(payload.method.rawValue) request to \(url.absoluteString)")
        if let headers = request.allHTTPHeaderFields {
            APIRequestLogger.log("Request headers: \(headers)")
        }
        
        let (data, response) = try await URLSession.shared.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            APIRequestLogger.log("Invalid response received.", level: .error)
            throw APIError.networkError(URLError(.badServerResponse))
        }
        
        APIRequestLogger.log("Response status code: \(httpResponse.statusCode)")
        if let responseString = String(data: data, encoding: .utf8) {
            APIRequestLogger.log("Response body: \(responseString)")
        }
        
        guard (200...299).contains(httpResponse.statusCode) else {
            let message = String(data: data, encoding: .utf8) ?? "No additional details"
            APIRequestLogger.log("Request failed with status code: \(httpResponse.statusCode), message: \(message)", level: .error)
            throw APIError.httpError(statusCode: httpResponse.statusCode, message: message)
        }
        
        return data
    }
}
