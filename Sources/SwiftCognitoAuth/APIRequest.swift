//
//  APIRequest.swift
//  SwiftCognitoAuth
//
//  Created by Kyle Buza on 1/24/25.
//

import Foundation

public enum HTTPMethod: String, Sendable {
    case GET, POST, PUT, DELETE
}

public enum APIEnvironment: String {
    case dev = "dev"
    case prod = "prod"
}

public protocol APIPathProtocol: RawRepresentable where RawValue == String {}

public struct APIRequest: Sendable {
    public let baseURL: URL
    public let path: String
    public let method: HTTPMethod
    public let body: Data?
    public let headers: [String: String]
    public let queryItems: [URLQueryItem]?
    private let auth: Auth

    public init(
        baseURL: URL,
        path: String,
        method: HTTPMethod,
        body: Data? = nil,
        auth: Auth,
        additionalHeaders: [String: String] = [:],
        queryItems: [URLQueryItem]? = nil
    ) {
        self.baseURL = baseURL
        self.path = path
        self.method = method
        self.body = body
        self.auth = auth
        self.headers = additionalHeaders
        self.queryItems = queryItems
    }

    private func buildURL() -> URL? {
        var components = URLComponents(url: baseURL.appendingPathComponent(path), resolvingAgainstBaseURL: false)
        components?.queryItems = queryItems
        return components?.url
    }

    public func execute() async throws -> Data {
        guard let url = buildURL() else {
            APIRequestLogger.log("Failed to build URL for request.", level: .error)
            throw URLError(.badURL)
        }

        var request = URLRequest(url: url)
        request.httpMethod = method.rawValue

        headers.forEach { key, value in
            request.setValue(value, forHTTPHeaderField: key)
        }

        do {
            let (idToken, _) = try await auth.tokens()
            APIRequestLogger.log("Authorization token: Bearer \(idToken)")
            request.setValue("Bearer \(idToken)", forHTTPHeaderField: "Authorization")
        } catch {
            APIRequestLogger.log("Authorization token is missing: \(error.localizedDescription)", level: .error)
        }

        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = body

        APIRequestLogger.log("Executing \(method.rawValue) request to \(url.absoluteString)")
        if let headers = request.allHTTPHeaderFields {
            APIRequestLogger.log("Request headers: \(headers)")
        }
        if let body = body, let bodyString = String(data: body, encoding: .utf8) {
            APIRequestLogger.log("Request body: \(bodyString)")
        }

        do {
            let (data, response) = try await URLSession.shared.data(for: request)

            if let httpResponse = response as? HTTPURLResponse {
                APIRequestLogger.log("Response status code: \(httpResponse.statusCode)")
            }
            if let responseString = String(data: data, encoding: .utf8) {
                APIRequestLogger.log("Response body: \(responseString)")
            }

            guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
                APIRequestLogger.log("Request failed with a non-2xx status code.", level: .error)
                throw URLError(.badServerResponse)
            }

            return data
        } catch {
            APIRequestLogger.log("Request failed with error: \(error.localizedDescription)", level: .error)
            throw error
        }
    }
}
