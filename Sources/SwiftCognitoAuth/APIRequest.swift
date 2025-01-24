//
//  APIRequest.swift
//  SwiftCognitoAuth
//
//  Created by Kyle Buza on 1/24/25.
//

import Foundation

public enum HTTPMethod: String {
    case GET, POST, PUT, DELETE
}

public enum APIEnvironment: String {
    case dev = "dev"
    case prod = "prod"
}

public protocol APIPathProtocol: RawRepresentable where RawValue == String {}

public struct APIRequest {
    public let baseURL: URL
    public let path: String
    public let method: HTTPMethod
    public let body: Data?
    public let headers: [String: String]
    private let auth: Auth

    public init(
        baseURL: URL,
        path: String,
        method: HTTPMethod,
        body: Data? = nil,
        auth: Auth,
        additionalHeaders: [String: String] = [:]
    ) {
        self.baseURL = baseURL
        self.path = path
        self.method = method
        self.body = body
        self.auth = auth
        self.headers = additionalHeaders
    }

    private func buildURL() -> URL? {
        return baseURL.appendingPathComponent(path)
    }

    public func execute() async throws -> Data {
        guard let url = buildURL() else {
            throw URLError(.badURL)
        }

        var request = URLRequest(url: url)
        request.httpMethod = method.rawValue
        headers.forEach { key, value in
            request.setValue(value, forHTTPHeaderField: key)
        }

        if let token = auth.idToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = body

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
            throw URLError(.badServerResponse)
        }

        return data
    }
}
