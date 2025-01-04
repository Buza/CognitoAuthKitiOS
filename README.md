# SwiftCognitoAuth

SwiftCognitoAuth is a simple interface for managing user authentication using AWS Cognito.

## Features

- **Authentication Support**: Sign in, sign up, and manage user sessions.
- **Session Management**: Handle session refresh and validate email addresses.
- **Custom Logging**: Leverage `BLog` for structured logging across the authentication flow.

## Installation

Add `SwiftCognitoAuth` to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/Buza/SwiftCognitoAuth.git", from: "1.0.0")
]
```

## Usage

### Setup

Initialize `Auth` with your AWS Cognito pool information:

```swift
let auth = Auth(region: .USEast1)
```

### Sign In

```swift
auth.signIn(username: "user@example.com", password: "password123") { success in
    if success {
        print("Sign-in successful")
    } else {
        print("Sign-in failed")
    }
}
```

### Sign Up

```swift
auth.signUp(username: "newuser", email: "newuser@example.com", password: "password123") { success in
    if success {
        print("Sign-up successful")
    } else {
        print("Sign-up failed")
    }
}
```

### Session Refresh

```swift
Task {
    do {
        let refreshed = try await auth.refreshSessionIfNeeded()
        print("Session refreshed: \(refreshed)")
    } catch {
        print("Failed to refresh session: \(error.localizedDescription)")
    }
}
```

### Logging

Use the `AuthLogger` to log messages during the authentication flow:

```swift
AuthLogger.log("Custom log message", level: .info)
```

## License

SwiftCognitoAuth is available under the MIT license.

