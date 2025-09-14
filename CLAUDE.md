# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

### Building the package
```bash
swift build
```

### Running tests
```bash
swift test
```

### Running a specific test
```bash
swift test --filter TestName
```

### Clean build
```bash
swift package clean
```

### Update dependencies
```bash
swift package update
```

### Generate Xcode project (if needed)
```bash
swift package generate-xcodeproj
```

## Architecture Overview

This is a Swift Package providing AWS Cognito authentication for iOS applications with the following key components:

### Core Components

1. **Auth.swift** (`Sources/CognitoAuthKit/Auth.swift`)
   - Main authentication class that manages user sign-in, sign-up, session management, and password operations
   - Uses AWS Cognito Identity Provider SDK for authentication
   - Provides both async/await and completion handler APIs
   - Manages authentication coordinators and session storage

2. **SessionStore.swift** (`Sources/CognitoAuthKit/SessionStore.swift`)
   - Actor-based session management for thread-safe token handling
   - Manages AWS Cognito user sessions with automatic refresh logic
   - Provides ID and access token retrieval

3. **APIRequest.swift** (`Sources/CognitoAuthKit/APIRequest.swift`)
   - HTTP client for authenticated API requests
   - Integrates with Cognito token provider for authorization headers
   - Implements the `APIExecutor` protocol from AuthAPICore dependency
   - Includes request/response logging with auth header redaction

### Key Dependencies

- **AWS Cognito Identity Provider**: Core AWS SDK for Cognito authentication
- **BLog**: Custom logging framework for structured logging
- **AuthAPICore**: Provides API execution protocols and error definitions

### Authentication Flow

1. User pool initialization with region, client ID, and pool ID
2. Sign-up with username, email, and password
3. Email verification via confirmation code
4. Sign-in with credentials
5. Session management with automatic token refresh
6. Password reset flow support

### Testing Configuration

Tests require Cognito pool configuration. Update `CognitoTestConfigDefault` in `Tests/CognitoAuthKitTests/CognitoAuthKitTests.swift` with valid AWS Cognito pool credentials before running tests.

## Important Notes

- This package targets iOS 14.0+
- Uses Swift 6.1 tools version
- All authentication operations log through BLog with the subsystem "com.buzamoto.cognitoauthios"
- Session tokens are automatically refreshed when needed
- The package exports as `CognitoAuthKit` library