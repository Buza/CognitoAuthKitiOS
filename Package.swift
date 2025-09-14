// swift-tools-version:6.1

import PackageDescription

let package = Package(
    name: "CognitoAuthKitiOS",
    platforms: [
        .iOS(.v14),
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "CognitoAuthKit",
            targets: ["CognitoAuthKitiOS"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/aws-amplify/aws-sdk-ios-spm", from: "2.40.0"),
        .package(url: "https://github.com/Buza/BLog.git", branch: "main"),
        .package(url: "git@github.com:Buza/AuthAPICore.git", branch: "main"),
    ],
    targets: [
        .target(
            name: "CognitoAuthKitiOS",
            dependencies: [
                .product(name: "AWSCognitoIdentityProvider", package: "aws-sdk-ios-spm"),
                "BLog",
                .product(name: "AuthAPICore", package: "AuthAPICore")
            ],
            path: "Sources/CognitoAuthKit"
        ),
        .testTarget(
            name: "CognitoAuthKitiOSTests",
            dependencies: ["CognitoAuthKitiOS"],
            path: "Tests/CognitoAuthKitTests"
        ),
    ]
)
