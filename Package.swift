// swift-tools-version: 6.0

import PackageDescription

import PackageDescription

let package = Package(
    name: "SwiftCognitoAuth",
    platforms: [
        .iOS(.v15), .macOS(.v12) // Ensure macOS version aligns with your target
    ],
    products: [
        .library(
            name: "SwiftCognitoAuth",
            targets: ["SwiftCognitoAuth"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/aws-amplify/aws-sdk-ios-spm", from: "2.37.0"),
        .package(url: "https://github.com/Buza/BLog.git", from: "1.0.1"),
    ],
    targets: [
        .target(
            name: "SwiftCognitoAuth",
            dependencies: [
                .product(name: "AWSCognitoIdentityProvider", package: "aws-sdk-ios-spm"),
                "BLog"
            ]
        ),
        .testTarget(
            name: "SwiftCognitoAuthTests",
            dependencies: ["SwiftCognitoAuth"]
        ),
    ]
)
