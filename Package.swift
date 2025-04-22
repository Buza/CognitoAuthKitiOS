// swift-tools-version:5.7

import PackageDescription

let package = Package(
    name: "CognitoAuthKit-iOS",
    platforms: [
        .iOS(.v15),
        .macOS(.v12)
    ],
    products: [
        .library(
            name: "CognitoAuthKit",
            targets: ["CognitoAuthKit"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/aws-amplify/aws-sdk-ios-spm", from: "2.37.0"),
        .package(url: "https://github.com/Buza/BLog.git", from: "1.0.1"),
    ],
    targets: [
        .target(
            name: "CognitoAuthKit",
            dependencies: [
                .product(name: "AWSCognitoIdentityProvider", package: "aws-sdk-ios-spm"),
                "BLog"
            ]
        ),
        .testTarget(
            name: "CognitoAuthKitTests",
            dependencies: ["CognitoAuthKit"]
        ),
    ]
)
