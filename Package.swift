// swift-tools-version:6.1

import PackageDescription

let package = Package(
    name: "CognitoAuthKitiOS",
    platforms: [
        .iOS(.v15)
    ],
    products: [
        .library(
            name: "CognitoAuthKit",
            targets: ["CognitoAuthKitiOS"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/aws-amplify/aws-sdk-ios-spm", from: "2.40.0"),
        .package(url: "https://github.com/Buza/BLog.git", from: "1.0.2"),
    ],
    targets: [
        .target(
            name: "CognitoAuthKitiOS",
            dependencies: [
                .product(name: "AWSCognitoIdentityProvider", package: "aws-sdk-ios-spm"),
                "BLog"
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
