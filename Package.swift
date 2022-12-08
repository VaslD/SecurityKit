// swift-tools-version: 5.7

import PackageDescription

let package = Package(
    name: "SecurityKit",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
    ],
    products: [
        .library(name: "SecurityKit", targets: ["SecurityKit"]),
    ],
    dependencies: [
    ],
    targets: [
        .target(name: "SecurityKit"),
        .testTarget(name: "SecurityKitTests", dependencies: ["SecurityKit"]),
    ]
)
