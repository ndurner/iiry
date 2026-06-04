// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "IIRY",
    platforms: [
        .macOS(.v15)
    ],
    products: [
        .library(name: "IIRYCore", targets: ["IIRYCore"]),
        .executable(name: "iiry", targets: ["IIRYCLI"])
    ],
    targets: [
        .target(
            name: "IIRYCore",
            path: "ios/IIRY.swiftpm/Sources/IIRYCore"
        ),
        .executableTarget(
            name: "IIRYCLI",
            dependencies: ["IIRYCore"],
            path: "cli/Sources/IIRYCLI"
        ),
        .testTarget(
            name: "IIRYCoreTests",
            dependencies: ["IIRYCore"],
            path: "Tests/IIRYCoreTests"
        )
    ]
)
