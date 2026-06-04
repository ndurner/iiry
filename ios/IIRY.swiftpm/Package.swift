// swift-tools-version: 5.9

import PackageDescription
#if canImport(AppleProductTypes)
import AppleProductTypes
#endif

#if canImport(AppleProductTypes)
let package = Package(
    name: "IIRY",
    platforms: [
        .iOS("17.0")
    ],
    products: [
        .iOSApplication(
            name: "IIRY",
            targets: ["AppModule"],
            bundleIdentifier: "de.ndurner.iiry",
            teamIdentifier: "FSYXWNUDDW",
            displayVersion: "1.0",
            bundleVersion: "1",
            appIcon: .placeholder(icon: .object),
            accentColor: .presetColor(.teal),
            supportedDeviceFamilies: [
                .phone,
                .pad
            ],
            supportedInterfaceOrientations: [
                .portrait,
                .landscapeLeft,
                .landscapeRight,
                .portraitUpsideDown(.when(deviceFamilies: [.pad]))
            ],
            additionalInfoPlistContentFilePath: "AdditionalInfo.plist"
        )
    ],
    targets: [
        .target(
            name: "IIRYCore",
            path: "Sources/IIRYCore"
        ),
        .executableTarget(
            name: "AppModule",
            dependencies: ["IIRYCore"],
            path: "Sources/AppModule"
        )
    ]
)
#else
let package = Package(
    name: "IIRY",
    platforms: [
        .macOS(.v14),
        .iOS(.v17)
    ],
    products: [
        .library(name: "IIRYCore", targets: ["IIRYCore"])
    ],
    targets: [
        .target(
            name: "IIRYCore",
            path: "Sources/IIRYCore"
        )
    ]
)
#endif
