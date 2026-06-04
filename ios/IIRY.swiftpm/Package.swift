// swift-tools-version: 5.9

import PackageDescription
import AppleProductTypes

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
