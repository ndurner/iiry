import Foundation
import IIRYCore

do {
    try IIRYCLI.run()
} catch {
    FileHandle.standardError.write(Data("error: \(error.localizedDescription)\n".utf8))
    Foundation.exit(2)
}

struct IIRYCLI {
    static func run() throws {
        var args = Array(CommandLine.arguments.dropFirst())
        guard let command = args.first else {
            printHelp()
            return
        }
        args.removeFirst()

        switch command {
        case "request-text":
            print(try IIRYRequestText.make())
        case "prepare":
            try commandPrepare(args)
        case "attach-vp":
            try commandAttachVP(args)
        case "verify":
            try commandVerify(args)
        case "extract-image":
            try commandExtractImage(args)
        case "c2pa-embed":
            try commandC2PAEmbed(args)
        case "-h", "--help", "help":
            printHelp()
        default:
            throw IIRYError.commandFailed("Unknown command: \(command)")
        }
    }

    static func commandPrepare(_ args: [String]) throws {
        guard let input = args.first else {
            throw IIRYError.commandFailed("prepare needs an input JPEG path")
        }
        let output = option("--out", in: args).map(URL.init(fileURLWithPath:))
        let imageURL = URL(fileURLWithPath: input)
        let imageData = try Data(contentsOf: imageURL)
        let prepared = try IIRYProofBuilder.prepare(imageData: imageData)
        let outURL = output ?? imageURL.deletingLastPathComponent().appendingPathComponent(prepared.carrier.suggestedFileName)
        try IIRYProofBuilder.carrierData(prepared.carrier).write(to: outURL)

        print("carrier: \(outURL.path)")
        print("nonce: \(prepared.nonce)")
        print("suggested_file_name: \(prepared.carrier.suggestedFileName)")
    }

    static func commandAttachVP(_ args: [String]) throws {
        guard let carrierPath = args.first else {
            throw IIRYError.commandFailed("attach-vp needs an IIRY carrier path")
        }
        guard let presentationPath = option("--presentation-json", in: args) else {
            throw IIRYError.commandFailed("attach-vp needs --presentation-json")
        }
        let output = option("--out", in: args).map(URL.init(fileURLWithPath:))
        let carrierURL = URL(fileURLWithPath: carrierPath)
        let carrier = try IIRYProofBuilder.decodeCarrier(try Data(contentsOf: carrierURL))
        let responseData = try Data(contentsOf: URL(fileURLWithPath: presentationPath))
        let updated = try IIRYProofBuilder.attachPresentation(carrier: carrier, decodedResponseJSON: responseData)
        let outURL = output ?? carrierURL
        try IIRYProofBuilder.carrierData(updated).write(to: outURL)
        let report = try IIRYVerifier.verifyCarrier(updated)
        printReport(report)
    }

    static func commandVerify(_ args: [String]) throws {
        guard let inputPath = args.first else {
            throw IIRYError.commandFailed("verify needs an IIRY carrier or C2PA JPEG path")
        }
        let inputURL = URL(fileURLWithPath: inputPath)
        let data = try Data(contentsOf: inputURL)

        if let carrier = try? IIRYProofBuilder.decodeCarrier(data) {
            let report = try IIRYVerifier.verifyCarrier(carrier)
            print("app_style_verification:")
            printReport(report)
            Foundation.exit(report.overallPassed ? 0 : 1)
        }

        let detailed = try runProcessCapture(
            executable: c2patoolPath(),
            arguments: [inputURL.path, "-d"]
        )
        let report = try IIRYC2PAInspectionVerifier.verifyC2PAAsset(
            imageData: data,
            detailedJSON: detailed.stdout
        )
        print("app_style_verification:")
        printReport(report)
        if let state = try? IIRYC2PAInspectionVerifier.validationState(fromDetailedJSON: detailed.stdout) {
            print("c2patool_validation_state: \(state)")
        }
        if !detailed.stderr.isEmpty {
            print("c2patool_stderr:")
            print(String(decoding: detailed.stderr, as: UTF8.self))
        }
        Foundation.exit(report.overallPassed ? 0 : 1)
    }

    static func commandExtractImage(_ args: [String]) throws {
        guard let carrierPath = args.first else {
            throw IIRYError.commandFailed("extract-image needs an IIRY carrier path")
        }
        guard let outputPath = option("--out", in: args) else {
            throw IIRYError.commandFailed("extract-image needs --out")
        }
        let carrier = try IIRYProofBuilder.decodeCarrier(try Data(contentsOf: URL(fileURLWithPath: carrierPath)))
        let imageData = try Base64URL.decode(carrier.imageB64URL)
        try imageData.write(to: URL(fileURLWithPath: outputPath))
        print("image: \(outputPath)")
    }

    static func commandC2PAEmbed(_ args: [String]) throws {
        guard let carrierPath = args.first else {
            throw IIRYError.commandFailed("c2pa-embed needs an IIRY carrier path")
        }
        guard let outputPath = option("--out", in: args) else {
            throw IIRYError.commandFailed("c2pa-embed needs --out")
        }
        let carrier = try IIRYProofBuilder.decodeCarrier(try Data(contentsOf: URL(fileURLWithPath: carrierPath)))
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let imageURL = tempDir.appendingPathComponent("image.jpg")
        try Base64URL.decode(carrier.imageB64URL).write(to: imageURL)

        let manifestURL = tempDir.appendingPathComponent("manifest.json")
        try IIRYC2PAManifestBuilder.manifestData(for: carrier, pretty: true).write(to: manifestURL)

        let signResult = try runProcessCapture(
            executable: c2patoolPath(),
            arguments: [imageURL.path, "-m", manifestURL.path, "-o", outputPath, "-f"]
        )
        let detailed = try runProcessCapture(
            executable: c2patoolPath(),
            arguments: [outputPath, "-d"]
        )
        let report = try IIRYC2PAInspectionVerifier.verifyC2PAAsset(
            imageData: try Data(contentsOf: URL(fileURLWithPath: outputPath)),
            detailedJSON: detailed.stdout
        )
        print("c2pa_jpeg: \(outputPath)")
        if !signResult.stderr.isEmpty {
            print("c2patool_signing_stderr:")
            print(String(decoding: signResult.stderr, as: UTF8.self))
        }
        printReport(report)
    }

    static func printReport(_ report: IIRYVerificationReport) {
        for check in report.checks {
            let status = check.passed ? "OK" : "FAIL"
            print("\(status)\t\(check.label)")
            if let detail = check.detail, !detail.isEmpty {
                print("  \(detail)")
            }
        }
        print("overall: \(report.overallPassed ? "OK" : "FAIL")")
    }

    static func option(_ name: String, in args: [String]) -> String? {
        guard let index = args.firstIndex(of: name), index + 1 < args.count else {
            return nil
        }
        return args[index + 1]
    }

    static func runProcess(executable: String, arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = FileHandle.standardOutput
        process.standardError = FileHandle.standardError
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw IIRYError.commandFailed("\(executable) exited with \(process.terminationStatus)")
        }
    }

    static func runProcessCapture(executable: String, arguments: [String]) throws -> (stdout: Data, stderr: Data) {
        let process = Process()
        let stdout = Pipe()
        let stderr = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        process.waitUntilExit()
        let stdoutData = stdout.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderr.fileHandleForReading.readDataToEndOfFile()
        guard process.terminationStatus == 0 else {
            let detail = String(decoding: stderrData.isEmpty ? stdoutData : stderrData, as: UTF8.self)
            throw IIRYError.commandFailed("\(executable) exited with \(process.terminationStatus): \(detail)")
        }
        return (stdoutData, stderrData)
    }

    static func c2patoolPath() throws -> String {
        if let configured = ProcessInfo.processInfo.environment["C2PATOOL_PATH"], !configured.isEmpty {
            return configured
        }
        for candidate in ["/opt/homebrew/bin/c2patool", "/usr/local/bin/c2patool"] {
            if FileManager.default.isExecutableFile(atPath: candidate) {
                return candidate
            }
        }
        throw IIRYError.commandFailed("c2patool not found. Install it or set C2PATOOL_PATH.")
    }


    static func printHelp() {
        print("""
        Usage:
          iiry request-text
          iiry prepare <image.jpg> [--out <proof.iiry>]
          iiry attach-vp <proof.iiry> --presentation-json <decoded-response.json> [--out <proof.iiry>]
          iiry verify <proof.iiry|c2pa-image.jpg>
          iiry extract-image <proof.iiry> --out <image.jpg>
          iiry c2pa-embed <proof.iiry> --out <image.jpg>
        """)
    }
}
