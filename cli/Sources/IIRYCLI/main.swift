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
        case "sign":
            try commandSign(args)
        case "verify":
            try commandVerify(args)
        case "-h", "--help", "help":
            printHelp()
        default:
            throw IIRYError.commandFailed("Unknown command: \(command)")
        }
    }

    static func commandSign(_ args: [String]) throws {
        guard let input = args.first else {
            throw IIRYError.commandFailed("sign needs an input JPEG path")
        }
        guard let presentationPath = option("--presentation-json", in: args) else {
            throw IIRYError.commandFailed("sign needs --presentation-json")
        }
        let output = option("--out", in: args).map(URL.init(fileURLWithPath:))
        let imageURL = URL(fileURLWithPath: input)
        let imageData = try Data(contentsOf: imageURL)
        let prepared = try IIRYProofBuilder.prepare(imageData: imageData)
        let responseData = try Data(contentsOf: URL(fileURLWithPath: presentationPath))
        let updated = try IIRYProofBuilder.attachPresentation(draft: prepared.draft, decodedResponseJSON: responseData)
        let signed = try IIRYC2PAAssetProcessor.signJPEG(draft: updated)
        let outURL = output ?? imageURL
            .deletingLastPathComponent()
            .appendingPathComponent(IIRYFileNames.c2paTransportFileName(from: updated.suggestedFileName))
        try signed.jpegData.write(to: outURL)
        let report = try IIRYC2PAAssetProcessor.verifyJPEG(signed.jpegData)
        print("c2pa_transport: \(outURL.path)")
        print("nonce: \(prepared.nonce)")
        printReport(report)
    }

    static func commandVerify(_ args: [String]) throws {
        guard let inputPath = args.first else {
            throw IIRYError.commandFailed("verify needs a C2PA JPEG path")
        }
        let mode = verificationMode(args)
        let inputURL = URL(fileURLWithPath: inputPath)
        let data = try Data(contentsOf: inputURL)

        var overall = true
        if mode == .own || mode == .both {
            let report = try IIRYC2PAAssetProcessor.verifyJPEG(
                data,
                walletPolicy: try walletVerificationPolicy(args)
            )
            print("own_c2pa_verification:")
            printReport(report)
            overall = overall && report.overallPassed
        }
        if mode == .c2patool || mode == .both {
            let detailed = try runProcessCaptureAllowingFailure(
                executable: c2patoolPath(),
                arguments: try c2patoolVerificationArguments(inputPath: inputURL.path, args: args)
            )
            print("c2patool_verification:")
            if detailed.exitCode == 0, !detailed.stdout.isEmpty {
                let report = try IIRYC2PAInspectionVerifier.verifyC2PAAsset(
                    imageData: data,
                    detailedJSON: detailed.stdout
                )
                printReport(report)
                if let state = try? IIRYC2PAInspectionVerifier.validationState(fromDetailedJSON: detailed.stdout) {
                    print("c2patool_validation_state: \(state)")
                }
                overall = overall && report.overallPassed
            } else {
                print("FAIL\tc2patool accepted the asset")
                print("overall: FAIL")
                overall = false
            }
            if !detailed.stderr.isEmpty {
                print("c2patool_stderr:")
                print(String(decoding: detailed.stderr, as: UTF8.self))
            }
        }
        Foundation.exit(overall ? 0 : 1)
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

    static func walletVerificationPolicy(_ args: [String]) throws -> IIRYWalletVerificationPolicy {
        if let audience = option("--audience", in: args), !audience.isEmpty {
            return IIRYWalletVerificationPolicy(acceptableAudiences: [audience])
        }
        if let accessCert = option("--access-cert", in: args), !accessCert.isEmpty {
            return try IIRYWalletVerificationPolicy.forAccessCertificate(at: URL(fileURLWithPath: accessCert))
        }
        if let serviceBaseURL = option("--service-base-url", in: args), !serviceBaseURL.isEmpty {
            return IIRYWalletVerificationPolicy.forServiceBaseURL(serviceBaseURL)
        }
        if ProcessInfo.processInfo.environment["IIRY_VERIFIER_IDENTIFIER"] != nil {
            return IIRYWalletVerificationPolicy()
        }
        return IIRYWalletVerificationPolicy()
    }

    enum VerificationMode {
        case own
        case c2patool
        case both
    }

    static func verificationMode(_ args: [String]) -> VerificationMode {
        if args.contains("--both") {
            return .both
        }
        if args.contains("--c2patool") {
            return .c2patool
        }
        return .own
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
        let result = try runProcessCaptureAllowingFailure(executable: executable, arguments: arguments)
        guard result.exitCode == 0 else {
            let detail = String(decoding: result.stderr.isEmpty ? result.stdout : result.stderr, as: UTF8.self)
            throw IIRYError.commandFailed("\(executable) exited with \(result.exitCode): \(detail)")
        }
        return (result.stdout, result.stderr)
    }

    static func runProcessCaptureAllowingFailure(executable: String, arguments: [String]) throws -> (stdout: Data, stderr: Data, exitCode: Int32) {
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
        return (stdoutData, stderrData, process.terminationStatus)
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

    static func c2patoolVerificationArguments(inputPath: String, args: [String]) throws -> [String] {
        var toolArgs = [inputPath, "-d"]
        if trustsC2PASample(args) {
            let anchor = try writeC2PASampleTrustAnchor()
            toolArgs.append(contentsOf: ["trust", "--trust_anchors", anchor.path])
        }
        return toolArgs
    }

    static func trustsC2PASample(_ args: [String]) -> Bool {
        if args.contains("--trust-c2pa-sample") {
            return true
        }
        let value = ProcessInfo.processInfo.environment["IIRY_TRUST_C2PA_SAMPLE"] ?? ""
        return ["1", "true", "yes"].contains(value.lowercased())
    }

    static func writeC2PASampleTrustAnchor() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("iiry-c2pa-es256-sample-trust-anchor.pem")
        try Data(c2paSampleES256TrustAnchorPEM.utf8).write(to: url)
        return url
    }

    // Development-only C2PA ES256 sample root anchor from c2pa-rs/cli/sample/trust_anchors.pem.
    // This is useful for local conformance checks and must not be treated as production trust.
    static let c2paSampleES256TrustAnchorPEM = """
    -----BEGIN CERTIFICATE-----
    MIICUzCCAfmgAwIBAgIUdmkq4byvgk2FSnddHqB2yjoD68gwCgYIKoZIzj0EAwIw
    dzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRIwEAYDVQQHDAlTb21ld2hlcmUx
    GjAYBgNVBAoMEUMyUEEgVGVzdCBSb290IENBMRkwFwYDVQQLDBBGT1IgVEVTVElO
    R19PTkxZMRAwDgYDVQQDDAdSb290IENBMB4XDTIyMDYxMDE4NDY0MFoXDTMyMDYw
    NzE4NDY0MFowdzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRIwEAYDVQQHDAlT
    b21ld2hlcmUxGjAYBgNVBAoMEUMyUEEgVGVzdCBSb290IENBMRkwFwYDVQQLDBBG
    T1IgVEVTVElOR19PTkxZMRAwDgYDVQQDDAdSb290IENBMFkwEwYHKoZIzj0CAQYI
    KoZIzj0DAQcDQgAEre/KpcWwGEHt+mD4xso3xotRnRx2IEsMoYwVIKI7iEJrDEye
    PcvJuBywA0qiMw2yvAvGOzW/fqUTu1jABrFIk6NjMGEwHQYDVR0OBBYEFF6ZuIbh
    eBvZVxVadQBStikOy6iMMB8GA1UdIwQYMBaAFF6ZuIbheBvZVxVadQBStikOy6iM
    MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMCA0gA
    MEUCIHBC1xLwkCWSGhVXFlSnQBx9cGZivXzCbt8BuwRqPSUoAiEAteZQDk685yh9
    jgOTkp4H8oAmM1As+qlkRK2b+CHAQ3k=
    -----END CERTIFICATE-----
    """


    static func printHelp() {
        print("""
        Usage:
          iiry request-text
          iiry sign <image.jpg> --presentation-json <decoded-response.json> [--out <c2pa-image.iiry>]
          iiry verify <c2pa-image.iiry|c2pa-image.jpg> [--own|--c2patool|--both] [--access-cert <cert.pem>|--audience <aud>|--service-base-url <url>] [--trust-c2pa-sample]
        """)
    }
}
