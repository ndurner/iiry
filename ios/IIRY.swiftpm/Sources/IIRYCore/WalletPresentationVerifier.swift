import CryptoKit
import Foundation
import Security

public struct IIRYWalletVerificationPolicy: Equatable {
    public var acceptableAudiences: [String]
    public var pidTrustListURL: URL
    public var pidTrustListSigningCertificateURL: URL
    public var pidTrustListPath: URL?
    public var pidTrustListSigningCertificatePath: URL?

    public init(
        acceptableAudiences: [String] = IIRYWalletVerificationPolicy.defaultAcceptableAudiences(),
        pidTrustListURL: URL = URL(string: "https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/pid-provider.jwt")!,
        pidTrustListSigningCertificateURL: URL = URL(string: "https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/certificate.pem")!,
        pidTrustListPath: URL? = IIRYWalletVerificationPolicy.defaultCacheURL(fileName: "pid-provider-trust-list.jwt"),
        pidTrustListSigningCertificatePath: URL? = IIRYWalletVerificationPolicy.defaultCacheURL(fileName: "pid-provider-trust-list-signer.pem")
    ) {
        self.acceptableAudiences = acceptableAudiences
        self.pidTrustListURL = pidTrustListURL
        self.pidTrustListSigningCertificateURL = pidTrustListSigningCertificateURL
        self.pidTrustListPath = pidTrustListPath
        self.pidTrustListSigningCertificatePath = pidTrustListSigningCertificatePath
    }

    public static func forServiceBaseURL(_ serviceBaseURL: String) -> IIRYWalletVerificationPolicy {
        let normalized = serviceBaseURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        return IIRYWalletVerificationPolicy(acceptableAudiences: ["redirect_uri:\(normalized)"])
    }

    public static func defaultAcceptableAudiences() -> [String] {
        let environment = ProcessInfo.processInfo.environment
        if let audience = environment["IIRY_VERIFIER_IDENTIFIER"], !audience.isEmpty {
            return [audience]
        }
        if let certPath = environment["IIRY_ACCESS_CERT_PEM_PATH"],
           let audience = try? audienceForAccessCertificate(at: URL(fileURLWithPath: certPath)) {
            return [audience]
        }
        if let audience = try? audienceForAccessCertificate(at: URL(fileURLWithPath: "service/secrets/access-certificate.pem")) {
            return [audience]
        }
        if !IIRYGeneratedVerifierPolicy.acceptableAudiences.isEmpty {
            return IIRYGeneratedVerifierPolicy.acceptableAudiences
        }
        let baseURL = (environment["PUBLIC_BASE_URL"] ?? "https://iiry.ndurner.de")
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        return ["redirect_uri:\(baseURL)"]
    }

    public static func forAccessCertificate(at url: URL) throws -> IIRYWalletVerificationPolicy {
        try IIRYWalletVerificationPolicy(acceptableAudiences: [audienceForAccessCertificate(at: url)])
    }

    public static func audienceForAccessCertificate(at url: URL) throws -> String {
        let data = try Data(contentsOf: url)
        let der = try iiryCertificateDER(fromPEMOrDER: data)
        return "x509_hash:\(Base64URL.encode(Hashing.sha256(der)))"
    }

    public static func defaultCacheURL(fileName: String) -> URL? {
        #if os(Linux)
        return nil
        #else
        guard let directory = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first else {
            return nil
        }
        return directory.appendingPathComponent("IIRY", isDirectory: true).appendingPathComponent(fileName)
        #endif
    }
}

public enum IIRYWalletPresentationVerifier {
    public static func verify(
        presentation: String,
        expectedNonce: String,
        policy: IIRYWalletVerificationPolicy = IIRYWalletVerificationPolicy()
    ) -> WalletVerificationSummary {
        var result = WalletVerificationSummary(
            issuerSignature: false,
            issuerCertificateTrusted: false,
            disclosuresMatchIssuerCommitments: false,
            holderSignature: false,
            nonceMatchesChallenge: false,
            audienceIsThisVerifier: false,
            sdHashBindsPresentation: false
        )

        do {
            let acceptableAudiences = policy.acceptableAudiences
            let parts = presentation.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
            guard parts.count >= 3 else {
                throw IIRYError.invalidJWT("SD-JWT presentation must contain issuer JWT, disclosures, and key-binding JWT")
            }

            let issuerJWT = parts[0]
            let disclosures = Array(parts[1..<parts.count - 1])
            let keyBindingJWT = parts[parts.count - 1]

            let issuerHeader = try jwtHeader(issuerJWT)
            guard let x5cValues = issuerHeader["x5c"] as? [String], let leafX5C = x5cValues.first else {
                throw IIRYError.invalidJWT("issuer JWT header has no x5c certificate chain")
            }
            let issuerCertificateDER = try Data(base64EncodedStrict: leafX5C)
            let issuerPublicKey = try certificatePublicKey(fromDER: issuerCertificateDER)
            let issuerClaims = try verifiedJWTClaims(
                issuerJWT,
                publicKey: issuerPublicKey,
                expectedAudience: nil
            )
            result.issuerSignature = true

            do {
                try verifyPIDIssuerTrust(x5cValues: x5cValues, policy: policy)
                result.issuerCertificateTrusted = true
            } catch {
                result.error = "issuer trust: \(error.localizedDescription)"
            }

            let signedDisclosureHashes = Set((issuerClaims["_sd"] as? [String]) ?? [])
            let disclosedHashes = Set(disclosures.map { Base64URL.encode(Hashing.sha256(Data($0.utf8))) })
            result.disclosuresMatchIssuerCommitments = !disclosedHashes.isEmpty && disclosedHashes.isSubset(of: signedDisclosureHashes)

            guard let cnf = issuerClaims["cnf"] as? [String: Any],
                  let holderJWK = cnf["jwk"] as? [String: Any] else {
                throw IIRYError.invalidJWT("issuer JWT does not contain cnf.jwk holder key")
            }
            let holderKey = try jwkPublicKey(holderJWK)
            let keyBindingClaims = try verifiedJWTClaims(
                keyBindingJWT,
                publicKey: holderKey,
                expectedAudience: nil
            )
            result.holderSignature = true
            result.nonceMatchesChallenge = keyBindingClaims["nonce"] as? String == expectedNonce

            if let aud = keyBindingClaims["aud"] as? String {
                result.audience = aud
                result.audienceIsThisVerifier = acceptableAudiences.contains(aud)
            } else if let aud = keyBindingClaims["aud"] as? [String] {
                result.audience = aud.joined(separator: ", ")
                result.audienceIsThisVerifier = !Set(aud).isDisjoint(with: acceptableAudiences)
            }

            let signedSDJWT = ([issuerJWT] + disclosures).joined(separator: "~") + "~"
            let expectedSDHash = Base64URL.encode(Hashing.sha256(Data(signedSDJWT.utf8)))
            result.sdHashBindsPresentation = keyBindingClaims["sd_hash"] as? String == expectedSDHash
        } catch {
            result.error = error.localizedDescription
        }

        return result
    }

    private static func verifyPIDIssuerTrust(x5cValues: [String], policy: IIRYWalletVerificationPolicy) throws {
        let trustListToken = try fetchText(url: policy.pidTrustListURL, cacheURL: policy.pidTrustListPath).trimmingCharacters(in: .whitespacesAndNewlines)
        let signingCertificatePEM = try fetchText(
            url: policy.pidTrustListSigningCertificateURL,
            cacheURL: policy.pidTrustListSigningCertificatePath
        )
        let signingCertificateDER = try derFromPEM(signingCertificatePEM)
        let signingPublicKey = try certificatePublicKey(fromDER: signingCertificateDER)
        let trustListPayload = try verifiedJWTClaims(trustListToken, publicKey: signingPublicKey, expectedAudience: nil)
        guard (try jwtHeader(trustListToken)["typ"] as? String) == "trustlist+jwt" else {
            throw IIRYError.invalidJWT("unexpected trust-list JWT typ")
        }
        try validateTrustListFreshness(trustListPayload)
        let anchors = try pidIssuanceTrustAnchors(from: trustListPayload)
        guard !anchors.isEmpty else {
            throw IIRYError.invalidJWT("PID trust list contains no issuance trust anchors")
        }
        let chain = try x5cValues.map { try Data(base64EncodedStrict: $0) }
        try verifyCertificateChain(chain: chain, anchors: anchors)
    }

    private static func validateTrustListFreshness(_ payload: [String: Any]) throws {
        guard let lote = payload["LoTE"] as? [String: Any],
              let info = lote["ListAndSchemeInformation"] as? [String: Any],
              let nextUpdate = info["NextUpdate"] as? String,
              let expiresAt = iso8601Date(nextUpdate) else {
            throw IIRYError.invalidJWT("trust list has no NextUpdate")
        }
        guard Date() < expiresAt else {
            throw IIRYError.invalidJWT("trust list expired at \(nextUpdate)")
        }
    }

    private static func pidIssuanceTrustAnchors(from payload: [String: Any]) throws -> [Data] {
        guard let lote = payload["LoTE"] as? [String: Any],
              let entities = lote["TrustedEntitiesList"] as? [[String: Any]] else {
            return []
        }
        var anchors: [Data] = []
        for entity in entities {
            guard let services = entity["TrustedEntityServices"] as? [[String: Any]] else {
                continue
            }
            for service in services {
                guard let info = service["ServiceInformation"] as? [String: Any],
                      info["ServiceTypeIdentifier"] as? String == "http://uri.etsi.org/19602/SvcType/PID/Issuance",
                      let digitalIdentity = info["ServiceDigitalIdentity"] as? [String: Any],
                      let certs = digitalIdentity["X509Certificates"] as? [[String: Any]] else {
                    continue
                }
                for cert in certs {
                    if let value = cert["val"] as? String {
                        anchors.append(try Data(base64EncodedStrict: value))
                    }
                }
            }
        }
        return anchors
    }

    private static func verifiedJWTClaims(
        _ compactJWT: String,
        publicKey: VerifiedPublicKey,
        expectedAudience: [String]?
    ) throws -> [String: Any] {
        let parts = compactJWT.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3 else {
            throw IIRYError.invalidJWT("JWT must have three segments")
        }
        let header = try jsonObject(Base64URL.decode(parts[0]))
        let payloadData = try Base64URL.decode(parts[1])
        let payload = try jsonObject(payloadData)
        let signingInput = Data("\(parts[0]).\(parts[1])".utf8)
        let signature = try Base64URL.decode(parts[2])
        let alg = (header["alg"] as? String) ?? ""
        guard try verify(signature: signature, message: signingInput, alg: alg, publicKey: publicKey) else {
            throw IIRYError.invalidJWT("JWT \(alg) signature did not verify")
        }
        try validateJWTTimeClaims(payload)
        if let expectedAudience {
            try validateAudience(payload["aud"], expectedAudience: expectedAudience)
        }
        return payload
    }

    private static func validateJWTTimeClaims(_ claims: [String: Any]) throws {
        let now = Date().timeIntervalSince1970
        if let exp = numericDate(claims["exp"]), now >= exp {
            throw IIRYError.invalidJWT("JWT expired")
        }
        if let nbf = numericDate(claims["nbf"]), now < nbf {
            throw IIRYError.invalidJWT("JWT not yet valid")
        }
        if let iat = numericDate(claims["iat"]), now + 300 < iat {
            throw IIRYError.invalidJWT("JWT issued in the future")
        }
    }

    private static func validateAudience(_ value: Any?, expectedAudience: [String]) throws {
        if let aud = value as? String, expectedAudience.contains(aud) {
            return
        }
        if let aud = value as? [String], !Set(aud).isDisjoint(with: expectedAudience) {
            return
        }
        throw IIRYError.invalidJWT("JWT audience does not match this verifier")
    }

    private static func numericDate(_ value: Any?) -> TimeInterval? {
        if let number = value as? NSNumber {
            return number.doubleValue
        }
        if let double = value as? Double {
            return double
        }
        if let int = value as? Int {
            return Double(int)
        }
        return nil
    }

    private static func iso8601Date(_ value: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: value) {
            return date
        }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: value)
    }

    private static func jwtHeader(_ compactJWT: String) throws -> [String: Any] {
        let parts = compactJWT.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3 else {
            throw IIRYError.invalidJWT("JWT must have three segments")
        }
        return try jsonObject(Base64URL.decode(parts[0]))
    }

    private static func jsonObject(_ data: Data) throws -> [String: Any] {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw IIRYError.invalidJWT("JWT payload is not a JSON object")
        }
        return object
    }

    private static func verify(signature: Data, message: Data, alg: String, publicKey: VerifiedPublicKey) throws -> Bool {
        switch (alg, publicKey) {
        case ("ES256", .secKey(let key)):
            let derSignature = try derEncodedECDSASignature(rawSignature: signature)
            var error: Unmanaged<CFError>?
            let ok = SecKeyVerifySignature(
                key,
                .ecdsaSignatureMessageX962SHA256,
                message as CFData,
                derSignature as CFData,
                &error
            )
            if let error {
                throw error.takeRetainedValue() as Error
            }
            return ok
        case ("ES256", .p256(let key)):
            let ecdsaSignature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
            return key.isValidSignature(ecdsaSignature, for: message)
        case ("EdDSA", .ed25519(let key)):
            return key.isValidSignature(signature, for: message)
        default:
            throw IIRYError.invalidJWT("unsupported JWT alg/key combination: \(alg)")
        }
    }

    private static func certificatePublicKey(fromDER der: Data) throws -> VerifiedPublicKey {
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData),
              let key = SecCertificateCopyKey(certificate) else {
            throw IIRYError.invalidJWT("could not read certificate public key")
        }
        return .secKey(key)
    }

    private static func jwkPublicKey(_ jwk: [String: Any]) throws -> VerifiedPublicKey {
        guard let kty = jwk["kty"] as? String else {
            throw IIRYError.invalidJWT("JWK missing kty")
        }
        if kty == "EC" {
            guard (jwk["crv"] as? String) == "P-256",
                  let x = jwk["x"] as? String,
                  let y = jwk["y"] as? String else {
                throw IIRYError.invalidJWT("unsupported EC JWK")
            }
            let xData = try Base64URL.decode(x)
            let yData = try Base64URL.decode(y)
            guard xData.count == 32, yData.count == 32 else {
                throw IIRYError.invalidJWT("P-256 JWK coordinates must be 32 bytes")
            }
            return .p256(try P256.Signing.PublicKey(x963Representation: Data([0x04]) + xData + yData))
        }
        if kty == "OKP" {
            guard (jwk["crv"] as? String) == "Ed25519", let x = jwk["x"] as? String else {
                throw IIRYError.invalidJWT("unsupported OKP JWK")
            }
            return .ed25519(try Curve25519.Signing.PublicKey(rawRepresentation: Base64URL.decode(x)))
        }
        throw IIRYError.invalidJWT("unsupported JWK kty: \(kty)")
    }

    private static func verifyCertificateChain(chain: [Data], anchors: [Data]) throws {
        guard !chain.isEmpty else {
            throw IIRYError.invalidJWT("issuer JWT has no x5c certificate chain")
        }
        let certificates = chain.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        let anchorCertificates = anchors.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        guard certificates.count == chain.count, anchorCertificates.count == anchors.count else {
            throw IIRYError.invalidJWT("could not parse certificate chain")
        }
        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(certificates as CFArray, SecPolicyCreateBasicX509(), &trust)
        guard status == errSecSuccess, let trust else {
            throw IIRYError.invalidJWT("could not create certificate trust evaluation")
        }
        SecTrustSetAnchorCertificates(trust, anchorCertificates as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            if let error {
                throw error as Error
            }
            throw IIRYError.invalidJWT("issuer certificate chain does not terminate at a trusted PID issuance anchor")
        }
    }

    private static func fetchText(url: URL, cacheURL: URL?) throws -> String {
        do {
            let data = try Data(contentsOf: url)
            if let cacheURL {
                try FileManager.default.createDirectory(
                    at: cacheURL.deletingLastPathComponent(),
                    withIntermediateDirectories: true
                )
                try data.write(to: cacheURL)
            }
            return String(decoding: data, as: UTF8.self)
        } catch {
            if let cacheURL, FileManager.default.fileExists(atPath: cacheURL.path) {
                return try String(contentsOf: cacheURL, encoding: .utf8)
            }
            throw error
        }
    }

    private static func derFromPEM(_ pem: String) throws -> Data {
        try iiryCertificateDER(fromPEMOrDER: Data(pem.utf8))
    }

    private static func derEncodedECDSASignature(rawSignature: Data) throws -> Data {
        guard rawSignature.count == 64 else {
            throw IIRYError.invalidJWT("ES256 signature must be 64 raw bytes")
        }
        let r = derInteger(rawSignature.prefix(32))
        let s = derInteger(rawSignature.suffix(32))
        let body = r + s
        return Data([0x30]) + derLength(body.count) + body
    }

    private static func derInteger(_ bytes: Data.SubSequence) -> Data {
        var value = Data(bytes)
        while value.count > 1 && value.first == 0x00 && (value.dropFirst().first ?? 0) < 0x80 {
            value.removeFirst()
        }
        if (value.first ?? 0) >= 0x80 {
            value.insert(0x00, at: 0)
        }
        return Data([0x02]) + derLength(value.count) + value
    }

    private static func derLength(_ length: Int) -> Data {
        if length < 0x80 {
            return Data([UInt8(length)])
        }
        var value = length
        var bytes: [UInt8] = []
        while value > 0 {
            bytes.insert(UInt8(value & 0xff), at: 0)
            value >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }
}

private enum VerifiedPublicKey {
    case secKey(SecKey)
    case p256(P256.Signing.PublicKey)
    case ed25519(Curve25519.Signing.PublicKey)
}

private func iiryCertificateDER(fromPEMOrDER data: Data) throws -> Data {
    guard let text = String(data: data, encoding: .utf8),
          text.contains("-----BEGIN CERTIFICATE-----") else {
        return data
    }
    let lines = text
        .split(whereSeparator: \.isNewline)
        .map(String.init)
        .filter { !$0.hasPrefix("-----") }
    return try Data(base64EncodedStrict: lines.joined())
}

private extension Data {
    init(base64EncodedStrict value: String) throws {
        guard let data = Data(base64Encoded: value) else {
            throw IIRYError.invalidBase64URL(value)
        }
        self = data
    }
}
