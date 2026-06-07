import CryptoKit
import Foundation

public struct IIRYC2PASignedAsset {
    public var jpegData: Data
    public var manifestReportJSON: Data

    public init(jpegData: Data, manifestReportJSON: Data) {
        self.jpegData = jpegData
        self.manifestReportJSON = manifestReportJSON
    }
}

public enum IIRYC2PAAssetProcessor {
    public static func signJPEG(carrier: IIRYCarrier) throws -> IIRYC2PASignedAsset {
        let visualJPEG = try Base64URL.decode(carrier.imageB64URL)
        guard IIRYJPEGC2PA.isJPEG(visualJPEG) else {
            throw IIRYError.invalidCarrier("IIRY C2PA profile currently supports JPEG only")
        }

        let signer = try IIRYC2PADevSigner()
        var dataHash = Data(repeating: 0, count: 32)
        var exclusions: [IIRYC2PAHashRange] = []

        for _ in 0..<8 {
            let store = try IIRYC2PAProfileStore.build(
                carrier: carrier,
                dataHash: dataHash,
                exclusions: exclusions,
                signer: signer
            )
            let signedJPEG = try IIRYJPEGC2PA.embed(storeBytes: store.storeBytes, intoJPEG: visualJPEG)
            let nextExclusions = try IIRYJPEGC2PA.c2paSegmentRanges(inJPEG: signedJPEG)
            let nextHash = Hashing.sha256(IIRYJPEGC2PA.bytes(signedJPEG, excluding: nextExclusions))

            if nextHash == dataHash, nextExclusions == exclusions {
                let report = try readManifestReport(fromJPEGData: signedJPEG)
                return IIRYC2PASignedAsset(jpegData: signedJPEG, manifestReportJSON: report)
            }

            dataHash = nextHash
            exclusions = nextExclusions
        }

        throw IIRYError.commandFailed("IIRY C2PA profile did not converge on stable JPEG exclusion ranges")
    }

    public static func readManifestReport(fromJPEGData imageData: Data) throws -> Data {
        let profile = try IIRYC2PAProfileStore.read(fromJPEG: imageData)
        let validation = try validate(profile: profile, imageData: imageData)
        return try IIRYC2PAProfileReport.data(profile: profile, validation: validation, pretty: true)
    }

    public static func verifyJPEG(_ imageData: Data) throws -> IIRYVerificationReport {
        let profile = try IIRYC2PAProfileStore.read(fromJPEG: imageData)
        let validation = try validate(profile: profile, imageData: imageData)
        let visualJPEG = try IIRYJPEGC2PA.stripC2PASegments(fromJPEG: imageData)
        let materialDigest = try assetBindingMaterialDigest(for: visualJPEG)
        var checks: [IIRYVerificationCheck] = [
            .init(
                id: "iiry_c2pa_profile",
                label: "IIRY JPEG/C2PA profile is present",
                passed: true,
                detail: profile.manifestLabel
            ),
            .init(
                id: "c2pa_data_hash",
                label: "JPEG bytes match c2pa.hash.data exclusions",
                passed: validation.dataHashMatches,
                detail: validation.dataHashDetail
            ),
            .init(
                id: "c2pa_claim_signature",
                label: "C2PA claim signature validates",
                passed: validation.profileSignatureValid,
                detail: validation.profileSignatureDetail
            ),
            .init(
                id: "iiry_claim_assertion_hashes",
                label: "Claim references match assertion hashes",
                passed: validation.claimAssertionHashesMatch,
                detail: validation.claimAssertionHashDetail
            ),
            .init(
                id: "cawg_identity_assertion",
                label: "Manifest carries CAWG identity assertion",
                passed: profile.cawgIdentity != nil,
                detail: IIRYConstants.cawgIdentityAssertionLabel
            )
        ]

        if let identity = profile.cawgIdentity {
            checks.append(contentsOf: try cawgIdentityChecks(
                identity: identity,
                profile: profile,
                materialDigest: materialDigest
            ))
        }

        return IIRYVerificationReport(checks: checks)
    }

    public static func carrier(fromJPEGData imageData: Data, suggestedFileName: String) throws -> IIRYCarrier {
        let profile = try IIRYC2PAProfileStore.read(fromJPEG: imageData)
        guard let identity = profile.cawgIdentity else {
            throw IIRYError.invalidCarrier("C2PA manifest does not contain a CAWG identity assertion")
        }
        let visualJPEG = try IIRYJPEGC2PA.stripC2PASegments(fromJPEG: imageData)
        let proof = try proofBundle(from: identity, imageData: visualJPEG)
        return IIRYCarrier(
            suggestedFileName: suggestedFileName,
            imageB64URL: Base64URL.encode(visualJPEG),
            proof: proof
        )
    }

    public static func visualJPEGData(from imageData: Data) throws -> Data {
        try IIRYJPEGC2PA.stripC2PASegments(fromJPEG: imageData)
    }

    private static func validate(profile: IIRYC2PAParsedProfile, imageData: Data) throws -> IIRYC2PAProfileValidation {
        let computedHash = Hashing.sha256(IIRYJPEGC2PA.bytes(imageData, excluding: profile.dataHash.exclusions))
        let dataHashMatches = computedHash == profile.dataHash.hash

        let assertionHashesMatch = profile.claim.assertions.allSatisfy { reference in
            guard let assertion = profile.assertions[reference.label] else {
                return false
            }
            return assertion.hash == reference.hash && reference.alg == "sha256"
        }

        let signatureValid: Bool
        let signatureDetail: String
        do {
            signatureValid = try IIRYC2PADevSigner.verifyDetachedCOSE(
                profile.coseSignature,
                payload: profile.claimCBOR
            )
            signatureDetail = "COSE_Sign1 ES256 over detached c2pa.claim.v2 bytes"
        } catch {
            signatureValid = false
            signatureDetail = error.localizedDescription
        }

        return IIRYC2PAProfileValidation(
            dataHashMatches: dataHashMatches,
            dataHashDetail: "sha256:\(Base64URL.encode(computedHash))",
            profileSignatureValid: signatureValid,
            profileSignatureDetail: signatureDetail,
            claimAssertionHashesMatch: assertionHashesMatch,
            claimAssertionHashDetail: "\(profile.claim.assertions.count) claim references"
        )
    }

    private static func cawgIdentityChecks(
        identity: IIRYCAWGIdentityAssertion,
        profile: IIRYC2PAParsedProfile,
        materialDigest: Data
    ) throws -> [IIRYVerificationCheck] {
        let hardBindingReference = profile.claim.assertions.first { $0.label == "c2pa.hash.data" }
        let referencesHardBinding = hardBindingReference.map { hardBinding in
            identity.referencedAssertions.contains { reference in
                reference.url == hardBinding.url &&
                reference.alg == hardBinding.alg &&
                reference.hash == hardBinding.hash
            }
        } ?? false
        let evidence = try IIRYCAWGEvidence.decode(identity.signature)
        let decodedNonce = evidence.nonce.flatMap { try? IIRYNonce.decode($0) }
        let disclosedClaims = evidence.presentation.map(PresentationExtractor.disclosedClaims(fromPresentation:)) ?? [:]
        let givenName = disclosedClaims["given_name"]?.trimmingCharacters(in: .whitespacesAndNewlines)
        let familyName = disclosedClaims["family_name"]?.trimmingCharacters(in: .whitespacesAndNewlines)
        return [
            .init(
                id: "cawg_identity_sig_type",
                label: "CAWG identity assertion uses IIRY OpenID4VP sig_type",
                passed: identity.sigType == IIRYConstants.cawgOpenID4VPSigType,
                detail: identity.sigType
            ),
            .init(
                id: "cawg_identity_hard_binding_reference",
                label: "CAWG identity assertion references c2pa.hash.data",
                passed: referencesHardBinding,
                detail: hardBindingReference?.url ?? "Missing c2pa.hash.data claim reference"
            ),
            .init(
                id: "cawg_identity_evidence",
                label: "CAWG identity signature carries OpenID4VP vp_token",
                passed: evidence.vpTokenObject != nil,
                detail: "vp_token"
            ),
            .init(
                id: "openid4vp_vp_token_present",
                label: "OpenID4VP evidence contains vp_token",
                passed: evidence.presentation?.isEmpty == false,
                detail: evidence.presentation == nil ? "Missing vp_token" : "vp_token embedded"
            ),
            .init(
                id: "nonce_decodes",
                label: "OpenID4VP nonce decodes",
                passed: decodedNonce != nil,
                detail: decodedNonce?.type
            ),
            .init(
                id: "nonce_payload",
                label: "Nonce payload is IIRY OpenID4VP nonce",
                passed: decodedNonce?.type == IIRYConstants.nonceType && decodedNonce?.version == 2,
                detail: decodedNonce?.type
            ),
            .init(
                id: "nonce_asset_binding",
                label: "Nonce binds asset binding digest",
                passed: decodedNonce?.assetBindingSHA256B64URL == Base64URL.encode(materialDigest),
                detail: decodedNonce?.assetBindingSHA256B64URL
            ),
            .init(
                id: "presentation_nonce",
                label: "Presentation nonce matches",
                passed: evidence.nonce != nil && decodedNonce != nil,
                detail: evidence.nonce
            ),
            .init(
                id: "pid_name_disclosed",
                label: "Wallet disclosed committed person's name",
                passed: givenName?.isEmpty == false && familyName?.isEmpty == false,
                detail: [givenName, familyName].compactMap { $0 }.joined(separator: " ")
            )
        ]
    }

    private static func proofBundle(from identity: IIRYCAWGIdentityAssertion, imageData: Data) throws -> IIRYProofBundle {
        let evidence = try IIRYCAWGEvidence.decode(identity.signature)
        guard let noncePayload = evidence.nonce.flatMap({ try? IIRYNonce.decode($0) }) else {
            throw IIRYError.invalidCarrier("CAWG identity vp_token does not contain a decodable IIRY nonce")
        }
        let assetSHA = Hashing.sha256(imageData)
        let materialDigest = try assetBindingMaterialDigest(for: imageData)
        let asset = IIRYAssetBinding(
            mediaType: IIRYConstants.jpegMediaType,
            byteLength: imageData.count,
            sha256B64URL: Base64URL.encode(assetSHA),
            bindingMaterialSHA256B64URL: Base64URL.encode(materialDigest)
        )
        let cawg = IIRYCAWGAssertion(referencedAssertions: identity.referencedAssertions.map {
            IIRYReferencedAssertion(url: $0.url, hashB64URL: Base64URL.encode($0.hash))
        })
        return IIRYProofBundle(
            createdAt: "",
            asset: asset,
            noncePayload: noncePayload,
            cawg: cawg,
            openID4VP: OpenID4VPEvidence(
                nonce: evidence.nonce ?? "",
                compactPresentation: evidence.presentation
            ),
            disclosedClaims: evidence.presentation.map(PresentationExtractor.disclosedClaims(fromPresentation:)) ?? [:]
        )
    }

    private static func assetBindingMaterialDigest(for imageData: Data) throws -> Data {
        let assetSHA = Hashing.sha256(imageData)
        let material = IIRYAssetBindingMaterial(
            mediaType: IIRYConstants.jpegMediaType,
            byteLength: imageData.count,
            assetSHA256B64URL: Base64URL.encode(assetSHA)
        )
        return Hashing.sha256(try JSONCoding.canonicalData(material))
    }
}

struct IIRYC2PAHashRange: Codable, Equatable {
    var start: UInt64
    var length: UInt64
}

private struct IIRYC2PAProfileValidation {
    var dataHashMatches: Bool
    var dataHashDetail: String
    var profileSignatureValid: Bool
    var profileSignatureDetail: String
    var claimAssertionHashesMatch: Bool
    var claimAssertionHashDetail: String
}

private struct IIRYC2PAProfileBuild {
    var storeBytes: Data
    var manifestLabel: String
}

private struct IIRYC2PAParsedProfile {
    var manifestLabel: String
    var assertions: [String: IIRYC2PAParsedAssertion]
    var cawgIdentity: IIRYCAWGIdentityAssertion?
    var actions: [String: Any]?
    var dataHash: IIRYC2PADataHash
    var claim: IIRYC2PAClaim
    var claimCBOR: Data
    var coseSignature: Data
}

private struct IIRYC2PAParsedAssertion {
    var label: String
    var contentType: String
    var data: Data
    var hash: Data
    var jsonObject: Any?
}

private struct IIRYC2PADataHash {
    var exclusions: [IIRYC2PAHashRange]
    var name: String
    var alg: String
    var hash: Data
}

private struct IIRYCAWGIdentityAssertion {
    var sigType: String
    var referencedAssertions: [IIRYC2PAClaimAssertion]
    var signature: Data
}

private struct IIRYCAWGEvidence {
    var vpTokenObject: [String: Any]?
    var presentation: String?
    var nonce: String?

    static func decode(_ data: Data) throws -> IIRYCAWGEvidence {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw IIRYError.invalidCarrier("Unsupported CAWG OpenID4VP evidence payload: expected v2 JSON object")
        }
        guard let vpToken = object["vp_token"] as? [String: Any] else {
            if object["presentation"] != nil || object["nonce_payload"] != nil || object["wallet_verification"] != nil {
                throw IIRYError.invalidCarrier("Unsupported CAWG OpenID4VP evidence payload: expected v2 {\"vp_token\": ...}; found pre-v2 expanded evidence")
            }
            throw IIRYError.invalidCarrier("Unsupported CAWG OpenID4VP evidence payload: expected v2 {\"vp_token\": ...}")
        }
        let presentation = PresentationExtractor.firstPresentation(fromVPTokenObject: vpToken)
        let nonce = try presentation.flatMap(PresentationExtractor.nonce(fromPresentation:))
        return IIRYCAWGEvidence(
            vpTokenObject: vpToken,
            presentation: presentation,
            nonce: nonce
        )
    }
}

private struct IIRYC2PAClaimAssertion {
    var url: String
    var alg: String
    var hash: Data

    var label: String {
        url.components(separatedBy: "/").last ?? url
    }
}

private struct IIRYC2PAClaim {
    var signatureURL: String
    var assertions: [IIRYC2PAClaimAssertion]
}

private struct IIRYC2PADevSigner {
    private let privateKey: P256.Signing.PrivateKey
    private let certificateChain: [Data]
    private let protectedHeader: Data

    init() throws {
        self.privateKey = try P256.Signing.PrivateKey(pemRepresentation: Self.privateKeyPEM)
        self.certificateChain = try Self.derCertificates(fromPEM: Self.certificateChainPEM)
        self.protectedHeader = try IIRYC2PACBOR.coseProtectedHeader(certificateChain: certificateChain)
    }

    func signDetachedCOSE(payload: Data) throws -> Data {
        let signatureInput = try IIRYC2PACBOR.coseSignatureInput(
            protectedHeader: protectedHeader,
            payload: payload
        )
        let signature = try privateKey.signature(for: signatureInput)
        return try IIRYC2PACBOR.coseSignature(
            protectedHeader: protectedHeader,
            signature: signature.rawRepresentation
        )
    }

    static func verifyDetachedCOSE(_ cose: Data, payload: Data) throws -> Bool {
        let signer = try IIRYC2PADevSigner()
        let coseParts = try IIRYC2PACBOR.decodeCOSESign1(cose)
        let signatureInput = try IIRYC2PACBOR.coseSignatureInput(
            protectedHeader: coseParts.protectedHeader,
            payload: payload
        )
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: coseParts.signature)
        return signer.privateKey.publicKey.isValidSignature(signature, for: signatureInput)
    }

    private static func derCertificates(fromPEM pem: String) throws -> [Data] {
        var certificates: [Data] = []
        let blocks = pem.components(separatedBy: "-----END CERTIFICATE-----")
        for block in blocks {
            guard let markerRange = block.range(of: "-----BEGIN CERTIFICATE-----") else {
                continue
            }
            let base64 = block[markerRange.upperBound...]
                .filter { !$0.isWhitespace }
            guard let data = Data(base64Encoded: String(base64)) else {
                throw IIRYError.invalidCarrier("Invalid C2PA development certificate PEM")
            }
            certificates.append(data)
        }
        guard !certificates.isEmpty else {
            throw IIRYError.invalidCarrier("C2PA development certificate chain is empty")
        }
        return certificates
    }

    // Same development-only ES256 material bundled with c2patool/c2pa-rs samples.
    // It validates C2PA mechanics but does not provide production signing identity.
    private static let privateKeyPEM = """
    -----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfNJBsaRLSeHizv0m
    GL+gcn78QmtfLSm+n+qG9veC2W2hRANCAAQPaL6RkAkYkKU4+IryBSYxJM3h77sF
    iMrbvbI8fG7w2Bbl9otNG/cch3DAw5rGAPV7NWkyl3QGuV/wt0MrAPDo
    -----END PRIVATE KEY-----
    """

    private static let certificateChainPEM = """
    -----BEGIN CERTIFICATE-----
    MIIChzCCAi6gAwIBAgIUcCTmJHYF8dZfG0d1UdT6/LXtkeYwCgYIKoZIzj0EAwIw
    gYwxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTESMBAGA1UEBwwJU29tZXdoZXJl
    MScwJQYDVQQKDB5DMlBBIFRlc3QgSW50ZXJtZWRpYXRlIFJvb3QgQ0ExGTAXBgNV
    BAsMEEZPUiBURVNUSU5HX09OTFkxGDAWBgNVBAMMD0ludGVybWVkaWF0ZSBDQTAe
    Fw0yMjA2MTAxODQ2NDBaFw0zMDA4MjYxODQ2NDBaMIGAMQswCQYDVQQGEwJVUzEL
    MAkGA1UECAwCQ0ExEjAQBgNVBAcMCVNvbWV3aGVyZTEfMB0GA1UECgwWQzJQQSBU
    ZXN0IFNpZ25pbmcgQ2VydDEZMBcGA1UECwwQRk9SIFRFU1RJTkdfT05MWTEUMBIG
    A1UEAwwLQzJQQSBTaWduZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQPaL6R
    kAkYkKU4+IryBSYxJM3h77sFiMrbvbI8fG7w2Bbl9otNG/cch3DAw5rGAPV7NWky
    l3QGuV/wt0MrAPDoo3gwdjAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsG
    AQUFBwMEMA4GA1UdDwEB/wQEAwIGwDAdBgNVHQ4EFgQUFznP0y83joiNOCedQkxT
    tAMyNcowHwYDVR0jBBgwFoAUDnyNcma/osnlAJTvtW6A4rYOL2swCgYIKoZIzj0E
    AwIDRwAwRAIgOY/2szXjslg/MyJFZ2y7OH8giPYTsvS7UPRP9GI9NgICIDQPMKrE
    LQUJEtipZ0TqvI/4mieoyRCeIiQtyuS0LACz
    -----END CERTIFICATE-----
    -----BEGIN CERTIFICATE-----
    MIICajCCAg+gAwIBAgIUfXDXHH+6GtA2QEBX2IvJ2YnGMnUwCgYIKoZIzj0EAwIw
    dzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRIwEAYDVQQHDAlTb21ld2hlcmUx
    GjAYBgNVBAoMEUMyUEEgVGVzdCBSb290IENBMRkwFwYDVQQLDBBGT1IgVEVTVElO
    R19PTkxZMRAwDgYDVQQDDAdSb290IENBMB4XDTIyMDYxMDE4NDY0MFoXDTMwMDgy
    NzE4NDY0MFowgYwxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTESMBAGA1UEBwwJ
    U29tZXdoZXJlMScwJQYDVQQKDB5DMlBBIFRlc3QgSW50ZXJtZWRpYXRlIFJvb3Qg
    Q0ExGTAXBgNVBAsMEEZPUiBURVNUSU5HX09OTFkxGDAWBgNVBAMMD0ludGVybWVk
    aWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHllI4O7a0EkpTYAWfPM
    D6Rnfk9iqhEmCQKMOR6J47Rvh2GGjUw4CS+aLT89ySukPTnzGsMQ4jK9d3V4Aq4Q
    LsOjYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQW
    BBQOfI1yZr+iyeUAlO+1boDitg4vazAfBgNVHSMEGDAWgBRembiG4Xgb2VcVWnUA
    UrYpDsuojDAKBggqhkjOPQQDAgNJADBGAiEAtdZ3+05CzFo90fWeZ4woeJcNQC4B
    84Ill3YeZVvR8ZECIQDVRdha1xEDKuNTAManY0zthSosfXcvLnZui1A/y/DYeg==
    -----END CERTIFICATE-----
    """
}

private enum IIRYC2PAProfileStore {
    private static let manifestStoreUUID = "6332706100110010800000AA00389B71"
    private static let manifestUUID = "63326D6100110010800000AA00389B71"
    private static let assertionStoreUUID = "6332617300110010800000AA00389B71"
    private static let claimUUID = "6332636C00110010800000AA00389B71"
    private static let signatureUUID = "6332637300110010800000AA00389B71"
    private static let jsonUUID = "6A736F6E00110010800000AA00389B71"
    private static let cborUUID = "63626F7200110010800000AA00389B71"

    static func build(
        carrier: IIRYCarrier,
        dataHash: Data,
        exclusions: [IIRYC2PAHashRange],
        signer: IIRYC2PADevSigner
    ) throws -> IIRYC2PAProfileBuild {
        let manifestLabel = "urn:c2pa:\(UUID().uuidString.lowercased())"
        let actionsData = try IIRYC2PACBOR.actions(softwareAgent: IIRYConstants.claimGenerator)
        let dataHashCBOR = try IIRYC2PACBOR.dataHash(
            hash: dataHash,
            exclusions: exclusions,
            name: "IIRY JPEG bytes excluding C2PA APP11 segments"
        )
        let dataHashBox = try JUMBF.assertion(label: "c2pa.hash.data", contentKind: .cbor, data: dataHashCBOR)
        let dataHashReference = try IIRYC2PAClaimAssertion(
            url: "self#jumbf=c2pa.assertions/c2pa.hash.data",
            alg: "sha256",
            hash: Hashing.sha256(JUMBF.superBoxPayload(dataHashBox))
        )
        let cawgIdentityCBOR = try IIRYC2PACBOR.cawgIdentityAssertion(
            proof: carrier.proof,
            referencedAssertions: [dataHashReference]
        )

        let assertionInputs: [(String, Data, IIRYJUMBFContentKind)] = [
            ("c2pa.hash.data", dataHashCBOR, .cbor),
            (IIRYConstants.cawgIdentityAssertionLabel, cawgIdentityCBOR, .cbor),
            ("c2pa.actions.v2", actionsData, .cbor)
        ]

        let assertionBoxes = try assertionInputs.map { label, data, kind in
            IIRYProfileAssertionBox(
                label: label,
                contentKind: kind,
                bytes: try JUMBF.assertion(label: label, contentKind: kind, data: data)
            )
        }
        let assertionReferences = try assertionBoxes.map { box in
            IIRYC2PAClaimAssertion(
                url: "self#jumbf=c2pa.assertions/\(box.label)",
                alg: "sha256",
                hash: Hashing.sha256(try JUMBF.superBoxPayload(box.bytes))
            )
        }
        let claimCBOR = try IIRYC2PACBOR.claimV2(
            claimGeneratorName: IIRYConstants.claimGenerator,
            title: carrier.suggestedFileName,
            instanceID: "xmp:iid:\(UUID().uuidString.lowercased())",
            signatureURL: "self#jumbf=/c2pa/\(manifestLabel)/c2pa.signature",
            createdAssertions: assertionReferences.filter { $0.label == "c2pa.hash.data" },
            gatheredAssertions: assertionReferences.filter { $0.label != "c2pa.hash.data" }
        )
        let signatureData = try signer.signDetachedCOSE(payload: claimCBOR)

        let assertionStore = JUMBF.superBox(
            label: "c2pa.assertions",
            uuidHex: assertionStoreUUID,
            children: assertionBoxes.map(\.bytes)
        )
        let claimBox = JUMBF.superBox(
            label: "c2pa.claim.v2",
            uuidHex: claimUUID,
            children: [JUMBF.content(type: "cbor", payload: claimCBOR)]
        )
        let signatureBox = JUMBF.superBox(
            label: "c2pa.signature",
            uuidHex: signatureUUID,
            children: [JUMBF.content(type: "cbor", payload: signatureData)]
        )
        let manifest = JUMBF.superBox(
            label: manifestLabel,
            uuidHex: manifestUUID,
            children: [assertionStore, claimBox, signatureBox]
        )
        let store = JUMBF.superBox(
            label: "c2pa",
            uuidHex: manifestStoreUUID,
            children: [manifest]
        )
        return IIRYC2PAProfileBuild(storeBytes: store, manifestLabel: manifestLabel)
    }

    static func read(fromJPEG imageData: Data) throws -> IIRYC2PAParsedProfile {
        let storeBytes = try IIRYJPEGC2PA.extractStoreBytes(fromJPEG: imageData)
        let root = try JUMBF.parseSingleSuperBox(storeBytes)
        guard root.label == "c2pa", root.uuidHex == manifestStoreUUID else {
            throw IIRYError.invalidCarrier("Embedded APP11 data is not a C2PA manifest store")
        }
        guard let manifest = root.children.first(where: { $0.label.hasPrefix("urn:c2pa:") }) else {
            throw IIRYError.invalidCarrier("C2PA store does not contain an IIRY manifest")
        }
        guard let assertionStore = manifest.children.first(where: { $0.label == "c2pa.assertions" }) else {
            throw IIRYError.invalidCarrier("IIRY manifest does not contain c2pa.assertions")
        }
        guard let claimBox = manifest.children.first(where: { $0.label == "c2pa.claim.v2" }),
              let claimCBOR = claimBox.firstContent(type: "cbor") else {
            throw IIRYError.invalidCarrier("IIRY manifest does not contain c2pa.claim.v2 CBOR")
        }
        guard let signatureBox = manifest.children.first(where: { $0.label == "c2pa.signature" }),
              let coseSignature = signatureBox.firstContent(type: "cbor") else {
            throw IIRYError.invalidCarrier("IIRY manifest does not contain a C2PA COSE signature")
        }

        var parsedAssertions: [String: IIRYC2PAParsedAssertion] = [:]
        for assertion in assertionStore.children {
            if let jsonData = assertion.firstContent(type: "json") {
                let jsonObject = try JSONSerialization.jsonObject(with: jsonData)
                parsedAssertions[assertion.label] = IIRYC2PAParsedAssertion(
                    label: assertion.label,
                    contentType: "application/json",
                    data: jsonData,
                    hash: Hashing.sha256(try JUMBF.superBoxPayload(assertion.rawBytes)),
                    jsonObject: jsonObject
                )
            } else if let cborData = assertion.firstContent(type: "cbor") {
                parsedAssertions[assertion.label] = IIRYC2PAParsedAssertion(
                    label: assertion.label,
                    contentType: "application/cbor",
                    data: cborData,
                    hash: Hashing.sha256(try JUMBF.superBoxPayload(assertion.rawBytes)),
                    jsonObject: nil
                )
            }
        }

        guard let dataHashAssertion = parsedAssertions["c2pa.hash.data"] else {
            throw IIRYError.invalidCarrier("c2pa.hash.data assertion is missing")
        }
        guard let cawgAssertion = parsedAssertions[IIRYConstants.cawgIdentityAssertionLabel] else {
            throw IIRYError.invalidCarrier("CAWG identity assertion is missing")
        }

        let cawgIdentity = try IIRYC2PACBOR.decodeCAWGIdentityAssertion(cawgAssertion.data)
        let dataHash = try IIRYC2PACBOR.decodeDataHash(dataHashAssertion.data)
        let claim = try IIRYC2PACBOR.decodeClaim(claimCBOR)
        let actions = try parsedAssertions["c2pa.actions.v2"].map {
            try IIRYC2PACBOR.decodeJSONObject($0.data)
        } as? [String: Any]

        return IIRYC2PAParsedProfile(
            manifestLabel: manifest.label,
            assertions: parsedAssertions,
            cawgIdentity: cawgIdentity,
            actions: actions,
            dataHash: dataHash,
            claim: claim,
            claimCBOR: claimCBOR,
            coseSignature: coseSignature
        )
    }
}

private struct IIRYProfileAssertionBox {
    var label: String
    var contentKind: IIRYJUMBFContentKind
    var bytes: Data
}

private enum IIRYJUMBFContentKind {
    case json
    case cbor
}

private enum JUMBF {
    static func assertion(label: String, contentKind: IIRYJUMBFContentKind, data: Data) throws -> Data {
        switch contentKind {
        case .json:
            return superBox(
                label: label,
                uuidHex: "6A736F6E00110010800000AA00389B71",
                children: [content(type: "json", payload: data)]
            )
        case .cbor:
            return superBox(
                label: label,
                uuidHex: "63626F7200110010800000AA00389B71",
                children: [content(type: "cbor", payload: data)]
            )
        }
    }

    static func superBox(label: String, uuidHex: String, children: [Data]) -> Data {
        var payload = Data()
        payload.append(descriptionBox(label: label, uuidHex: uuidHex))
        for child in children {
            payload.append(child)
        }
        return content(type: "jumb", payload: payload)
    }

    static func content(type: String, payload: Data) -> Data {
        var box = Data()
        box.appendUInt32BE(UInt32(payload.count + 8))
        box.append(Data(type.utf8.prefix(4)))
        box.append(payload)
        return box
    }

    static func parseSingleSuperBox(_ data: Data) throws -> IIRYJUMBFNode {
        var offset = 0
        let node = try parseSuperBox(data, offset: &offset, limit: data.count)
        guard offset == data.count else {
            throw IIRYError.invalidCarrier("Trailing data after JUMBF manifest store")
        }
        return node
    }

    static func superBoxPayload(_ data: Data) throws -> Data {
        var offset = 0
        let box = try parseBox(data, offset: &offset, limit: data.count)
        guard box.type == "jumb", offset == data.count else {
            throw IIRYError.invalidCarrier("Expected exactly one JUMBF superbox")
        }
        return Data(data[box.payloadRange])
    }

    private static func descriptionBox(label: String, uuidHex: String) -> Data {
        var payload = Data()
        payload.append(Data(hexString: uuidHex))
        payload.append(0x03)
        payload.append(Data(label.utf8))
        payload.append(0x00)
        return content(type: "jumd", payload: payload)
    }

    private static func parseSuperBox(_ data: Data, offset: inout Int, limit: Int) throws -> IIRYJUMBFNode {
        let box = try parseBox(data, offset: &offset, limit: limit)
        guard box.type == "jumb" else {
            throw IIRYError.invalidCarrier("Expected JUMBF superbox, found \(box.type)")
        }
        var childOffset = box.payloadRange.lowerBound
        let desc = try parseBox(data, offset: &childOffset, limit: box.payloadRange.upperBound)
        guard desc.type == "jumd" else {
            throw IIRYError.invalidCarrier("JUMBF superbox missing jumd description")
        }
        let description = try parseDescription(Data(data[desc.payloadRange]))
        var children: [IIRYJUMBFNode] = []
        while childOffset < box.payloadRange.upperBound {
            let peek = try parseBox(data, offset: &childOffset, limit: box.payloadRange.upperBound, advance: false)
            if peek.type == "jumb" {
                children.append(try parseSuperBox(data, offset: &childOffset, limit: box.payloadRange.upperBound))
            } else {
                let contentBox = try parseBox(data, offset: &childOffset, limit: box.payloadRange.upperBound)
                children.append(IIRYJUMBFNode(
                    type: contentBox.type,
                    label: contentBox.type,
                    uuidHex: "",
                    rawBytes: Data(data[contentBox.range]),
                    content: Data(data[contentBox.payloadRange]),
                    children: []
                ))
            }
        }
        return IIRYJUMBFNode(
            type: box.type,
            label: description.label,
            uuidHex: description.uuidHex,
            rawBytes: Data(data[box.range]),
            content: nil,
            children: children
        )
    }

    private static func parseBox(
        _ data: Data,
        offset: inout Int,
        limit: Int,
        advance: Bool = true
    ) throws -> IIRYBMFFBox {
        guard offset + 8 <= limit else {
            throw IIRYError.invalidCarrier("Truncated JUMBF box header")
        }
        let start = offset
        let size = Int(data.readUInt32BE(at: offset))
        let typeData = data[(offset + 4)..<(offset + 8)]
        guard let type = String(data: typeData, encoding: .ascii), type.count == 4 else {
            throw IIRYError.invalidCarrier("Invalid JUMBF box type")
        }
        guard size >= 8, start + size <= limit else {
            throw IIRYError.invalidCarrier("Invalid JUMBF box length for \(type)")
        }
        if advance {
            offset = start + size
        }
        return IIRYBMFFBox(
            type: type,
            range: start..<(start + size),
            payloadRange: (start + 8)..<(start + size)
        )
    }

    private static func parseDescription(_ payload: Data) throws -> (uuidHex: String, label: String) {
        guard payload.count >= 18 else {
            throw IIRYError.invalidCarrier("JUMBF description is too short")
        }
        let uuid = payload[0..<16].map { String(format: "%02X", $0) }.joined()
        let labelStart = 17
        guard let nul = payload[labelStart...].firstIndex(of: 0) else {
            throw IIRYError.invalidCarrier("JUMBF description label is not NUL-terminated")
        }
        let labelData = payload[labelStart..<nul]
        guard let label = String(data: labelData, encoding: .utf8) else {
            throw IIRYError.invalidCarrier("JUMBF description label is not UTF-8")
        }
        return (uuid, label)
    }
}

private struct IIRYBMFFBox {
    var type: String
    var range: Range<Int>
    var payloadRange: Range<Int>
}

private struct IIRYJUMBFNode {
    var type: String
    var label: String
    var uuidHex: String
    var rawBytes: Data
    var content: Data?
    var children: [IIRYJUMBFNode]

    func firstContent(type: String) -> Data? {
        children.first { $0.type == type }?.content
    }
}

enum IIRYJPEGC2PA {
    private static let app0: UInt8 = 0xE0
    private static let app11: UInt8 = 0xEB
    private static let sos: UInt8 = 0xDA
    private static let eoi: UInt8 = 0xD9
    private static let maxAPP11Payload = 64_000
    private static let c2paInstance = Data([0x02, 0x11])

    static func isJPEG(_ data: Data) -> Bool {
        data.count >= 2 && data[0] == 0xFF && data[1] == 0xD8
    }

    static func embed(storeBytes: Data, intoJPEG jpeg: Data) throws -> Data {
        let parsed = try parseHeaderSegments(jpeg)
        let c2paGroups = c2paGroupIdentifiers(in: parsed.segments, data: jpeg)
        let keptSegments = parsed.segments.filter { segment in
            !(segment.marker == app11 && c2paGroups.contains(segment.groupIdentifier(in: jpeg) ?? Data()))
        }
        let insertionIndex = keptSegments.lastIndex { $0.marker == app0 }.map { $0 + 1 } ?? 0
        let app11Segments = makeAPP11Segments(storeBytes: storeBytes)

        var output = Data([0xFF, 0xD8])
        for index in 0...keptSegments.count {
            if index == insertionIndex {
                for segment in app11Segments {
                    output.append(segment)
                }
            }
            if index < keptSegments.count {
                output.append(jpeg[keptSegments[index].range])
            }
        }
        output.append(jpeg[parsed.remainderRange])
        return output
    }

    static func extractStoreBytes(fromJPEG jpeg: Data) throws -> Data {
        let parsed = try parseHeaderSegments(jpeg)
        let groups = c2paGroupIdentifiers(in: parsed.segments, data: jpeg)
        guard groups.count == 1, let group = groups.first else {
            throw IIRYError.invalidCarrier(groups.isEmpty ? "JPEG does not contain C2PA APP11 data" : "JPEG contains multiple C2PA APP11 stores")
        }
        let groupSegments = parsed.segments
            .filter { $0.marker == app11 && $0.groupIdentifier(in: jpeg) == group }
            .sorted { lhs, rhs in
                (lhs.sequenceNumber(in: jpeg) ?? 0) < (rhs.sequenceNumber(in: jpeg) ?? 0)
            }

        guard !groupSegments.isEmpty else {
            throw IIRYError.invalidCarrier("C2PA APP11 segment set is empty")
        }

        var store = Data()
        for (index, segment) in groupSegments.enumerated() {
            let content = jpeg[segment.contentRange]
            guard content.count >= (index == 0 ? 8 : 16) else {
                throw IIRYError.invalidCarrier("Truncated C2PA APP11 segment")
            }
            if index == 0 {
                store.append(content.dropFirst(8))
            } else {
                store.append(content.dropFirst(16))
            }
        }
        return store
    }

    static func stripC2PASegments(fromJPEG jpeg: Data) throws -> Data {
        let parsed = try parseHeaderSegments(jpeg)
        let c2paGroups = c2paGroupIdentifiers(in: parsed.segments, data: jpeg)
        var output = Data([0xFF, 0xD8])
        for segment in parsed.segments {
            if segment.marker == app11, c2paGroups.contains(segment.groupIdentifier(in: jpeg) ?? Data()) {
                continue
            }
            output.append(jpeg[segment.range])
        }
        output.append(jpeg[parsed.remainderRange])
        return output
    }

    static func c2paSegmentRanges(inJPEG jpeg: Data) throws -> [IIRYC2PAHashRange] {
        let parsed = try parseHeaderSegments(jpeg)
        let c2paGroups = c2paGroupIdentifiers(in: parsed.segments, data: jpeg)
        return parsed.segments.compactMap { segment in
            guard segment.marker == app11,
                  c2paGroups.contains(segment.groupIdentifier(in: jpeg) ?? Data()) else {
                return nil
            }
            return IIRYC2PAHashRange(
                start: UInt64(segment.range.lowerBound),
                length: UInt64(segment.range.count)
            )
        }
    }

    static func bytes(_ data: Data, excluding ranges: [IIRYC2PAHashRange]) -> Data {
        let sorted = ranges.sorted { $0.start < $1.start }
        var output = Data()
        var offset = 0
        for range in sorted {
            let start = min(Int(range.start), data.count)
            let end = min(start + Int(range.length), data.count)
            if offset < start {
                output.append(data[offset..<start])
            }
            offset = max(offset, end)
        }
        if offset < data.count {
            output.append(data[offset..<data.count])
        }
        return output
    }

    private static func makeAPP11Segments(storeBytes: Data) -> [Data] {
        let chunks = Array(storeBytes.chunks(ofCount: maxAPP11Payload))
        return chunks.enumerated().map { index, chunk in
            var payload = Data([0x4A, 0x50])
            payload.append(c2paInstance)
            payload.appendUInt32BE(UInt32(index + 1))
            if index > 0 {
                payload.append(storeBytes[0..<8])
            }
            payload.append(chunk)

            var segment = Data([0xFF, app11])
            segment.appendUInt16BE(UInt16(payload.count + 2))
            segment.append(payload)
            return segment
        }
    }

    private static func c2paGroupIdentifiers(in segments: [IIRYJPEGSegment], data: Data) -> Set<Data> {
        var groups = Set<Data>()
        for segment in segments where segment.marker == app11 {
            guard let group = segment.groupIdentifier(in: data),
                  segment.sequenceNumber(in: data) == 1 else {
                continue
            }
            let content = data[segment.contentRange]
            if content.count > 28,
               content[(content.startIndex + 24)..<(content.startIndex + 28)] == Data([0x63, 0x32, 0x70, 0x61]) {
                groups.insert(group)
            }
        }
        return groups
    }

    private static func parseHeaderSegments(_ data: Data) throws -> IIRYJPEGHeaderParse {
        guard isJPEG(data) else {
            throw IIRYError.invalidCarrier("Not a JPEG file")
        }
        var offset = 2
        var segments: [IIRYJPEGSegment] = []
        while offset < data.count {
            guard data[offset] == 0xFF else {
                return IIRYJPEGHeaderParse(segments: segments, remainderRange: offset..<data.count)
            }
            let markerStart = offset
            offset += 1
            while offset < data.count, data[offset] == 0xFF {
                offset += 1
            }
            guard offset < data.count else {
                throw IIRYError.invalidCarrier("Truncated JPEG marker")
            }
            let marker = data[offset]
            offset += 1
            if marker == eoi {
                return IIRYJPEGHeaderParse(segments: segments, remainderRange: markerStart..<data.count)
            }
            guard offset + 2 <= data.count else {
                throw IIRYError.invalidCarrier("Truncated JPEG segment length")
            }
            let length = Int(data.readUInt16BE(at: offset))
            guard length >= 2, offset + length <= data.count else {
                throw IIRYError.invalidCarrier("Invalid JPEG segment length")
            }
            let contentStart = offset + 2
            let segmentEnd = offset + length
            segments.append(IIRYJPEGSegment(
                marker: marker,
                range: markerStart..<segmentEnd,
                contentRange: contentStart..<segmentEnd
            ))
            offset = segmentEnd
            if marker == sos {
                return IIRYJPEGHeaderParse(segments: segments, remainderRange: offset..<data.count)
            }
        }
        return IIRYJPEGHeaderParse(segments: segments, remainderRange: data.count..<data.count)
    }
}

private struct IIRYJPEGHeaderParse {
    var segments: [IIRYJPEGSegment]
    var remainderRange: Range<Int>
}

private struct IIRYJPEGSegment {
    var marker: UInt8
    var range: Range<Int>
    var contentRange: Range<Int>

    func groupIdentifier(in data: Data) -> Data? {
        let content = data[contentRange]
        guard content.count >= 4,
              content[content.startIndex] == 0x4A,
              content[content.startIndex + 1] == 0x50 else {
            return nil
        }
        return Data(content[(content.startIndex + 2)..<(content.startIndex + 4)])
    }

    func sequenceNumber(in data: Data) -> UInt32? {
        let content = data[contentRange]
        guard content.count >= 8 else {
            return nil
        }
        return content.readUInt32BE(at: content.startIndex + 4)
    }
}

private enum IIRYC2PACBOR {
    static func actions(softwareAgent: String) throws -> Data {
        try DeterministicCBOR.encode(.map([
            (.string("actions"), .array([
                .map([
                    (.string("action"), .string("c2pa.created")),
                    (.string("softwareAgent"), .string(softwareAgent))
                ])
            ]))
        ]))
    }

    static func dataHash(hash: Data, exclusions: [IIRYC2PAHashRange], name: String) throws -> Data {
        try DeterministicCBOR.encode(.map([
            (.string("alg"), .string("sha256")),
            (.string("exclusions"), .array(exclusions.map { range in
                .map([
                    (.string("length"), .unsigned(range.length)),
                    (.string("start"), .unsigned(range.start))
                ])
            })),
            (.string("hash"), .bytes(hash)),
            (.string("name"), .string(name)),
            (.string("pad"), .bytes(Data()))
        ]))
    }

    static func claimV2(
        claimGeneratorName: String,
        title: String,
        instanceID: String,
        signatureURL: String,
        createdAssertions: [IIRYC2PAClaimAssertion],
        gatheredAssertions: [IIRYC2PAClaimAssertion]
    ) throws -> Data {
        var pairs: [(CBORValue, CBORValue)] = [
            (.string("alg"), .string("sha256")),
            (.string("claim_generator_info"), .map([
                (.string("name"), .string(claimGeneratorName)),
                (.string("version"), .string("0.1"))
            ])),
            (.string("created_assertions"), .array(createdAssertions.map(claimReference))),
            (.string("dc:title"), .string(title)),
            (.string("instanceID"), .string(instanceID)),
            (.string("signature"), .string(signatureURL))
        ]
        if !gatheredAssertions.isEmpty {
            pairs.append((.string("gathered_assertions"), .array(gatheredAssertions.map(claimReference))))
        }
        return try DeterministicCBOR.encode(.map(pairs))
    }

    static func cawgIdentityAssertion(
        proof: IIRYProofBundle,
        referencedAssertions: [IIRYC2PAClaimAssertion]
    ) throws -> Data {
        let evidence = try openID4VPEvidence(proof: proof)
        let signerPayload: CBORValue = .map([
            (.string("referenced_assertions"), .array(referencedAssertions.map(cawgReference))),
            (.string("sig_type"), .string(IIRYConstants.cawgOpenID4VPSigType))
        ])
        return try DeterministicCBOR.encode(.map([
            (.string("pad1"), .bytes(Data())),
            (.string("signature"), .bytes(evidence)),
            (.string("signer_payload"), signerPayload)
        ]))
    }

    static func coseSignature(protectedHeader: Data, signature: Data) throws -> Data {
        try DeterministicCBOR.encode(.tagged(18, .array([
            .bytes(protectedHeader),
            .map([]),
            .null,
            .bytes(signature)
        ])))
    }

    static func coseSignatureInput(protectedHeader: Data, payload: Data) throws -> Data {
        try DeterministicCBOR.encode(.array([
            .string("Signature1"),
            .bytes(protectedHeader),
            .bytes(Data()),
            .bytes(payload)
        ]))
    }

    static func coseProtectedHeader(certificateChain: [Data]) throws -> Data {
        let chainValue: CBORValue
        if certificateChain.count == 1, let cert = certificateChain.first {
            chainValue = .bytes(cert)
        } else {
            chainValue = .array(certificateChain.map { .bytes($0) })
        }
        return try DeterministicCBOR.encode(.map([
            (.unsigned(1), .negative(-7)),
            (.unsigned(33), chainValue)
        ]))
    }

    static func decodeCOSESign1(_ data: Data) throws -> (protectedHeader: Data, signature: Data) {
        guard case .tagged(18, .array(let values)) = try DeterministicCBOR.decode(data),
              values.count == 4,
              case .bytes(let protectedHeader) = values[0],
              case .bytes(let signature) = values[3] else {
            throw IIRYError.invalidCBOR("C2PA signature is not COSE_Sign1")
        }
        return (protectedHeader, signature)
    }

    static func decodeCAWGIdentityAssertion(_ data: Data) throws -> IIRYCAWGIdentityAssertion {
        guard case .map(let pairs) = try DeterministicCBOR.decode(data) else {
            throw IIRYError.invalidCBOR("CAWG identity assertion is not a CBOR map")
        }
        let assertion = CBORMap(pairs)
        guard case .map(let signerPayloadPairs) = assertion.values["signer_payload"] else {
            throw IIRYError.invalidCBOR("CAWG identity assertion missing signer_payload")
        }
        let signerPayload = CBORMap(signerPayloadPairs)
        let sigType = try signerPayload.string("sig_type")
        guard sigType == IIRYConstants.cawgOpenID4VPSigType else {
            if sigType == IIRYConstants.legacyCAWGOpenID4VPSigTypeV1 {
                throw IIRYError.invalidCarrier("Unsupported CAWG OpenID4VP holder-binding profile v1: regenerate the asset with \(IIRYConstants.cawgOpenID4VPSigType)")
            }
            throw IIRYError.invalidCarrier("Unsupported CAWG identity sig_type \(sigType); expected \(IIRYConstants.cawgOpenID4VPSigType)")
        }
        let references = try signerPayload.array("referenced_assertions").map(decodeReference)
        return IIRYCAWGIdentityAssertion(
            sigType: sigType,
            referencedAssertions: references,
            signature: try assertion.bytes("signature")
        )
    }

    private static func claimReference(_ assertion: IIRYC2PAClaimAssertion) -> CBORValue {
        .map([
            (.string("hash"), .bytes(assertion.hash)),
            (.string("url"), .string(assertion.url))
        ])
    }

    private static func cawgReference(_ assertion: IIRYC2PAClaimAssertion) -> CBORValue {
        .map([
            (.string("alg"), .string(assertion.alg)),
            (.string("hash"), .bytes(assertion.hash)),
            (.string("url"), .string(assertion.url))
        ])
    }

    private static func decodeReference(_ value: CBORValue) throws -> IIRYC2PAClaimAssertion {
        guard case .map(let pairs) = value else {
            throw IIRYError.invalidCBOR("CAWG referenced assertion is not a map")
        }
        let reference = CBORMap(pairs)
        return IIRYC2PAClaimAssertion(
            url: try reference.string("url"),
            alg: (try? reference.string("alg")) ?? "sha256",
            hash: try reference.bytes("hash")
        )
    }

    private static func openID4VPEvidence(proof: IIRYProofBundle) throws -> Data {
        guard let compactPresentation = proof.openID4VP.compactPresentation,
              !compactPresentation.isEmpty else {
            throw IIRYError.invalidCarrier("CAWG identity evidence requires a vp_token presentation")
        }
        guard let responseJSONB64URL = proof.openID4VP.responseJSONB64URL,
              !responseJSONB64URL.isEmpty else {
            throw IIRYError.invalidCarrier("CAWG identity evidence requires the decoded OpenID4VP response JSON")
        }
        let responseData = try Base64URL.decode(responseJSONB64URL)
        let responsePresentation = try PresentationExtractor.firstPresentation(fromDecodedResponseJSON: responseData)
        guard responsePresentation == compactPresentation else {
            throw IIRYError.invalidCarrier("CAWG identity vp_token does not match the OpenID4VP response JSON")
        }
        guard let vpToken = try PresentationExtractor.vpTokenObject(fromDecodedResponseJSON: responseData) else {
            throw IIRYError.invalidCarrier("OpenID4VP response JSON did not contain a vp_token object")
        }
        return try JSONCoding.objectData(["vp_token": vpToken])
    }

    static func decodeDataHash(_ data: Data) throws -> IIRYC2PADataHash {
        guard case .map(let pairs) = try DeterministicCBOR.decode(data) else {
            throw IIRYError.invalidCBOR("c2pa.hash.data is not a CBOR map")
        }
        let map = CBORMap(pairs)
        let exclusionValues = try map.array("exclusions")
        let exclusions = try exclusionValues.map { value in
            guard case .map(let rangePairs) = value else {
                throw IIRYError.invalidCBOR("Data hash exclusion is not a map")
            }
            let range = CBORMap(rangePairs)
            return IIRYC2PAHashRange(
                start: try range.unsigned("start"),
                length: try range.unsigned("length")
            )
        }
        return IIRYC2PADataHash(
            exclusions: exclusions,
            name: try map.string("name"),
            alg: try map.string("alg"),
            hash: try map.bytes("hash")
        )
    }

    static func decodeClaim(_ data: Data) throws -> IIRYC2PAClaim {
        guard case .map(let pairs) = try DeterministicCBOR.decode(data) else {
            throw IIRYError.invalidCBOR("c2pa.claim is not a CBOR map")
        }
        let map = CBORMap(pairs)
        let created = (try? map.array("created_assertions")) ?? []
        let gathered = (try? map.array("gathered_assertions")) ?? []
        let assertions = try (created + gathered).map { value -> IIRYC2PAClaimAssertion in
            guard case .map(let assertionPairs) = value else {
                throw IIRYError.invalidCBOR("Claim assertion reference is not a map")
            }
            let assertion = CBORMap(assertionPairs)
            return IIRYC2PAClaimAssertion(
                url: try assertion.string("url"),
                alg: (try? assertion.string("alg")) ?? "sha256",
                hash: try assertion.bytes("hash")
            )
        }
        return IIRYC2PAClaim(
            signatureURL: try map.string("signature"),
            assertions: assertions
        )
    }

    static func decodeJSONObject(_ data: Data) throws -> Any {
        try jsonValue(DeterministicCBOR.decode(data))
    }

    private static func jsonValue(_ value: CBORValue) throws -> Any {
        switch value {
        case .unsigned(let unsigned):
            return Int(unsigned)
        case .negative(let negative):
            return Int(negative)
        case .bytes(let data):
            return Base64URL.encode(data)
        case .string(let string):
            return string
        case .array(let values):
            return try values.map(jsonValue)
        case .map(let pairs):
            var object: [String: Any] = [:]
            for (key, value) in pairs {
                guard case .string(let stringKey) = key else {
                    continue
                }
                object[stringKey] = try jsonValue(value)
            }
            return object
        case .tagged(let tag, let taggedValue):
            return [
                "tag": Int(tag),
                "value": try jsonValue(taggedValue)
            ]
        case .null:
            return NSNull()
        }
    }
}

private struct CBORMap {
    var values: [String: CBORValue] = [:]

    init(_ pairs: [(CBORValue, CBORValue)]) {
        for (key, value) in pairs {
            if case .string(let string) = key {
                values[string] = value
            }
        }
    }

    func string(_ key: String) throws -> String {
        guard case .string(let value) = values[key] else {
            throw IIRYError.invalidCBOR("Missing CBOR text field \(key)")
        }
        return value
    }

    func bytes(_ key: String) throws -> Data {
        guard case .bytes(let value) = values[key] else {
            throw IIRYError.invalidCBOR("Missing CBOR bytes field \(key)")
        }
        return value
    }

    func unsigned(_ key: String) throws -> UInt64 {
        guard case .unsigned(let value) = values[key] else {
            throw IIRYError.invalidCBOR("Missing CBOR unsigned field \(key)")
        }
        return value
    }

    func array(_ key: String) throws -> [CBORValue] {
        guard case .array(let value) = values[key] else {
            throw IIRYError.invalidCBOR("Missing CBOR array field \(key)")
        }
        return value
    }
}

private enum IIRYC2PAProfileReport {
    static func data(
        profile: IIRYC2PAParsedProfile,
        validation: IIRYC2PAProfileValidation,
        pretty: Bool
    ) throws -> Data {
        var assertionStore: [String: Any] = [:]
        if let identity = profile.cawgIdentity {
            assertionStore[IIRYConstants.cawgIdentityAssertionLabel] = [
                "signer_payload": [
                    "sig_type": identity.sigType,
                    "referenced_assertions": identity.referencedAssertions.map {
                        [
                            "url": $0.url,
                            "alg": $0.alg,
                            "hash": Base64URL.encode($0.hash)
                        ]
                    }
                ],
                "signature_b64u": Base64URL.encode(identity.signature)
            ]
        }
        if let actions = profile.actions {
            assertionStore["c2pa.actions.v2"] = actions
        }
        assertionStore["c2pa.hash.data"] = [
            "alg": profile.dataHash.alg,
            "name": profile.dataHash.name,
            "hash": Base64URL.encode(profile.dataHash.hash),
            "exclusions": profile.dataHash.exclusions.map {
                ["start": Int($0.start), "length": Int($0.length)]
            }
        ]

        let successes = validationSuccesses(validation)
        let failures = validationFailures(validation)
        let report: [String: Any] = [
            "active_manifest": profile.manifestLabel,
            "validation_state": failures.isEmpty ? "valid" : "invalid",
            "manifests": [
                profile.manifestLabel: [
                    "claim": [
                        "signature": profile.claim.signatureURL,
                        "assertions": profile.claim.assertions.map {
                            [
                                "url": $0.url,
                                "alg": $0.alg,
                                "hash": Base64URL.encode($0.hash)
                            ]
                        }
                    ],
                    "assertion_store": assertionStore
                ]
            ],
            "validation_results": [
                "activeManifest": [
                    "success": successes,
                    "failure": failures
                ]
            ]
        ]
        return try JSONCoding.objectData(report, pretty: pretty)
    }

    private static func validationSuccesses(_ validation: IIRYC2PAProfileValidation) -> [[String: String]] {
        var results: [[String: String]] = []
        if validation.dataHashMatches {
            results.append(["code": "assertion.dataHash.match", "url": "self#jumbf=c2pa.assertions/c2pa.hash.data"])
        }
        if validation.profileSignatureValid {
            results.append(["code": "claimSignature.validated", "url": "self#jumbf=c2pa.signature"])
        }
        if validation.claimAssertionHashesMatch {
            results.append(["code": "iiry.claimAssertionHashes.match", "url": "self#jumbf=c2pa.claim.v2"])
        }
        return results
    }

    private static func validationFailures(_ validation: IIRYC2PAProfileValidation) -> [[String: String]] {
        var results: [[String: String]] = []
        if !validation.dataHashMatches {
            results.append(["code": "assertion.dataHash.mismatch", "url": "self#jumbf=c2pa.assertions/c2pa.hash.data"])
        }
        if !validation.profileSignatureValid {
            results.append(["code": "claimSignature.mismatch", "url": "self#jumbf=c2pa.signature"])
        }
        if !validation.claimAssertionHashesMatch {
            results.append(["code": "iiry.claimAssertionHashes.mismatch", "url": "self#jumbf=c2pa.claim.v2"])
        }
        return results
    }
}

private extension Data {
    init(hexString: String) {
        var bytes: [UInt8] = []
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let next = hexString.index(index, offsetBy: 2)
            let byte = UInt8(hexString[index..<next], radix: 16) ?? 0
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }

    mutating func appendUInt16BE(_ value: UInt16) {
        append(UInt8((value >> 8) & 0xFF))
        append(UInt8(value & 0xFF))
    }

    mutating func appendUInt32BE(_ value: UInt32) {
        append(UInt8((value >> 24) & 0xFF))
        append(UInt8((value >> 16) & 0xFF))
        append(UInt8((value >> 8) & 0xFF))
        append(UInt8(value & 0xFF))
    }

    func readUInt16BE(at offset: Int) -> UInt16 {
        (UInt16(self[offset]) << 8) | UInt16(self[offset + 1])
    }

    func readUInt32BE(at offset: Int) -> UInt32 {
        (UInt32(self[offset]) << 24) |
        (UInt32(self[offset + 1]) << 16) |
        (UInt32(self[offset + 2]) << 8) |
        UInt32(self[offset + 3])
    }

    func chunks(ofCount size: Int) -> [Data] {
        var chunks: [Data] = []
        var offset = 0
        while offset < count {
            let end = Swift.min(offset + size, count)
            chunks.append(Data(self[offset..<end]))
            offset = end
        }
        return chunks
    }
}
