import Foundation

public struct IIRYAssetBinding: Codable, Equatable {
    public var mediaType: String
    public var byteLength: Int
    public var sha256B64URL: String
    public var bindingMaterialSHA256B64URL: String

    public init(mediaType: String, byteLength: Int, sha256B64URL: String, bindingMaterialSHA256B64URL: String) {
        self.mediaType = mediaType
        self.byteLength = byteLength
        self.sha256B64URL = sha256B64URL
        self.bindingMaterialSHA256B64URL = bindingMaterialSHA256B64URL
    }
}

public struct IIRYAssetBindingMaterial: Codable, Equatable {
    public var type: String
    public var version: Int
    public var mediaType: String
    public var byteLength: Int
    public var assetSHA256B64URL: String
    public var scope: String

    public init(mediaType: String, byteLength: Int, assetSHA256B64URL: String) {
        self.type = "io.github.ndurner.iiry.asset-binding-material.v1"
        self.version = 1
        self.mediaType = mediaType
        self.byteLength = byteLength
        self.assetSHA256B64URL = assetSHA256B64URL
        self.scope = "pre-c2pa-jpeg-bytes"
    }
}

public struct IIRYNoncePayload: Codable, Equatable {
    public var type: String
    public var version: Int
    public var randomNonceB64URL: String
    public var assetBindingSHA256B64URL: String
    public var requestContextSHA256B64URL: String

    public init(
        type: String = IIRYConstants.nonceType,
        version: Int = 1,
        randomNonceB64URL: String,
        assetBindingSHA256B64URL: String,
        requestContextSHA256B64URL: String
    ) {
        self.type = type
        self.version = version
        self.randomNonceB64URL = randomNonceB64URL
        self.assetBindingSHA256B64URL = assetBindingSHA256B64URL
        self.requestContextSHA256B64URL = requestContextSHA256B64URL
    }
}

public struct IIRYReferencedAssertion: Codable, Equatable {
    public var url: String
    public var hashB64URL: String

    public init(url: String, hashB64URL: String) {
        self.url = url
        self.hashB64URL = hashB64URL
    }
}

public struct IIRYCAWGAssertion: Codable, Equatable {
    public var sigType: String
    public var referencedAssertions: [IIRYReferencedAssertion]

    public init(
        sigType: String = IIRYConstants.cawgOpenID4VPSigType,
        referencedAssertions: [IIRYReferencedAssertion]
    ) {
        self.sigType = sigType
        self.referencedAssertions = referencedAssertions
    }
}

public struct WalletVerificationSummary: Codable, Equatable {
    public var issuerSignature: Bool?
    public var issuerCertificateTrusted: Bool?
    public var disclosuresMatchIssuerCommitments: Bool?
    public var holderSignature: Bool?
    public var nonceMatchesChallenge: Bool?
    public var audienceIsThisVerifier: Bool?
    public var sdHashBindsPresentation: Bool?
    public var error: String?

    public init(
        issuerSignature: Bool? = nil,
        issuerCertificateTrusted: Bool? = nil,
        disclosuresMatchIssuerCommitments: Bool? = nil,
        holderSignature: Bool? = nil,
        nonceMatchesChallenge: Bool? = nil,
        audienceIsThisVerifier: Bool? = nil,
        sdHashBindsPresentation: Bool? = nil,
        error: String? = nil
    ) {
        self.issuerSignature = issuerSignature
        self.issuerCertificateTrusted = issuerCertificateTrusted
        self.disclosuresMatchIssuerCommitments = disclosuresMatchIssuerCommitments
        self.holderSignature = holderSignature
        self.nonceMatchesChallenge = nonceMatchesChallenge
        self.audienceIsThisVerifier = audienceIsThisVerifier
        self.sdHashBindsPresentation = sdHashBindsPresentation
        self.error = error
    }

    public var allKnownChecksPassed: Bool {
        let checks = [
            issuerSignature,
            issuerCertificateTrusted,
            disclosuresMatchIssuerCommitments,
            holderSignature,
            nonceMatchesChallenge,
            audienceIsThisVerifier,
            sdHashBindsPresentation
        ]
        return checks.allSatisfy { $0 == true } && error == nil
    }
}

public struct OpenID4VPEvidence: Codable, Equatable {
    public var nonce: String
    public var state: String?
    public var responseJSONB64URL: String?
    public var compactPresentation: String?
    public var walletVerification: WalletVerificationSummary?

    public init(
        nonce: String,
        state: String? = nil,
        responseJSONB64URL: String? = nil,
        compactPresentation: String? = nil,
        walletVerification: WalletVerificationSummary? = nil
    ) {
        self.nonce = nonce
        self.state = state
        self.responseJSONB64URL = responseJSONB64URL
        self.compactPresentation = compactPresentation
        self.walletVerification = walletVerification
    }
}

public struct IIRYProofBundle: Codable, Equatable {
    public var type: String
    public var version: Int
    public var createdAt: String
    public var requestText: String?
    public var asset: IIRYAssetBinding
    public var noncePayload: IIRYNoncePayload
    public var cawg: IIRYCAWGAssertion
    public var openID4VP: OpenID4VPEvidence
    public var disclosedClaims: [String: String]

    public init(
        type: String = IIRYConstants.proofBundleType,
        version: Int = 1,
        createdAt: String,
        requestText: String? = nil,
        asset: IIRYAssetBinding,
        noncePayload: IIRYNoncePayload,
        cawg: IIRYCAWGAssertion,
        openID4VP: OpenID4VPEvidence,
        disclosedClaims: [String: String] = [:]
    ) {
        self.type = type
        self.version = version
        self.createdAt = createdAt
        self.requestText = requestText
        self.asset = asset
        self.noncePayload = noncePayload
        self.cawg = cawg
        self.openID4VP = openID4VP
        self.disclosedClaims = disclosedClaims
    }
}

public struct IIRYCarrier: Codable, Equatable {
    public var type: String
    public var version: Int
    public var mediaType: String
    public var suggestedFileName: String
    public var imageB64URL: String
    public var proof: IIRYProofBundle

    public init(
        type: String = IIRYConstants.carrierType,
        version: Int = 1,
        mediaType: String = IIRYConstants.jpegMediaType,
        suggestedFileName: String,
        imageB64URL: String,
        proof: IIRYProofBundle
    ) {
        self.type = type
        self.version = version
        self.mediaType = mediaType
        self.suggestedFileName = suggestedFileName
        self.imageB64URL = imageB64URL
        self.proof = proof
    }
}

public struct IIRYVerificationCheck: Codable, Equatable, Identifiable {
    public var id: String
    public var label: String
    public var passed: Bool
    public var detail: String?

    public init(id: String, label: String, passed: Bool, detail: String? = nil) {
        self.id = id
        self.label = label
        self.passed = passed
        self.detail = detail
    }
}

public struct IIRYVerificationReport: Codable, Equatable {
    public var overallPassed: Bool
    public var checks: [IIRYVerificationCheck]

    public init(checks: [IIRYVerificationCheck]) {
        self.checks = checks
        self.overallPassed = checks.allSatisfy(\.passed)
    }
}
