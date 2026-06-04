import Foundation

public struct IIRYPreparedProof {
    public var nonce: String
    public var proof: IIRYProofBundle
    public var carrier: IIRYCarrier

    public init(nonce: String, proof: IIRYProofBundle, carrier: IIRYCarrier) {
        self.nonce = nonce
        self.proof = proof
        self.carrier = carrier
    }
}

public enum IIRYProofBuilder {
    public static func prepare(
        imageData: Data,
        now: Date = Date(),
        randomNonce: Data? = nil
    ) throws -> IIRYPreparedProof {
        let assetSHA256 = Hashing.sha256(imageData)
        let material = IIRYAssetBindingMaterial(
            mediaType: IIRYConstants.jpegMediaType,
            byteLength: imageData.count,
            assetSHA256B64URL: Base64URL.encode(assetSHA256)
        )
        let materialData = try JSONCoding.canonicalData(material)
        let materialDigest = Hashing.sha256(materialData)
        let nonceResult = try IIRYNonce.create(
            assetBindingSHA256: materialDigest,
            randomNonce: randomNonce
        )

        let asset = IIRYAssetBinding(
            mediaType: IIRYConstants.jpegMediaType,
            byteLength: imageData.count,
            sha256B64URL: Base64URL.encode(assetSHA256),
            bindingMaterialSHA256B64URL: Base64URL.encode(materialDigest)
        )
        let reference = IIRYReferencedAssertion(
            url: IIRYConstants.hardBindingReferenceURL,
            hashB64URL: asset.bindingMaterialSHA256B64URL
        )
        let proof = IIRYProofBundle(
            createdAt: IIRYDateFormatting.iso8601String(from: now),
            asset: asset,
            noncePayload: nonceResult.payload,
            cawg: IIRYCAWGAssertion(referencedAssertions: [reference]),
            openID4VP: OpenID4VPEvidence(nonce: nonceResult.nonce),
            disclosedClaims: [:]
        )
        let fileName = IIRYFileNames.proofFileName(date: now, noncePayload: nonceResult.payload)
        let carrier = IIRYCarrier(
            suggestedFileName: fileName,
            imageB64URL: Base64URL.encode(imageData),
            proof: proof
        )
        return IIRYPreparedProof(nonce: nonceResult.nonce, proof: proof, carrier: carrier)
    }

    public static func attachPresentation(
        carrier: IIRYCarrier,
        decodedResponseJSON: Data,
        walletVerification: WalletVerificationSummary? = nil
    ) throws -> IIRYCarrier {
        var updated = carrier
        let presentation = try PresentationExtractor.firstPresentation(fromDecodedResponseJSON: decodedResponseJSON)
        var state: String?
        if let object = try JSONSerialization.jsonObject(with: decodedResponseJSON) as? [String: Any] {
            state = object["state"] as? String
        }
        updated.proof.openID4VP.responseJSONB64URL = Base64URL.encode(decodedResponseJSON)
        updated.proof.openID4VP.compactPresentation = presentation
        updated.proof.openID4VP.state = state
        updated.proof.openID4VP.walletVerification = walletVerification
        if let presentation {
            updated.proof.disclosedClaims = PresentationExtractor.disclosedClaims(fromPresentation: presentation)
        }
        return updated
    }

    public static func carrierData(_ carrier: IIRYCarrier, pretty: Bool = true) throws -> Data {
        try JSONCoding.encoder(pretty: pretty).encode(carrier)
    }

    public static func decodeCarrier(_ data: Data) throws -> IIRYCarrier {
        let carrier = try JSONCoding.decoder().decode(IIRYCarrier.self, from: data)
        guard carrier.type == IIRYConstants.carrierType else {
            throw IIRYError.invalidCarrier("Unexpected carrier type \(carrier.type)")
        }
        return carrier
    }
}
