import Foundation

public struct IIRYPreparedProof {
    public var nonce: String
    public var proof: IIRYProofBundle
    public var draft: IIRYCommitmentDraft

    public init(nonce: String, proof: IIRYProofBundle, draft: IIRYCommitmentDraft) {
        self.nonce = nonce
        self.proof = proof
        self.draft = draft
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
        let draft = IIRYCommitmentDraft(
            suggestedFileName: fileName,
            imageB64URL: Base64URL.encode(imageData),
            proof: proof
        )
        return IIRYPreparedProof(nonce: nonceResult.nonce, proof: proof, draft: draft)
    }

    public static func attachPresentation(
        draft: IIRYCommitmentDraft,
        decodedResponseJSON: Data,
        walletVerification: WalletVerificationSummary? = nil
    ) throws -> IIRYCommitmentDraft {
        var updated = draft
        guard let presentation = try PresentationExtractor.firstPresentation(fromDecodedResponseJSON: decodedResponseJSON) else {
            throw IIRYError.invalidCarrier("OpenID4VP response did not contain a vp_token presentation")
        }
        var state: String?
        if let object = try JSONSerialization.jsonObject(with: decodedResponseJSON) as? [String: Any] {
            state = object["state"] as? String
        }
        updated.proof.openID4VP.responseJSONB64URL = Base64URL.encode(decodedResponseJSON)
        updated.proof.openID4VP.compactPresentation = presentation
        updated.proof.openID4VP.state = state
        updated.proof.openID4VP.walletVerification = walletVerification
        updated.proof.disclosedClaims = PresentationExtractor.disclosedClaims(fromPresentation: presentation)
        return updated
    }
}
