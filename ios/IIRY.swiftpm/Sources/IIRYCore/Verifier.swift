import Foundation

public enum IIRYVerifier {
    public static func verifyCarrier(_ carrier: IIRYCarrier) throws -> IIRYVerificationReport {
        let imageData = try Base64URL.decode(carrier.imageB64URL)
        return try verify(proof: carrier.proof, imageData: imageData)
    }

    public static func verify(proof: IIRYProofBundle, imageData: Data) throws -> IIRYVerificationReport {
        var checks: [IIRYVerificationCheck] = []

        let assetSHA = Hashing.sha256(imageData)
        let material = IIRYAssetBindingMaterial(
            mediaType: proof.asset.mediaType,
            byteLength: imageData.count,
            assetSHA256B64URL: Base64URL.encode(assetSHA)
        )
        let materialDigest = Hashing.sha256(try JSONCoding.canonicalData(material))
        let decodedNonce = try? IIRYNonce.decode(proof.openID4VP.nonce)

        checks.append(.init(
            id: "carrier_type",
            label: "IIRY carrier type",
            passed: proof.type == IIRYConstants.proofBundleType,
            detail: proof.type
        ))
        checks.append(.init(
            id: "asset_hash",
            label: "Image bytes match proof hash",
            passed: proof.asset.sha256B64URL == Base64URL.encode(assetSHA),
            detail: proof.asset.sha256B64URL
        ))
        checks.append(.init(
            id: "asset_binding",
            label: "Asset binding material matches",
            passed: proof.asset.bindingMaterialSHA256B64URL == Base64URL.encode(materialDigest),
            detail: proof.asset.bindingMaterialSHA256B64URL
        ))
        checks.append(.init(
            id: "nonce_decodes",
            label: "OpenID4VP nonce decodes",
            passed: decodedNonce != nil,
            detail: decodedNonce?.type
        ))
        checks.append(.init(
            id: "nonce_payload",
            label: "Nonce payload matches proof",
            passed: decodedNonce == proof.noncePayload,
            detail: proof.noncePayload.type
        ))
        checks.append(.init(
            id: "nonce_asset_binding",
            label: "Nonce binds asset binding digest",
            passed: proof.noncePayload.assetBindingSHA256B64URL == Base64URL.encode(materialDigest),
            detail: proof.noncePayload.assetBindingSHA256B64URL
        ))
        checks.append(.init(
            id: "cawg_sig_type",
            label: "CAWG extension sig_type",
            passed: proof.cawg.sigType == IIRYConstants.cawgOpenID4VPSigType,
            detail: proof.cawg.sigType
        ))
        checks.append(.init(
            id: "cawg_hard_binding_reference",
            label: "Proof references asset-binding material",
            passed: proof.cawg.referencedAssertions.contains {
                $0.url == IIRYConstants.hardBindingReferenceURL &&
                $0.hashB64URL == proof.asset.bindingMaterialSHA256B64URL
            },
            detail: IIRYConstants.hardBindingReferenceURL
        ))

        if let presentation = proof.openID4VP.compactPresentation {
            let presentationNonce = try? PresentationExtractor.nonce(fromPresentation: presentation)
            checks.append(.init(
                id: "presentation_nonce",
                label: "Presentation nonce matches",
                passed: presentationNonce == proof.openID4VP.nonce,
                detail: presentationNonce
            ))
        } else {
            checks.append(.init(
                id: "presentation_nonce",
                label: "Presentation nonce matches",
                passed: false,
                detail: "No compact presentation embedded"
            ))
        }

        if let summary = proof.openID4VP.walletVerification {
            checks.append(.init(
                id: "wallet_service_verification",
                label: "Wallet service verification passed",
                passed: summary.allKnownChecksPassed,
                detail: summary.error
            ))
        } else {
            checks.append(.init(
                id: "wallet_service_verification",
                label: "Wallet service verification passed",
                passed: false,
                detail: "No service verification summary embedded"
            ))
        }

        return IIRYVerificationReport(checks: checks)
    }
}
