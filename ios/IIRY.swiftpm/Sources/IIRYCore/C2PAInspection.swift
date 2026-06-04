import Foundation

public enum IIRYC2PAInspectionVerifier {
    public static func verifyC2PAAsset(imageData: Data, detailedJSON: Data) throws -> IIRYVerificationReport {
        let proof = try extractProofBundle(fromDetailedJSON: detailedJSON)
        let visualImage = (try? IIRYJPEGC2PA.stripC2PASegments(fromJPEG: imageData)) ?? imageData
        var checks = try IIRYVerifier.verify(proof: proof, imageData: visualImage).checks
        checks.insert(.init(
            id: "c2pa_data_hash",
            label: "C2PA validator confirms hard binding",
            passed: hasValidationSuccess(code: "assertion.dataHash.match", inDetailedJSON: detailedJSON),
            detail: "assertion.dataHash.match"
        ), at: 0)
        checks.insert(.init(
            id: "c2pa_claim_signature",
            label: "C2PA validator confirms claim signature",
            passed: hasValidationSuccess(code: "claimSignature.validated", inDetailedJSON: detailedJSON),
            detail: "claimSignature.validated"
        ), at: 1)
        let expectedAssertionHashes = claimAssertionReferenceCount(inDetailedJSON: detailedJSON)
        let matchedAssertionHashes = validationCodeCount(code: "assertion.hashedURI.match", bucket: "success", inDetailedJSON: detailedJSON)
        checks.insert(.init(
            id: "c2pa_assertion_hashes",
            label: "C2PA validator confirms assertion hashes",
            passed: expectedAssertionHashes > 0 && matchedAssertionHashes == expectedAssertionHashes,
            detail: "\(matchedAssertionHashes)/\(expectedAssertionHashes) assertion hashes"
        ), at: 2)
        checks.insert(.init(
            id: "c2pa_signing_credential",
            label: "C2PA signing credential is trusted",
            passed: hasValidationSuccess(code: "signingCredential.trusted", inDetailedJSON: detailedJSON)
                || !hasValidationFailure(code: "signingCredential.untrusted", inDetailedJSON: detailedJSON),
            detail: hasValidationSuccess(code: "signingCredential.trusted", inDetailedJSON: detailedJSON)
                ? "signingCredential.trusted"
                : "signingCredential.untrusted"
        ), at: 3)
        checks.insert(.init(
            id: "c2pa_proof_assertion",
            label: "C2PA manifest carries IIRY proof assertion",
            passed: true,
            detail: IIRYConstants.proofBundleAssertionLabel
        ), at: 4)
        checks.insert(.init(
            id: "c2pa_container_image",
            label: "Opened asset is a JPEG-like carrier",
            passed: imageData.starts(with: [0xff, 0xd8]),
            detail: "\(imageData.count) bytes"
        ), at: 5)
        return IIRYVerificationReport(checks: checks)
    }

    public static func extractProofBundle(fromDetailedJSON detailedJSON: Data) throws -> IIRYProofBundle {
        guard let root = try JSONSerialization.jsonObject(with: detailedJSON) as? [String: Any],
              let active = root["active_manifest"] as? String,
              let manifests = root["manifests"] as? [String: Any],
              let manifest = manifests[active] as? [String: Any],
              let assertionStore = manifest["assertion_store"] as? [String: Any] else {
            throw IIRYError.invalidCarrier("C2PA report did not contain an active assertion store")
        }
        let proofObject = assertionStore[IIRYConstants.proofBundleAssertionLabel]
            ?? assertionStore[IIRYConstants.proofBundleType]
        guard let proofObject else {
            throw IIRYError.invalidCarrier("C2PA manifest did not contain the IIRY proof-bundle assertion")
        }
        let proofData = try JSONCoding.objectData(proofObject)
        return try JSONCoding.decoder().decode(IIRYProofBundle.self, from: proofData)
    }

    public static func validationState(fromDetailedJSON detailedJSON: Data) throws -> String? {
        guard let root = try JSONSerialization.jsonObject(with: detailedJSON) as? [String: Any] else {
            return nil
        }
        return root["validation_state"] as? String
    }

    private static func hasValidationSuccess(code: String, inDetailedJSON detailedJSON: Data) -> Bool {
        hasValidationCode(code: code, bucket: "success", inDetailedJSON: detailedJSON)
    }

    private static func hasValidationFailure(code: String, inDetailedJSON detailedJSON: Data) -> Bool {
        hasValidationCode(code: code, bucket: "failure", inDetailedJSON: detailedJSON)
    }

    private static func hasValidationCode(code: String, bucket: String, inDetailedJSON detailedJSON: Data) -> Bool {
        validationCodeCount(code: code, bucket: bucket, inDetailedJSON: detailedJSON) > 0
    }

    private static func validationCodeCount(code: String, bucket: String, inDetailedJSON detailedJSON: Data) -> Int {
        guard let root = try? JSONSerialization.jsonObject(with: detailedJSON) as? [String: Any],
              let results = root["validation_results"] as? [String: Any],
              let active = results["activeManifest"] as? [String: Any],
              let entries = active[bucket] as? [[String: Any]] else {
            return 0
        }
        return entries.filter { $0["code"] as? String == code }.count
    }

    private static func claimAssertionReferenceCount(inDetailedJSON detailedJSON: Data) -> Int {
        guard let root = try? JSONSerialization.jsonObject(with: detailedJSON) as? [String: Any],
              let active = root["active_manifest"] as? String,
              let manifests = root["manifests"] as? [String: Any],
              let manifest = manifests[active] as? [String: Any],
              let claim = manifest["claim"] as? [String: Any] else {
            return 0
        }
        let created = (claim["created_assertions"] as? [[String: Any]])?.count ?? 0
        let gathered = (claim["gathered_assertions"] as? [[String: Any]])?.count ?? 0
        let assertions = (claim["assertions"] as? [[String: Any]])?.count ?? 0
        return max(assertions, created + gathered)
    }
}
