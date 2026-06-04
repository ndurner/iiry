import Foundation
import Testing
@testable import IIRYCore

@Test func requestTextUsesShortDateAndNonceCode() throws {
    let date = Date(timeIntervalSince1970: 1_780_416_000)
    let text = try IIRYRequestText.make(date: date, nonceCode: "ABC123XY")
    #expect(text == "Is it really you?\n(26-06-02 ABC123XY)")
}

@Test func preparedProofCarriesDecodableNonce() throws {
    let image = Data([0xff, 0xd8, 0xff, 0xd9])
    let random = Data(repeating: 0x42, count: 32)
    let prepared = try IIRYProofBuilder.prepare(
        imageData: image,
        now: Date(timeIntervalSince1970: 1_780_416_000),
        randomNonce: random
    )

    #expect(prepared.carrier.suggestedFileName == "IIRY-Commitment-2026-06-02-QKJCQKJC.jpg.c2pa.cawg.iiry")
    #expect(prepared.proof.noncePayload == (try IIRYNonce.decode(prepared.nonce)))
    #expect(prepared.proof.openID4VP.nonce == prepared.nonce)
    #expect(prepared.proof.cawg.sigType == IIRYConstants.cawgOpenID4VPSigType)
}

@Test func verificationDetectsImageTampering() throws {
    let image = Data([0xff, 0xd8, 0x01, 0xff, 0xd9])
    let prepared = try IIRYProofBuilder.prepare(
        imageData: image,
        randomNonce: Data(repeating: 0x11, count: 32)
    )
    let report = try IIRYVerifier.verifyCarrier(prepared.carrier)
    #expect(report.checks.first { $0.id == "asset_hash" }?.passed == true)
    #expect(report.overallPassed == false)

    var tampered = prepared.carrier
    tampered.imageB64URL = Base64URL.encode(Data([0xff, 0xd8, 0x02, 0xff, 0xd9]))
    let tamperedReport = try IIRYVerifier.verifyCarrier(tampered)
    #expect(tamperedReport.checks.first { $0.id == "asset_hash" }?.passed == false)
}

@Test func attachPresentationExtractsNonceAndClaims() throws {
    let image = Data([0xff, 0xd8, 0xff, 0xd9])
    let prepared = try IIRYProofBuilder.prepare(
        imageData: image,
        randomNonce: Data(repeating: 0x22, count: 32)
    )
    let presentation = fakePresentation(nonce: prepared.nonce)
    let response: [String: Any] = [
        "state": "test-state",
        "vp_token": [
            "pid-sd-jwt": [presentation]
        ]
    ]
    let responseData = try JSONCoding.objectData(response)
    let carrier = try IIRYProofBuilder.attachPresentation(
        carrier: prepared.carrier,
        decodedResponseJSON: responseData,
        walletVerification: WalletVerificationSummary(
            issuerSignature: true,
            issuerCertificateTrusted: true,
            disclosuresMatchIssuerCommitments: true,
            holderSignature: true,
            nonceMatchesChallenge: true,
            audienceIsThisVerifier: true,
            sdHashBindsPresentation: true
        )
    )

    #expect(carrier.proof.openID4VP.state == "test-state")
    #expect(carrier.proof.disclosedClaims["given_name"] == "ERIKA")

    let report = try IIRYVerifier.verifyCarrier(carrier)
    #expect(report.checks.first { $0.id == "presentation_nonce" }?.passed == true)
    #expect(report.checks.first { $0.id == "wallet_service_verification" }?.passed == true)
    #expect(report.overallPassed == true)
}

@Test func c2paProfileRoundTripsAndKeepsVisualJPEGStable() throws {
    let image = Data([0xff, 0xd8, 0xff, 0xd9])
    let carrier = try preparedCarrierWithPresentation(image: image)

    let signed = try IIRYC2PAAssetProcessor.signJPEG(carrier: carrier)
    let stripped = try IIRYJPEGC2PA.stripC2PASegments(fromJPEG: signed.jpegData)
    let report = try IIRYC2PAAssetProcessor.verifyJPEG(signed.jpegData)

    #expect(stripped == image)
    #expect(report.checks.first { $0.id == "c2pa_data_hash" }?.passed == true)
    #expect(report.checks.first { $0.id == "c2pa_claim_signature" }?.passed == true)
    #expect(report.checks.first { $0.id == "iiry_claim_assertion_hashes" }?.passed == true)
    #expect(report.checks.first { $0.id == "asset_hash" }?.passed == true)
}

@Test func c2paProfileDetectsVisualByteReplay() throws {
    let image = Data([0xff, 0xd8, 0x01, 0xff, 0xd9])
    let carrier = try preparedCarrierWithPresentation(image: image)
    let signed = try IIRYC2PAAssetProcessor.signJPEG(carrier: carrier)

    var tampered = signed.jpegData
    tampered[tampered.count - 3] = 0x02
    let report = try IIRYC2PAAssetProcessor.verifyJPEG(tampered)

    #expect(report.checks.first { $0.id == "c2pa_data_hash" }?.passed == false)
    #expect(report.checks.first { $0.id == "asset_hash" }?.passed == false)
}

@Test func c2paProfileDetectsSignatureTampering() throws {
    let image = Data([0xff, 0xd8, 0xff, 0xd9])
    let carrier = try preparedCarrierWithPresentation(image: image)
    let signed = try IIRYC2PAAssetProcessor.signJPEG(carrier: carrier)
    var tampered = signed.jpegData
    guard let range = try IIRYJPEGC2PA.c2paSegmentRanges(inJPEG: tampered).last else {
        throw IIRYError.commandFailed("C2PA APP11 segment not found")
    }
    let signatureByteOffset = Int(range.start + range.length - 1)
    tampered[signatureByteOffset] ^= 0x01

    let report = try IIRYC2PAAssetProcessor.verifyJPEG(tampered)
    #expect(report.checks.first { $0.id == "c2pa_claim_signature" }?.passed == false)
}

private func preparedCarrierWithPresentation(image: Data) throws -> IIRYCarrier {
    let prepared = try IIRYProofBuilder.prepare(
        imageData: image,
        randomNonce: Data(repeating: 0x33, count: 32)
    )
    let presentation = fakePresentation(nonce: prepared.nonce)
    let responseData = try JSONCoding.objectData([
        "state": "test-state",
        "vp_token": [
            "pid-sd-jwt": [presentation]
        ]
    ])
    return try IIRYProofBuilder.attachPresentation(
        carrier: prepared.carrier,
        decodedResponseJSON: responseData,
        walletVerification: WalletVerificationSummary(
            issuerSignature: true,
            issuerCertificateTrusted: true,
            disclosuresMatchIssuerCommitments: true,
            holderSignature: true,
            nonceMatchesChallenge: true,
            audienceIsThisVerifier: true,
            sdHashBindsPresentation: true
        )
    )
}

private func fakePresentation(nonce: String) -> String {
    let issuerJWT = fakeJWT(payload: ["iss": "issuer"])
    let disclosure = Base64URL.encode(try! JSONCoding.objectData(["salt", "given_name", "ERIKA"]))
    let keyBinding = fakeJWT(payload: ["nonce": nonce, "aud": "verifier"])
    return [issuerJWT, disclosure, keyBinding].joined(separator: "~")
}

private func fakeJWT(payload: [String: Any]) -> String {
    let header = Base64URL.encode(try! JSONCoding.objectData(["alg": "none"]))
    let body = Base64URL.encode(try! JSONCoding.objectData(payload))
    return "\(header).\(body).signature"
}
