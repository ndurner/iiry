import Foundation
import Testing
@testable import IIRYCore

@Test func requestTextUsesShortDateAndNonceCode() throws {
    let date = Date(timeIntervalSince1970: 1_780_416_000)
    let text = try IIRYRequestText.make(date: date, nonceCode: "ABC123XY")
    #expect(text == "Is it really you?\n(2026-06-02 ABC123XY)")
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
