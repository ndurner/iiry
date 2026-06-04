import Foundation

public enum IIRYC2PAManifestBuilder {
    public static func manifestData(for carrier: IIRYCarrier, pretty: Bool = true) throws -> Data {
        try JSONCoding.objectData(manifestObject(for: carrier), pretty: pretty)
    }

    public static func manifestObject(for carrier: IIRYCarrier) throws -> [String: Any] {
        let proofData = try JSONCoding.encoder(pretty: false).encode(carrier.proof)
        let proofObject = try JSONSerialization.jsonObject(with: proofData)
        return [
            "claim_generator": IIRYConstants.claimGenerator,
            "format": IIRYConstants.jpegMediaType,
            "title": carrier.suggestedFileName,
            "assertions": [
                [
                    "label": IIRYConstants.proofBundleAssertionLabel,
                    "data": proofObject
                ],
                [
                    "label": "c2pa.actions",
                    "data": [
                        "actions": [
                            [
                                "action": "c2pa.created",
                                "softwareAgent": IIRYConstants.claimGenerator
                            ]
                        ]
                    ]
                ]
            ]
        ]
    }
}
