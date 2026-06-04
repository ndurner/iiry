import Foundation
import Security

public enum IIRYNonce {
    public static func create(
        assetBindingSHA256: Data,
        randomNonce: Data? = nil
    ) throws -> (nonce: String, payload: IIRYNoncePayload) {
        let random = try randomNonce ?? secureRandom(count: 32)
        guard random.count >= 16 else {
            throw IIRYError.invalidNonce("Random nonce must be at least 128 bits")
        }
        guard assetBindingSHA256.count == 32 else {
            throw IIRYError.invalidNonce("Asset binding digest must be SHA-256")
        }

        let cbor = try DeterministicCBOR.encode(.array([
            .string(IIRYConstants.nonceType),
            .unsigned(2),
            .bytes(random),
            .bytes(assetBindingSHA256)
        ]))
        let payload = IIRYNoncePayload(
            randomNonceB64URL: Base64URL.encode(random),
            assetBindingSHA256B64URL: Base64URL.encode(assetBindingSHA256)
        )
        return (Base64URL.encode(cbor), payload)
    }

    public static func decode(_ nonce: String) throws -> IIRYNoncePayload {
        let data = try Base64URL.decode(nonce)
        let decoded = try DeterministicCBOR.decode(data)
        guard case .array(let values) = decoded, values.count == 4 else {
            throw IIRYError.invalidNonce("Nonce payload must be a four-item CBOR array")
        }
        guard case .string(let type) = values[0], type == IIRYConstants.nonceType else {
            throw IIRYError.invalidNonce("Nonce payload has wrong namespace")
        }
        guard case .unsigned(let version) = values[1], version == 2 else {
            throw IIRYError.invalidNonce("Nonce payload has unsupported version")
        }
        guard case .bytes(let random) = values[2], random.count >= 16 else {
            throw IIRYError.invalidNonce("Nonce payload random value is too short")
        }
        guard case .bytes(let assetBinding) = values[3], assetBinding.count == 32 else {
            throw IIRYError.invalidNonce("Nonce payload asset binding digest must be SHA-256")
        }
        return IIRYNoncePayload(
            randomNonceB64URL: Base64URL.encode(random),
            assetBindingSHA256B64URL: Base64URL.encode(assetBinding)
        )
    }

    public static func secureRandom(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw IIRYError.invalidNonce("SecRandomCopyBytes failed with status \(status)")
        }
        return Data(bytes)
    }
}
