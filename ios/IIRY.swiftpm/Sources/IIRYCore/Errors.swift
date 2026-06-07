import Foundation

public enum IIRYError: Error, LocalizedError, Equatable {
    case invalidBase64URL(String)
    case invalidCBOR(String)
    case invalidNonce(String)
    case invalidCarrier(String)
    case invalidJWT(String)
    case commandFailed(String)

    public var errorDescription: String? {
        switch self {
        case .invalidBase64URL(let value):
            return "Invalid base64url value: \(value)"
        case .invalidCBOR(let detail):
            return "Invalid deterministic CBOR: \(detail)"
        case .invalidNonce(let detail):
            return "Invalid IIRY nonce: \(detail)"
        case .invalidCarrier(let detail):
            return "Invalid IIRY data: \(detail)"
        case .invalidJWT(let detail):
            return "Invalid JWT: \(detail)"
        case .commandFailed(let detail):
            return detail
        }
    }
}
