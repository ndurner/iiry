import CryptoKit
import Foundation

public enum Hashing {
    public static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    public static func sha256Base64URL(_ data: Data) -> String {
        Base64URL.encode(sha256(data))
    }

    public static func sha256Hex(_ data: Data) -> String {
        sha256(data).map { String(format: "%02x", $0) }.joined()
    }
}
