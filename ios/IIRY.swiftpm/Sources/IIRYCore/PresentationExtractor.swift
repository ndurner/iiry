import Foundation

public enum PresentationExtractor {
    public static func vpTokenObject(fromDecodedResponseJSON data: Data) throws -> [String: Any]? {
        guard let dictionary = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let vpToken = dictionary["vp_token"] as? [String: Any] else {
            return nil
        }
        return vpToken
    }

    public static func firstPresentation(fromVPTokenObject vpToken: [String: Any]) -> String? {
        firstPresentation(inVPToken: vpToken)
    }

    public static func firstPresentation(fromDecodedResponseJSON data: Data) throws -> String? {
        let object = try JSONSerialization.jsonObject(with: data)
        return firstPresentation(in: object)
    }

    public static func firstPresentation(in object: Any) -> String? {
        guard let dictionary = object as? [String: Any],
              let vpToken = dictionary["vp_token"] as? [String: Any] else {
            return nil
        }
        return firstPresentation(inVPToken: vpToken)
    }

    private static func firstPresentation(inVPToken vpToken: [String: Any]) -> String? {
        for value in vpToken.values {
            if let presentations = value as? [Any] {
                for item in presentations {
                    if let presentation = item as? String {
                        return presentation
                    }
                }
            } else if let presentation = value as? String {
                return presentation
            }
        }
        return nil
    }

    public static func keyBindingPayload(fromPresentation presentation: String) throws -> [String: Any] {
        let parts = presentation.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 3, let keyBindingJWT = parts.last, !keyBindingJWT.isEmpty else {
            throw IIRYError.invalidJWT("SD-JWT presentation must include a key-binding JWT")
        }
        return try jwtPayload(keyBindingJWT)
    }

    public static func nonce(fromPresentation presentation: String) throws -> String? {
        try keyBindingPayload(fromPresentation: presentation)["nonce"] as? String
    }

    public static func disclosedClaims(fromPresentation presentation: String) -> [String: String] {
        let parts = presentation.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 3 else {
            return [:]
        }
        var claims: [String: String] = [:]
        for disclosure in parts.dropFirst().dropLast() where !disclosure.isEmpty {
            guard let data = try? Base64URL.decode(disclosure),
                  let array = try? JSONSerialization.jsonObject(with: data) as? [Any],
                  array.count >= 3,
                  let key = array[1] as? String else {
                continue
            }
            if let value = array[2] as? String {
                claims[key] = value
            } else if let value = array[2] as? NSNumber {
                claims[key] = value.stringValue
            }
        }
        return claims
    }

    public static func jwtPayload(_ compactJWT: String) throws -> [String: Any] {
        let parts = compactJWT.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3 else {
            throw IIRYError.invalidJWT("JWT must have three segments")
        }
        let payloadData = try Base64URL.decode(parts[1])
        guard let payload = try JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            throw IIRYError.invalidJWT("JWT payload is not a JSON object")
        }
        return payload
    }
}
