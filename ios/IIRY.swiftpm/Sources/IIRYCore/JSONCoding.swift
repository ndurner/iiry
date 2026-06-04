import Foundation

public enum JSONCoding {
    public static func encoder(pretty: Bool = false) -> JSONEncoder {
        let encoder = JSONEncoder()
        if pretty {
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        } else {
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        }
        return encoder
    }

    public static func decoder() -> JSONDecoder {
        JSONDecoder()
    }

    public static func canonicalData<T: Encodable>(_ value: T) throws -> Data {
        try encoder(pretty: false).encode(value)
    }

    public static func objectData(_ value: Any, pretty: Bool = false) throws -> Data {
        var options: JSONSerialization.WritingOptions = [.sortedKeys]
        if pretty {
            options.insert(.prettyPrinted)
        }
        return try JSONSerialization.data(withJSONObject: value, options: options)
    }

    public static func objectString(_ value: Any, pretty: Bool = false) throws -> String {
        let data = try objectData(value, pretty: pretty)
        return String(decoding: data, as: UTF8.self)
    }
}
