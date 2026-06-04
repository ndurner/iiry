import Foundation

public enum CBORValue: Equatable {
    case unsigned(UInt64)
    case bytes(Data)
    case string(String)
    case array([CBORValue])
}

public enum DeterministicCBOR {
    public static func encode(_ value: CBORValue) throws -> Data {
        switch value {
        case .unsigned(let integer):
            return encodeHeader(majorType: 0, value: integer)
        case .bytes(let data):
            return encodeHeader(majorType: 2, value: UInt64(data.count)) + data
        case .string(let string):
            let data = Data(string.utf8)
            return encodeHeader(majorType: 3, value: UInt64(data.count)) + data
        case .array(let values):
            var out = encodeHeader(majorType: 4, value: UInt64(values.count))
            for item in values {
                out.append(try encode(item))
            }
            return out
        }
    }

    public static func decode(_ data: Data) throws -> CBORValue {
        var reader = CBORReader(data: data)
        let value = try reader.read()
        guard reader.isAtEnd else {
            throw IIRYError.invalidCBOR("Trailing bytes after CBOR item")
        }
        return value
    }

    private static func encodeHeader(majorType: UInt8, value: UInt64) -> Data {
        let prefix = majorType << 5
        if value < 24 {
            return Data([prefix | UInt8(value)])
        }
        if value <= UInt64(UInt8.max) {
            return Data([prefix | 24, UInt8(value)])
        }
        if value <= UInt64(UInt16.max) {
            var data = Data([prefix | 25])
            data.append(UInt8((value >> 8) & 0xff))
            data.append(UInt8(value & 0xff))
            return data
        }
        if value <= UInt64(UInt32.max) {
            var data = Data([prefix | 26])
            for shift in stride(from: 24, through: 0, by: -8) {
                data.append(UInt8((value >> UInt64(shift)) & 0xff))
            }
            return data
        }
        var data = Data([prefix | 27])
        for shift in stride(from: 56, through: 0, by: -8) {
            data.append(UInt8((value >> UInt64(shift)) & 0xff))
        }
        return data
    }
}

private struct CBORReader {
    let data: Data
    var offset = 0

    var isAtEnd: Bool {
        offset == data.count
    }

    mutating func read() throws -> CBORValue {
        let byte = try readByte()
        let majorType = byte >> 5
        let additional = byte & 0x1f
        let value = try readArgument(additional)

        switch majorType {
        case 0:
            return .unsigned(value)
        case 2:
            return .bytes(try readData(count: Int(value)))
        case 3:
            let bytes = try readData(count: Int(value))
            guard let string = String(data: bytes, encoding: .utf8) else {
                throw IIRYError.invalidCBOR("Invalid UTF-8 string")
            }
            return .string(string)
        case 4:
            var values: [CBORValue] = []
            values.reserveCapacity(Int(value))
            for _ in 0..<value {
                values.append(try read())
            }
            return .array(values)
        default:
            throw IIRYError.invalidCBOR("Unsupported major type \(majorType)")
        }
    }

    private mutating func readArgument(_ additional: UInt8) throws -> UInt64 {
        if additional < 24 {
            return UInt64(additional)
        }
        switch additional {
        case 24:
            return UInt64(try readByte())
        case 25:
            let bytes = try readData(count: 2)
            return bytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        case 26:
            let bytes = try readData(count: 4)
            return bytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        case 27:
            let bytes = try readData(count: 8)
            return bytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        default:
            throw IIRYError.invalidCBOR("Indefinite or reserved CBOR length is not allowed")
        }
    }

    private mutating func readByte() throws -> UInt8 {
        guard offset < data.count else {
            throw IIRYError.invalidCBOR("Unexpected end of CBOR data")
        }
        let byte = data[offset]
        offset += 1
        return byte
    }

    private mutating func readData(count: Int) throws -> Data {
        guard count >= 0, offset + count <= data.count else {
            throw IIRYError.invalidCBOR("Unexpected end of CBOR byte string")
        }
        let value = data[offset..<(offset + count)]
        offset += count
        return Data(value)
    }
}
