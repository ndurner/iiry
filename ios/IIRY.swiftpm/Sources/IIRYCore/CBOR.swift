import Foundation

public enum CBORValue: Equatable {
    case unsigned(UInt64)
    case negative(Int64)
    case bytes(Data)
    case string(String)
    case array([CBORValue])
    case map([(CBORValue, CBORValue)])
    indirect case tagged(UInt64, CBORValue)
    case null

    public static func == (lhs: CBORValue, rhs: CBORValue) -> Bool {
        switch (lhs, rhs) {
        case (.unsigned(let left), .unsigned(let right)):
            return left == right
        case (.negative(let left), .negative(let right)):
            return left == right
        case (.bytes(let left), .bytes(let right)):
            return left == right
        case (.string(let left), .string(let right)):
            return left == right
        case (.array(let left), .array(let right)):
            return left == right
        case (.map(let left), .map(let right)):
            guard left.count == right.count else {
                return false
            }
            return zip(left, right).allSatisfy { lhsPair, rhsPair in
                lhsPair.0 == rhsPair.0 && lhsPair.1 == rhsPair.1
            }
        case (.tagged(let leftTag, let leftValue), .tagged(let rightTag, let rightValue)):
            return leftTag == rightTag && leftValue == rightValue
        case (.null, .null):
            return true
        default:
            return false
        }
    }
}

public enum DeterministicCBOR {
    public static func encode(_ value: CBORValue) throws -> Data {
        switch value {
        case .unsigned(let integer):
            return encodeHeader(majorType: 0, value: integer)
        case .negative(let integer):
            guard integer < 0 else {
                throw IIRYError.invalidCBOR("Negative CBOR value must be below zero")
            }
            return encodeHeader(majorType: 1, value: UInt64(-1 - integer))
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
        case .map(let pairs):
            let encodedPairs = try pairs.map { key, value in
                (key: try encode(key), value: try encode(value))
            }.sorted { lhs, rhs in
                lhs.key.lexicographicallyPrecedes(rhs.key)
            }
            var out = encodeHeader(majorType: 5, value: UInt64(encodedPairs.count))
            for pair in encodedPairs {
                out.append(pair.key)
                out.append(pair.value)
            }
            return out
        case .tagged(let tag, let value):
            return encodeHeader(majorType: 6, value: tag) + (try encode(value))
        case .null:
            return Data([0xf6])
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
        case 1:
            guard value <= UInt64(Int64.max) else {
                throw IIRYError.invalidCBOR("Negative integer is too large")
            }
            return .negative(-1 - Int64(value))
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
        case 5:
            var pairs: [(CBORValue, CBORValue)] = []
            pairs.reserveCapacity(Int(value))
            for _ in 0..<value {
                let key = try read()
                let entry = try read()
                pairs.append((key, entry))
            }
            return .map(pairs)
        case 6:
            return .tagged(value, try read())
        case 7:
            guard additional == 22 else {
                throw IIRYError.invalidCBOR("Unsupported CBOR simple value \(additional)")
            }
            return .null
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
