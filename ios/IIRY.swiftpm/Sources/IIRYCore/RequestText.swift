import Foundation

public enum IIRYRequestText {
    public static func make(date: Date = Date(), nonceCode: String? = nil) throws -> String {
        let code = try nonceCode ?? IIRYFileNames.shortCode(data: IIRYNonce.secureRandom(count: 8))
        return "Is it really you?\n(\(IIRYDateFormatting.shortRequestDateString(from: date)) \(code))"
    }
}

public enum IIRYFileNames {
    public static func proofFileName(date: Date, noncePayload: IIRYNoncePayload) -> String {
        let random = (try? Base64URL.decode(noncePayload.randomNonceB64URL)) ?? Data()
        let code = (try? shortCode(data: random)) ?? "UNKNOWN"
        return "IIRY-Commitment-\(IIRYDateFormatting.shortDateString(from: date))-\(code).jpg.c2pa.cawg.\(IIRYConstants.carrierExtension)"
    }

    public static func c2paJPEGFileName(from suggestedFileName: String) -> String {
        let suffix = ".\(IIRYConstants.carrierExtension)"
        let candidate: String
        if suggestedFileName.hasSuffix(suffix) {
            candidate = String(suggestedFileName.dropLast(suffix.count))
        } else {
            candidate = suggestedFileName
        }
        if candidate.lowercased().hasSuffix(".jpg") || candidate.lowercased().hasSuffix(".jpeg") {
            return candidate
        }
        return "\(candidate).jpg"
    }

    public static func c2paTransportFileName(from suggestedFileName: String) -> String {
        let suffix = ".\(IIRYConstants.carrierExtension)"
        if suggestedFileName.hasSuffix(suffix) {
            return suggestedFileName
        }
        return "\(c2paJPEGFileName(from: suggestedFileName)).\(IIRYConstants.carrierExtension)"
    }

    public static func shortCode(data: Data) throws -> String {
        guard !data.isEmpty else {
            throw IIRYError.invalidNonce("Cannot derive a short code from empty data")
        }
        let encoded = Base64URL.encode(data)
            .uppercased()
            .replacingOccurrences(of: "-", with: "")
            .replacingOccurrences(of: "_", with: "")
        return String(encoded.prefix(8))
    }
}

public enum IIRYDateFormatting {
    public static func shortDateString(from date: Date) -> String {
        var calendar = Calendar(identifier: .iso8601)
        calendar.timeZone = TimeZone(secondsFromGMT: 0) ?? .gmt
        let components = calendar.dateComponents([.year, .month, .day], from: date)
        return String(
            format: "%04d-%02d-%02d",
            components.year ?? 0,
            components.month ?? 0,
            components.day ?? 0
        )
    }

    public static func shortRequestDateString(from date: Date) -> String {
        let full = shortDateString(from: date)
        if full.hasPrefix("20") {
            return String(full.dropFirst(2))
        }
        return full
    }

    public static func iso8601String(from date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }
}
