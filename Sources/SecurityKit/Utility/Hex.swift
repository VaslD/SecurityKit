import Foundation

extension UInt8 {
    func asHexString(uppercased: Bool = true) -> String {
        String(format: uppercased ? "%02X" : "%02x", self)
    }
}

extension Sequence where Element == UInt8 {
    func asHexString(uppercased: Bool = true, separator: String = "") -> String {
        self.map { String(format: uppercased ? "%02X" : "%02x", $0) }.joined(separator: separator)
    }
}
