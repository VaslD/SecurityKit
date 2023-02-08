import Foundation

public extension RangeReplaceableCollection<UInt8> {
    /// Converts sequence of hexadecimal bytes to a collection of `UInt8` values.
    ///
    /// - Parameter string: Hexadecimal representation of bytes. The full string must be valid hex
    ///                     (i.e. contains no separator character).
    init?(hex string: some StringProtocol) {
        guard string.count.isMultiple(of: 2) else {
            return nil
        }

        var bytes = [UInt8]()
        var index = string.startIndex
        while index != string.endIndex {
            let nextIndex = string.index(index, offsetBy: 2)
            let substring = string[index..<nextIndex]
            guard let byte = UInt8(substring, radix: 16) else {
                return nil
            }
            bytes.append(byte)
            index = nextIndex
        }
        self = Self(bytes)
    }
}

public extension UInt8 {
    /// Converts this byte to its hexadecimal representation, padded with a leading `0` if necessary.
    ///
    /// - Parameters:
    ///   - uppercase: Letter cases to use to represent numerals greater than 9.
    /// - Returns: A hexadecimal byte.
    func asHexString(uppercase: Bool) -> String {
        let hex = String(self, radix: 16, uppercase: uppercase)
        if hex.count == 1 {
            return "0\(hex)"
        }
        return hex
    }
}

public extension Sequence<UInt8> {
    /// Converts sequence of bytes to their hexadecimal representation.
    ///
    /// - Parameters:
    ///   - uppercase: Letter cases to use to represent numerals greater than 9.
    ///   - separator: A string to insert between every two characters (one hexadecimal byte).
    /// - Returns: Concatenated hexadecimal bytes.
    func asHexString(uppercase: Bool, separator: String = String()) -> String {
        self.map { $0.asHexString(uppercase: uppercase) }.joined(separator: separator)
    }
}
