import Foundation
import Security

public extension Data {
    /// Generates cryptographically secure random bytes.
    ///
    /// - Parameter count: The number of random bytes to return.
    init(randomBytes count: Int) throws {
        let buffer = UnsafeMutableRawBufferPointer(start: malloc(count)!, count: count)
        buffer.initializeMemory(as: UInt8.self, repeating: 0x00)

        let status = SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        guard status == errSecSuccess else {
            throw SecError(status)
        }

        self = Data(bytesNoCopy: buffer.baseAddress!, count: count, deallocator: .free)
    }
}
