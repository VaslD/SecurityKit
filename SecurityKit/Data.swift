import Foundation
import Security

public extension Data {
    /// Generates cryptographically secure random bytes.
    ///
    /// - Parameter count: The number of random bytes to return.
    init(randomBytes count: Int) throws {
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: count, alignment: MemoryLayout<UInt8>.alignment)
        buffer.initializeMemory(as: UInt8.self, repeating: 0x00, count: count)

        let status = SecRandomCopyBytes(kSecRandomDefault, count, buffer)
        guard status == errSecSuccess else {
            throw SecError(status)
        }

        self = Data(bytesNoCopy: buffer, count: count, deallocator: .custom { pointer, _ in pointer.deallocate() })
    }
}
