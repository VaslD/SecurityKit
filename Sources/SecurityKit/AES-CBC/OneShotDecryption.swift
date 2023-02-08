import CommonCrypto
import CryptoKit
import Foundation

public extension AES.CBC {
    /// One-shot in-place AES-CBC decryption, reuses an unmanaged buffer.
    ///
    /// - Parameters:
    ///   - buffer: Unmanaged buffer to IV and cipher text.
    ///   - key: AES symmetric key.
    /// - Returns: Length of decrypted plaintext.
    static func decrypt(_ buffer: UnsafeMutableBufferPointer<UInt8>, key: SymmetricKey) -> Int {
        guard buffer.count > kCCBlockSizeAES128 else {
            return 0
        }

        return key.withUnsafeBytes { keyIn in
            var sizeOut = 0
            guard CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES),
                          CCOptions(kCCOptionPKCS7Padding),
                          keyIn.baseAddress!, keyIn.count,
                          buffer.baseAddress!,
                          buffer.baseAddress! + kCCBlockSizeAES128, buffer.count - kCCBlockSizeAES128,
                          buffer.baseAddress!, buffer.count, &sizeOut) == kCCSuccess else {
                return 0
            }

            let unused = UnsafeMutableBufferPointer(rebasing: buffer[sizeOut...])
            unused.assign(repeating: 0x00)
            return sizeOut
        }
    }

    static func decrypt<R>(_ data: some ContiguousBytes, key: SymmetricKey,
                           completion: (UnsafeBufferPointer<UInt8>?) throws -> R) rethrows -> R {
        try data.withUnsafeBytes { dataIn in
            guard dataIn.count > kCCBlockSizeAES128 else {
                return try completion(nil)
            }

            return try key.withUnsafeBytes { keyIn in
                let dataOut = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: dataIn.count)
                defer { dataOut.deallocate() }
                dataOut.initialize(repeating: 0x00)

                var sizeOut = 0
                guard CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES),
                              CCOptions(kCCOptionPKCS7Padding),
                              keyIn.baseAddress!, keyIn.count,
                              dataIn.baseAddress!,
                              dataIn.baseAddress! + kCCBlockSizeAES128, dataIn.count - kCCBlockSizeAES128,
                              dataOut.baseAddress!, dataOut.count, &sizeOut) == kCCSuccess else {
                    return try completion(nil)
                }

                return try completion(UnsafeBufferPointer(rebasing: dataOut[..<sizeOut]))
            }
        }
    }
}
