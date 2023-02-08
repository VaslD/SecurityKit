import CommonCrypto
import CryptoKit
import Foundation
import Security

public extension AES.CBC {
    /// One-shot in-place AES-CBC encryption, reuses an unmanaged buffer.
    ///
    /// - Parameters:
    ///   - data: Unmanaged buffer to plaintext, with at least 32 bytes (2 additional AES blocks) of free space.
    ///   - size: Length of plaintext in the buffer.
    ///   - key: AES symmetric key.
    /// - Returns: Length of encrypted cipher text.
    static func encrypt(_ data: UnsafeMutableBufferPointer<UInt8>, size: Int, key: SymmetricKey) -> Int {
        guard size >= 0, data.count >= size + kCCBlockSizeAES128 * 2 else {
            return 0
        }

        let bufferIV = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: kCCKeySizeAES128)
        defer { bufferIV.deallocate() }
        bufferIV.initialize(repeating: 0x00)
        let status = SecRandomCopyBytes(kSecRandomDefault, kCCKeySizeAES128, bufferIV.baseAddress!)
        guard status == errSecSuccess else {
            return 0
        }

        return key.withUnsafeBytes {
            var sizeOut = 0

            // CCCrypt only performs in-place operations if input and output buffers have the exact same start address.
            // If two buffers partially overlap (e.g. output shifted to reserve additional AES blocks),
            // CCCrypt will unknowingly overwrite the next block of plaintext with ciphertext block. (So stupid!)
            // We do an in-place encryption here, then use memmove(_:_:_:) to shift the ciphertext;
            // therefore, "reserving" an additional AES block of output for randomly generated IV.
            // Previously failing test cases should now pass, :-)
            guard CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES),
                          CCOptions(kCCOptionPKCS7Padding),
                          $0.baseAddress!, $0.count,
                          bufferIV.baseAddress!,
                          data.baseAddress!, size,
                          data.baseAddress!, data.count,
                          &sizeOut) == kCCSuccess else {
                return 0
            }
            memmove(data.baseAddress! + kCCBlockSizeAES128, data.baseAddress!, sizeOut)

            (0..<kCCBlockSizeAES128).forEach {
                data[$0] = bufferIV[$0]
            }
            sizeOut += kCCBlockSizeAES128

            return sizeOut
        }
    }

    static func encrypt<R>(_ data: some ContiguousBytes, key: SymmetricKey,
                           completion: (_ buffer: UnsafeBufferPointer<UInt8>?) throws -> R
    ) rethrows -> R {
        let bufferIV = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: kCCKeySizeAES128)
        defer { bufferIV.deallocate() }
        bufferIV.initialize(repeating: 0x00)
        let status = SecRandomCopyBytes(kSecRandomDefault, kCCKeySizeAES128, bufferIV.baseAddress!)
        guard status == errSecSuccess else {
            return try completion(nil)
        }

        return try data.withUnsafeBytes { dataIn in
            try key.withUnsafeBytes { keyIn in
                var sizeOut = dataIn.count + kCCBlockSizeAES128 * 2
                let dataOut = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: sizeOut)
                defer { dataOut.deallocate() }
                dataOut.initialize(repeating: 0x00)

                (0..<kCCBlockSizeAES128).forEach {
                    dataOut[$0] = bufferIV[$0]
                }
                sizeOut -= kCCBlockSizeAES128

                guard CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES),
                              CCOptions(kCCOptionPKCS7Padding),
                              keyIn.baseAddress!, keyIn.count,
                              bufferIV.baseAddress!,
                              dataIn.baseAddress!, dataIn.count,
                              dataOut.baseAddress! + kCCBlockSizeAES128, sizeOut, &sizeOut) == kCCSuccess else {
                    return try completion(nil)
                }
                sizeOut += kCCBlockSizeAES128

                let result = try completion(UnsafeBufferPointer(rebasing: dataOut[..<sizeOut]))

                dataOut.assign(repeating: 0x00)
                return result
            }
        }
    }
}
