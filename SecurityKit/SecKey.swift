import Foundation
import Security

public extension SecKey {
    /// Restores a key from an external representation of that key.
    ///
    /// - Parameters:
    ///   - type: A value indicating the key's algorithm.
    ///   - class: A value indicating the key's cryptographic key class.
    ///   - data: Data representing the key. The format of the data depends on the type of key being created.
    ///           See the description of the return value of the `SecKeyCopyExternalRepresentation(_:_:)`
    ///           function for details.
    /// - Throws: `CFError` or ``SecError``.
    /// - Returns: The restored key.
    static func `import`<T: ContiguousBytes>(_ type: SecAttrKeyType, _ class: SecAttrKeyClass,
                                             _ data: T) throws -> SecKey {
        var error: Unmanaged<CFError>?
        let key = data.withUnsafeBytes {
            let data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, $0.baseAddress!, $0.count, kCFAllocatorNull)!
            return SecKeyCreateWithData(data, [
                kSecAttrKeyType: type.rawValue,
                kSecAttrKeyClass: `class`.rawValue,
            ] as CFDictionary, &error)
        }

        if let error = error?.takeUnretainedValue() {
            throw error
        }
        return key!
    }

    /// Gets the algorithm of this key.
    var keyType: SecAttrKeyType? {
        guard let attributes = SecKeyCopyAttributes(self) as? [CFString: Any] else {
            return nil
        }
        let value = attributes[kSecAttrKeyType] as AnyObject
        guard CFGetTypeID(value) == CFStringGetTypeID(),
              let keyClass = SecAttrKeyType(rawValue: value as! CFString) else {
            return nil
        }
        return keyClass
    }

    /// Gets the cryptographic key class of this key.
    var keyClass: SecAttrKeyClass? {
        guard let attributes = SecKeyCopyAttributes(self) as? [CFString: Any] else {
            return nil
        }
        let value = attributes[kSecAttrKeyClass] as AnyObject
        guard CFGetTypeID(value) == CFStringGetTypeID(),
              let keyClass = SecAttrKeyClass(rawValue: value as! CFString) else {
            return nil
        }
        return keyClass
    }

    /// Gets the number of **bytes** in a cryptographic key.
    var keySize: Int? {
        guard let attributes = SecKeyCopyAttributes(self) as? [CFString: Any] else {
            return nil
        }
        let value = attributes[kSecAttrKeySizeInBits] as AnyObject
        guard CFGetTypeID(value) == CFNumberGetTypeID() else {
            return nil
        }
        return ((value as! CFNumber) as NSNumber).intValue / 8
    }

    /// Gets the block length in **bytes** associated with a cryptographic key.
    ///
    /// If the key is an RSA key, for example, this is the size of the modulus.
    var blockSize: Int {
        SecKeyGetBlockSize(self)
    }

    /// Gets the public key associated with this private key.
    var publicKey: SecKey? {
        SecKeyCopyPublicKey(self)
    }

    /// Encrypts a block of data using this key (or the corresponding public key) and specified algorithm.
    ///
    /// - Parameters:
    ///   - message: The data to be encrypted.
    ///   - algorithm: The encryption algorithm to use.
    /// - Throws: `CFError` or ``SecError``.
    /// - Returns: The encrypted data.
    func encrypt<T: ContiguousBytes>(_ message: T, algorithm: SecKeyAlgorithm) throws -> Data {
        let key: SecKey
        if self.keyClass == .privateKey, let publicKey = self.publicKey {
            key = publicKey
        } else {
            key = self
        }

        guard SecKeyIsAlgorithmSupported(key, .encrypt, algorithm) else {
            throw SecError(errSecInvalidAlgorithm)
        }

        var error: Unmanaged<CFError>?
        let encrypted = message.withUnsafeBytes {
            let data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, $0.baseAddress!, $0.count, kCFAllocatorNull)!
            return SecKeyCreateEncryptedData(key, algorithm, data, &error)
        }
        if let error = error?.takeUnretainedValue() {
            throw error
        }
        return encrypted! as Data
    }

    /// Decrypts a block of data using this private key and specified algorithm.
    ///
    /// - Parameters:
    ///   - message: The algorithm that was used to encrypt the data in the first place.
    ///   - algorithm: The data, produced with the corresponding public key and a call to the
    ///                `SecKeyCreateEncryptedData(_:_:_:_:)` function, that you want to decrypt.
    /// - Throws: `CFError` or ``SecError``.
    /// - Returns: The decrypted data.
    func decrypt<T: ContiguousBytes>(_ message: T, algorithm: SecKeyAlgorithm) throws -> Data {
        guard SecKeyIsAlgorithmSupported(self, .decrypt, algorithm) else {
            throw SecError(errSecInvalidAlgorithm)
        }

        var error: Unmanaged<CFError>?
        let decrypted = message.withUnsafeBytes {
            let data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, $0.baseAddress!, $0.count, kCFAllocatorNull)!
            return SecKeyCreateDecryptedData(self, algorithm, data, &error)
        }
        if let error = error?.takeUnretainedValue() {
            throw error
        }
        return decrypted! as Data
    }

    /// Creates the cryptographic signature for a block of data using this private key and specified algorithm.
    ///
    /// - Parameters:
    ///   - message: The data whose signature you want.
    ///   - algorithm: The signing algorithm to use.
    /// - Throws: `CFError` or ``SecError``.
    /// - Returns: The digital signature.
    func sign<T: ContiguousBytes>(_ message: T, algorithm: SecKeyAlgorithm) throws -> Data {
        guard SecKeyIsAlgorithmSupported(self, .sign, algorithm) else {
            throw SecError(errSecInvalidAlgorithm)
        }

        var error: Unmanaged<CFError>?
        let signature = message.withUnsafeBytes {
            let data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, $0.baseAddress!, $0.count, kCFAllocatorNull)!
            return SecKeyCreateSignature(self, algorithm, data, &error)
        }
        if let error = error?.takeUnretainedValue() {
            throw error
        }
        return signature! as Data
    }

    /// Verifies the cryptographic signature of a block of data using this key (or the corresponding public key)
    /// and specified algorithm.
    ///
    /// - Parameters:
    ///   - message: The data that was signed.
    ///   - signature: The signature that was created with a call to the `SecKeyCreateSignature(_:_:_:_:)` function.
    ///   - algorithm: The algorithm that was used to create the signature.
    /// - Throws: `CFError` or ``SecError``.
    /// - Returns: This method returns `Void` only if the signature was valid. Otherwise an error is thrown.
    func verify<M: ContiguousBytes, S: ContiguousBytes>(message: M, signature: S,
                                                        algorithm: SecKeyAlgorithm) throws {
        let key: SecKey
        if self.keyClass == .privateKey, let publicKey = self.publicKey {
            key = publicKey
        } else {
            key = self
        }

        guard SecKeyIsAlgorithmSupported(key, .verify, algorithm) else {
            throw SecError(errSecInvalidAlgorithm)
        }

        var error: Unmanaged<CFError>?
        let isValid = message.withUnsafeBytes {
            let messageData = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, $0.baseAddress!, $0.count,
                                                          kCFAllocatorNull)!
            return signature.withUnsafeBytes {
                let signatureData = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, $0.baseAddress!, $0.count,
                                                                kCFAllocatorNull)!
                return SecKeyVerifySignature(key, algorithm, messageData, signatureData, &error)
            }
        }
        if let error = error?.takeUnretainedValue() {
            throw error
        }
        guard isValid else {
            throw SecError(errSecInvalidSignature)
        }
    }

    /// Returns an external representation of this key suitable for the key's type.
    ///
    /// The method returns data in the PKCS #1 format for an RSA key.
    ///
    /// For an elliptic curve public key, the format follows the ANSI X9.63 standard using a byte string of
    /// `04 || X || Y`. For an elliptic curve private key, the output is formatted as the public key concatenated with
    /// the big endian encoding of the secret scalar, or `04 || X || Y || K`. All of these representations use
    /// constant size integers, including leading zeros as needed.
    ///
    /// - Throws: `CFError` or ``SecError``.
    /// - Returns: A data object representing the key in a format suitable for the key type.
    func export() throws -> Data {
        var error: Unmanaged<CFError>?
        let data = SecKeyCopyExternalRepresentation(self, &error)
        if let error = error?.takeUnretainedValue() {
            throw error
        }
        return data! as Data
    }
}
