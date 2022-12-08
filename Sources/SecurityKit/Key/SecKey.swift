import Foundation
import Security

/// Restores a key from an external representation of that key.
///
/// - Parameters:
///   - data: Data representing the key. The format of the data depends on the type of key being created.
///   - properties: A dictionary containing attributes describing the key to be imported.
/// - Returns: The restored key.
public func SecKeyCreateWithData<T: ContiguousBytes>(_ data: T, properties: [CFString: Any]) throws -> SecKey {
    var error: Unmanaged<CFError>?
    let key = data.withUnsafeBytes {
        let data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, $0.baseAddress!, $0.count, kCFAllocatorNull)!
        return SecKeyCreateWithData(data, properties as CFDictionary, &error)
    }
    if let error = error?.takeUnretainedValue() {
        throw error
    }
    return key!
}

/// Generates a new private/public key pair.
///
/// - Parameter properties: A dictionary you use to specify the attributes of the keys to be generated.
/// - Returns: The newly generated private key.
public func SecKeyCreateRandomPrivateKey(_ properties: [CFString: Any]) throws -> SecKey {
    var error: Unmanaged<CFError>?
    let key = SecKeyCreateRandomKey(properties as CFDictionary, &error)
    if let error = error?.takeUnretainedValue() {
        throw error
    }
    return key!
}

public extension SecKey {
    /// Gets the block length in **bytes** associated with this cryptographic key.
    var blockSize: Int {
        SecKeyGetBlockSize(self)
    }

    /// Gets the public key associated with the given private key.
    var publicKey: SecKey {
        get throws {
            guard let key = SecKeyCopyPublicKey(self) else {
                throw SecError(errSecInternalError)
            }
            return key
        }
    }

    // MARK: Encryption

    /// Encrypts a block of data using this public key and specified algorithm.
    ///
    /// - Parameters:
    ///   - block: The data to be encrypted.
    ///   - algorithm: The encryption algorithm to use.
    /// - Returns: The encrypted data.
    func encrypt<T: ContiguousBytes>(block: T, algorithm: SecKeyAlgorithm) throws -> Data {
        guard SecKeyIsAlgorithmSupported(self, .encrypt, algorithm) else {
            throw SecError(errSecInvalidAlgorithm)
        }

        var error: Unmanaged<CFError>?
        let encrypted = block.withUnsafeBytes {
            let data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, $0.baseAddress!, $0.count, kCFAllocatorNull)!
            return SecKeyCreateEncryptedData(self, algorithm, data, &error)
        }
        if let error = error?.takeUnretainedValue() {
            throw error
        }
        return encrypted! as Data
    }

    /// Decrypts a block of data using this private key and specified algorithm.
    ///
    /// - Parameters:
    ///   - block: The algorithm that was used to encrypt the data in the first place.
    ///   - algorithm: The data, produced with the corresponding public key and a call to the
    ///                `SecKeyCreateEncryptedData(_:_:_:_:)` function, that you want to decrypt.
    /// - Returns: The decrypted data.
    func decrypt<T: ContiguousBytes>(block: T, algorithm: SecKeyAlgorithm) throws -> Data {
        guard SecKeyIsAlgorithmSupported(self, .decrypt, algorithm) else {
            throw SecError(errSecInvalidAlgorithm)
        }

        var error: Unmanaged<CFError>?
        let decrypted = block.withUnsafeBytes {
            let data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, $0.baseAddress!, $0.count, kCFAllocatorNull)!
            return SecKeyCreateDecryptedData(self, algorithm, data, &error)
        }
        if let error = error?.takeUnretainedValue() {
            throw error
        }
        return decrypted! as Data
    }

    // MARK: Signature

    /// Creates the cryptographic signature for a block of data using this private key and specified algorithm.
    ///
    /// - Parameters:
    ///   - message: The data whose signature you want.
    ///   - algorithm: The signing algorithm to use.
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

    /// Verifies the cryptographic signature of a block of data using this public key and specified algorithm.
    ///
    /// - Parameters:
    ///   - message: The data that was signed.
    ///   - signature: The signature that was created with a call to the `SecKeyCreateSignature(_:_:_:_:)` function.
    ///   - algorithm: The algorithm that was used to create the signature.
    /// - Returns: This method returns `Void` only if the signature was valid. Otherwise an error is thrown.
    func verify<M: ContiguousBytes, S: ContiguousBytes>(message: M, signature: S,
                                                        algorithm: SecKeyAlgorithm) throws {
        guard SecKeyIsAlgorithmSupported(self, .verify, algorithm) else {
            throw SecError(errSecInvalidAlgorithm)
        }

        var error: Unmanaged<CFError>?
        let isValid = message.withUnsafeBytes {
            let messageData = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, $0.baseAddress!, $0.count,
                                                          kCFAllocatorNull)!
            return signature.withUnsafeBytes {
                let signatureData = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, $0.baseAddress!, $0.count,
                                                                kCFAllocatorNull)!
                return SecKeyVerifySignature(self, algorithm, messageData, signatureData, &error)
            }
        }
        if let error = error?.takeUnretainedValue() {
            throw error
        }
        guard isValid else {
            throw SecError(errSecInvalidSignature)
        }
    }

    // MARK: - Key Exchange

    /// Performs the Diffie-Hellman style of key exchange using this private key and optional key-derivation steps.
    ///
    /// - Parameters:
    ///   - publicKey: The other party’s public key.
    ///   - algorithm: The key exchange algorithm to use.
    ///   - parameters: Additional key exchange parameters.
    /// - Returns: A data instance representing the result of the key exchange operation.
    func exchange(_ publicKey: SecKey, algorithm: SecKeyAlgorithm, parameters: [CFString: Any]) throws -> Data {
        guard SecKeyIsAlgorithmSupported(self, .keyExchange, algorithm) else {
            throw SecError(errSecInvalidAlgorithm)
        }

        var error: Unmanaged<CFError>?
        let data = SecKeyCopyKeyExchangeResult(self, algorithm, publicKey, parameters as CFDictionary, &error)
        if let error = error?.takeUnretainedValue() {
            throw error
        }

        return data! as Data
    }

    // MARK: - Export

    /// Returns an external representation of this key suitable for the key’s type.
    ///
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
