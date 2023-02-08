import Foundation
import Security

public final class SecRSAKey: SecSpecializedKey {
    public let isPrivate: Bool

    public let rawKey: SecKey

    public init(_ key: SecKey) throws {
        guard let attributes = SecKeyCopyAttributes(key) as? [CFString: Any] else {
            throw SecError(errSecMissingAttributeKeyType)
        }
        let type = attributes[kSecAttrKeyType] as AnyObject
        guard CFGetTypeID(type) == CFStringGetTypeID(),
              (type as! CFString) == kSecAttrKeyTypeRSA else {
            throw SecError(errSecInvalidAttributeKeyType)
        }

        let keyClass = attributes[kSecAttrKeyClass] as AnyObject
        guard CFGetTypeID(keyClass) == CFStringGetTypeID() else {
            throw SecError(errSecInvalidAttributeKey)
        }

        self.isPrivate = (keyClass as! CFString) == kSecAttrKeyClassPrivate
        self.rawKey = key
    }

    /// Generates a new private/public key pair.
    ///
    /// - Parameter size: A value indicating the number of bits in a cryptographic key.
    public init(size: KeySize) throws {
        var error: Unmanaged<CFError>?
        let key = SecKeyCreateRandomKey([
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits: size.rawValue,
        ] as CFDictionary, &error)
        if let error = error?.takeRetainedValue() {
            throw error
        }

        self.isPrivate = true
        self.rawKey = key!
    }

    /// Gets the size in **bits** of the modulus.
    public var keySize: Int {
        self.blockSize * 8
    }

    /// Gets the block length in **bytes** associated with this cryptographic key.
    public var blockSize: Int {
        SecKeyGetBlockSize(self.rawKey)
    }

    /// Gets the public key associated with this RSA key.
    public var publicKey: SecRSAKey {
        get throws {
            guard self.isPrivate else {
                return self
            }
            guard let key = SecKeyCopyPublicKey(self.rawKey) else {
                throw SecError(errSecInternalError)
            }
            return try SecRSAKey(key)
        }
    }

    // MARK: Encryption

    /// Encrypts a block of data using this key (or the associated public key) and specified algorithm.
    ///
    /// - Parameters:
    ///   - block: The data to be encrypted.
    ///   - algorithm: The encryption algorithm to use.
    /// - Returns: The encrypted data.
    public func encrypt(block: some ContiguousBytes, algorithm: EncryptionAlgorithm) throws -> Data {
        let key = self.isPrivate ? try self.publicKey.rawKey : self.rawKey

        guard SecKeyIsAlgorithmSupported(key, .encrypt, algorithm.rawValue) else {
            throw SecError(errSecInvalidAlgorithm)
        }

        var error: Unmanaged<CFError>?
        let encrypted = block.withUnsafeBytes {
            let data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, $0.baseAddress!, $0.count, kCFAllocatorNull)!
            return SecKeyCreateEncryptedData(key, algorithm.rawValue, data, &error)
        }
        if let error = error?.takeRetainedValue() {
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
    public func decrypt(block: some ContiguousBytes, algorithm: EncryptionAlgorithm) throws -> Data {
        guard self.isPrivate else {
            throw SecError(errSecKeyUsageIncorrect)
        }

        guard SecKeyIsAlgorithmSupported(self.rawKey, .decrypt, algorithm.rawValue) else {
            throw SecError(errSecInvalidAlgorithm)
        }

        var error: Unmanaged<CFError>?
        let decrypted = block.withUnsafeBytes {
            let data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, $0.baseAddress!, $0.count, kCFAllocatorNull)!
            return SecKeyCreateDecryptedData(self.rawKey, algorithm.rawValue, data, &error)
        }
        if let error = error?.takeRetainedValue() {
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
    public func sign(_ message: some ContiguousBytes, algorithm: SignatureAlgorithm) throws -> Data {
        guard self.isPrivate else {
            throw SecError(errSecKeyUsageIncorrect)
        }

        guard SecKeyIsAlgorithmSupported(self.rawKey, .sign, algorithm.rawValue) else {
            throw SecError(errSecInvalidAlgorithm)
        }

        var error: Unmanaged<CFError>?
        let signature = message.withUnsafeBytes {
            let data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, $0.baseAddress!, $0.count, kCFAllocatorNull)!
            return SecKeyCreateSignature(self.rawKey, algorithm.rawValue, data, &error)
        }
        if let error = error?.takeRetainedValue() {
            throw error
        }
        return signature! as Data
    }

    /// Verifies the cryptographic signature of a block of data using this key (or the associated public key)
    /// and specified algorithm.
    ///
    /// - Parameters:
    ///   - message: The data that was signed.
    ///   - signature: The signature that was created with a call to the `SecKeyCreateSignature(_:_:_:_:)` function.
    ///   - algorithm: The algorithm that was used to create the signature.
    /// - Returns: This method returns `Void` only if the signature was valid. Otherwise an error is thrown.
    public func verify(message: some ContiguousBytes, signature: some ContiguousBytes,
                       algorithm: SignatureAlgorithm) throws {
        let key = self.isPrivate ? try self.publicKey.rawKey : self.rawKey

        guard SecKeyIsAlgorithmSupported(key, .verify, algorithm.rawValue) else {
            throw SecError(errSecInvalidAlgorithm)
        }

        var error: Unmanaged<CFError>?
        let isValid = message.withUnsafeBytes {
            let messageData = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, $0.baseAddress!, $0.count,
                                                          kCFAllocatorNull)!
            return signature.withUnsafeBytes {
                let signatureData = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, $0.baseAddress!, $0.count,
                                                                kCFAllocatorNull)!
                return SecKeyVerifySignature(key, algorithm.rawValue, messageData, signatureData, &error)
            }
        }
        if let error = error?.takeRetainedValue() {
            throw error
        }
        guard isValid else {
            throw SecError(errSecInvalidSignature)
        }
    }

    // MARK: Export

    /// Restores an RSA key from the PKCS#1 representation of that key.
    ///
    /// - Parameter data: Data representing the key.
    public init(_ data: some ContiguousBytes) throws {
        var keyClass: CFString?
        let key: SecKey = try data.withUnsafeBytes {
            let data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, $0.baseAddress!, $0.count, kCFAllocatorNull)!

            if let privateKey = SecKeyCreateWithData(data, [
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            ] as CFDictionary, nil) {
                keyClass = kSecAttrKeyClassPrivate
                return privateKey
            }

            var error: Unmanaged<CFError>?
            let publicKey = SecKeyCreateWithData(data, [
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass: kSecAttrKeyClassPublic,
            ] as CFDictionary, &error)
            if let error = error?.takeRetainedValue() {
                throw error
            }

            keyClass = kSecAttrKeyClassPublic
            return publicKey!
        }

        self.isPrivate = keyClass! == kSecAttrKeyClassPrivate
        self.rawKey = key
    }

    /// Restores an RSA key from a Privacy Enhanced Mail (PEM) representation of that key.
    ///
    /// - Parameter PEM: PEM document of the key. It must have either "BEGIN PUBLIC KEY" or
    ///                  "BEGIN RSA PRIVATE KEY" header.
    public convenience init(_ PEM: String) throws {
        let lines = PEM.split(whereSeparator: \.isNewline)

        guard (lines.first == "-----BEGIN PUBLIC KEY-----" && lines.last == "-----END PUBLIC KEY-----") ||
            (lines.first == "-----BEGIN RSA PRIVATE KEY-----" && lines.last == "-----END RSA PRIVATE KEY-----") else {
            throw SecError(errSecUnsupportedKeyFormat)
        }

        guard let data = Data(base64Encoded: lines.dropFirst().dropLast().joined(),
                              options: .ignoreUnknownCharacters) else {
            throw SecError(errSecInvalidEncoding)
        }
        try self.init(data)
    }

    /// Returns an external representation of this key in the PKCS#1 format.
    ///
    /// - Returns: A data object representing the key in a format suitable for the key type.
    public func export() throws -> Data {
        var error: Unmanaged<CFError>?
        let data = SecKeyCopyExternalRepresentation(self.rawKey, &error)
        if let error = error?.takeRetainedValue() {
            throw error
        }
        return data! as Data
    }
}
