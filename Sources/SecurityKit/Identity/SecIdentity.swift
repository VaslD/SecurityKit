import CryptoKit
import Foundation
import Security

/// Creates a new identity for a certificate and its associated private key.
///
/// - Parameters:
///   - certificate: The certificate for which you want to create an identity.
///   - privateKey: The associated private key.
/// - Returns: An identity object for the certificate and its associated private key.
public func SecIdentityCreateWithCertificate(_ certificate: SecCertificate,
                                             privateKey: SecKey) throws -> SecIdentity {
    guard let publicKeyFromCertificate = SecCertificateCopyKey(certificate),
          let publicKey = SecKeyCopyPublicKey(privateKey) else {
        throw SecError(errSecInternalError)
    }

    var error: Unmanaged<CFError>?
    let certificateKeyData = SecKeyCopyExternalRepresentation(publicKeyFromCertificate, &error)
    if let error = error?.takeRetainedValue() {
        throw error
    }
    let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error)
    if let error = error?.takeRetainedValue() {
        throw error
    }
    guard certificateKeyData! == publicKeyData! else {
        throw SecError(errSecPublicKeyInconsistent)
    }

    let hash = Insecure.SHA1.hash(data: certificateKeyData! as Data).withUnsafeBytes { Data($0) }

    if let identity = try? SecItemCopyIdentity(fingerprint: hash) {
        return identity
    }

    let certificateReference = try SecItemAddCertificate(certificate)
    let privateKeyReference = try {
        do {
            return try SecItemAddPrivateKey(privateKey)
        } catch {
            SecItemDelete([kSecValuePersistentRef: certificateReference] as CFDictionary)
            throw error
        }
    }()

    let identity = try {
        do {
            return try SecItemCopyIdentity(fingerprint: hash)
        } catch {
            SecItemDelete([kSecValuePersistentRef: certificateReference] as CFDictionary)
            SecItemDelete([kSecValuePersistentRef: privateKeyReference] as CFDictionary)
            throw error
        }
    }()

    SecItemDelete([kSecValuePersistentRef: certificateReference] as CFDictionary)
    SecItemDelete([kSecValuePersistentRef: privateKeyReference] as CFDictionary)
    return identity
}

public extension SecIdentity {
    /// Retrieves the common name of the subject of an identity.
    var commonName: String {
        get throws {
            try self.certificate.commonName
        }
    }

    /// Retrieves a certificate associated with an identity.
    var certificate: SecCertificate {
        get throws {
            var certificate: SecCertificate?
            let status = SecIdentityCopyCertificate(self, &certificate)
            guard status == errSecSuccess else {
                throw SecError(status)
            }
            return certificate!
        }
    }

    /// Retrieves the public key for a given identity.
    var publicKey: SecKey {
        get throws {
            try self.certificate.publicKey
        }
    }

    /// Retrieves the private key associated with an identity.
    var privateKey: SecKey {
        get throws {
            var key: SecKey?
            let status = SecIdentityCopyPrivateKey(self, &key)
            guard status == errSecSuccess else {
                throw SecError(status)
            }
            return key!
        }
    }
}
