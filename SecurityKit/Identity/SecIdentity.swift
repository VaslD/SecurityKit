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

    var returnValue: CFTypeRef?
    var status = SecItemAdd([
        kSecValueRef: certificate,
        kSecReturnPersistentRef: true,
    ] as CFDictionary, &returnValue)
    guard status == errSecSuccess, CFGetTypeID(returnValue) == CFDataGetTypeID() else {
        throw SecError(status)
    }
    let certificateReference = returnValue! as! CFData

    status = SecItemAdd([
        kSecAttrApplicationLabel: hash,
        kSecValueRef: privateKey,
        kSecReturnPersistentRef: true,
    ] as CFDictionary, &returnValue)
    guard status == errSecSuccess, CFGetTypeID(returnValue) == CFDataGetTypeID() else {
        SecItemDelete([kSecValuePersistentRef: certificateReference] as CFDictionary)
        throw SecError(status)
    }
    let privateKeyReference = returnValue! as! CFData

    status = SecItemCopyMatching([
        kSecClass: kSecClassIdentity,
        kSecAttrApplicationLabel: hash,
        kSecReturnRef: true,
    ] as CFDictionary, &returnValue)
    guard status == errSecSuccess, CFGetTypeID(returnValue) == SecIdentityGetTypeID() else {
        SecItemDelete([kSecValuePersistentRef: certificateReference] as CFDictionary)
        SecItemDelete([kSecValuePersistentRef: privateKeyReference] as CFDictionary)
        throw SecError(status)
    }

    SecItemDelete([kSecValuePersistentRef: certificateReference] as CFDictionary)
    SecItemDelete([kSecValuePersistentRef: privateKeyReference] as CFDictionary)

    return returnValue! as! SecIdentity
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
