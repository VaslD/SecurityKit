import CryptoKit
import Foundation
import Security

@discardableResult
public func SecItemAddCertificate(_ certificate: SecCertificate) throws -> Data {
    var reference: CFTypeRef?
    let status = SecItemAdd([
        kSecValueRef: certificate,
        kSecReturnPersistentRef: true,
    ] as CFDictionary, &reference)
    guard status == errSecSuccess, CFGetTypeID(reference) == CFDataGetTypeID() else {
        throw SecError(status)
    }
    return reference! as! Data
}

@discardableResult
public func SecItemAddPrivateKey(_ key: SecKey) throws -> Data {
    guard let publicKey = SecKeyCopyPublicKey(key) else {
        throw SecError(errSecInternalError)
    }

    var error: Unmanaged<CFError>?
    let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error)
    if let error = error?.takeRetainedValue() {
        throw error
    }

    let hash = Insecure.SHA1.hash(data: publicKeyData! as Data).withUnsafeBytes { Data($0) }
    var reference: CFTypeRef?
    let status = SecItemAdd([
        kSecAttrApplicationLabel: hash,
        kSecValueRef: key,
        kSecReturnPersistentRef: true,
    ] as CFDictionary, &reference)
    guard status == errSecSuccess, CFGetTypeID(reference) == CFDataGetTypeID() else {
        throw SecError(status)
    }
    return reference! as! Data
}

@discardableResult
public func SecItemAddIdentity(_ identity: SecIdentity) throws -> (certificateReference: Data, keyReference: Data) {
    var certificate: SecCertificate?
    var status = SecIdentityCopyCertificate(identity, &certificate)
    guard status == errSecSuccess else {
        throw SecError(status)
    }

    var key: SecKey?
    status = SecIdentityCopyPrivateKey(identity, &key)
    guard status == errSecSuccess else {
        throw SecError(status)
    }

    let certificateReference = try SecItemAddCertificate(certificate!)
    let keyReference = try {
        do {
            return try SecItemAddPrivateKey(key!)
        } catch {
            SecItemDelete([kSecValuePersistentRef: certificateReference] as CFDictionary)
            throw error
        }
    }()

    return (certificateReference, keyReference)
}

public func SecItemCopyIdentity(fingerprint: Data) throws -> SecIdentity {
    var identity: CFTypeRef?
    let status = SecItemCopyMatching([
        kSecClass: kSecClassIdentity,
        kSecAttrApplicationLabel: fingerprint,
        kSecReturnRef: true,
    ] as CFDictionary, &identity)
    guard status == errSecSuccess, CFGetTypeID(identity!) == SecIdentityGetTypeID() else {
        throw SecError(status)
    }
    return identity! as! SecIdentity
}
