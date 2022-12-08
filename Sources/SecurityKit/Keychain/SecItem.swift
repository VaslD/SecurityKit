import CryptoKit
import Foundation
import Security

@discardableResult
public func SecItemAddCertificate(_ certificate: SecCertificate) throws -> Data {
    var reference: CFTypeRef!
    let status = SecItemAdd([
        kSecValueRef: certificate,
        kSecReturnPersistentRef: true,
    ] as CFDictionary, &reference)
    guard status == errSecSuccess, CFGetTypeID(reference) == CFDataGetTypeID() else {
        throw SecError(status)
    }
    return reference as! Data
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
    var reference: CFTypeRef!
    let status = SecItemAdd([
        kSecAttrApplicationLabel: hash,
        kSecValueRef: key,
        kSecReturnPersistentRef: true,
    ] as CFDictionary, &reference)
    guard status == errSecSuccess, CFGetTypeID(reference) == CFDataGetTypeID() else {
        throw SecError(status)
    }
    return reference as! Data
}

public func SecItemCopyIdentity(fingerprint: Data) throws -> SecIdentity {
    var identity: CFTypeRef!
    let status = SecItemCopyMatching([
        kSecClass: kSecClassIdentity,
        kSecAttrApplicationLabel: fingerprint,
        kSecReturnRef: true,
    ] as CFDictionary, &identity)
    guard status == errSecSuccess, CFGetTypeID(identity) == SecIdentityGetTypeID() else {
        throw SecError(status)
    }
    return identity as! SecIdentity
}
