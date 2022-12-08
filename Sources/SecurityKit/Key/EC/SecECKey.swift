import Foundation
import Security

@available(*, deprecated, message: "Use CryptoKit.")
public final class SecECKey: SecSpecializedKey {
    public let isPrivate: Bool

    public let rawKey: SecKey

    public init(_ key: SecKey) throws {
        guard let attributes = SecKeyCopyAttributes(key) as? [CFString: Any] else {
            throw SecError(errSecMissingAttributeKeyType)
        }
        let type = attributes[kSecAttrKeyType] as AnyObject
        guard CFGetTypeID(type) == CFStringGetTypeID(),
              (type as! CFString) == kSecAttrKeyTypeEC else {
            throw SecError(errSecInvalidAttributeKeyType)
        }

        let keyClass = attributes[kSecAttrKeyClass] as AnyObject
        guard CFGetTypeID(keyClass) == CFStringGetTypeID() else {
            throw SecError(errSecInvalidAttributeKey)
        }

        self.isPrivate = (keyClass as! CFString) == kSecAttrKeyClassPrivate
        self.rawKey = key
    }

    public var publicKey: SecECKey {
        get throws {
            guard self.isPrivate else {
                return self
            }
            guard let key = SecKeyCopyPublicKey(self.rawKey) else {
                throw SecError(errSecInternalError)
            }
            return try SecECKey(key)
        }
    }

    // MARK: Export

    public init<T: ContiguousBytes>(_ data: T) throws {
        var keyClass: CFString?
        let key: SecKey = try data.withUnsafeBytes {
            let data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, $0.baseAddress!, $0.count, kCFAllocatorNull)!

            if let privateKey = SecKeyCreateWithData(data, [
                kSecAttrKeyType: kSecAttrKeyTypeEC,
                kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            ] as CFDictionary, nil) {
                keyClass = kSecAttrKeyClassPrivate
                return privateKey
            }

            var error: Unmanaged<CFError>?
            let publicKey = SecKeyCreateWithData(data, [
                kSecAttrKeyType: kSecAttrKeyTypeEC,
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

    public func export() throws -> Data {
        var error: Unmanaged<CFError>?
        let data = SecKeyCopyExternalRepresentation(self.rawKey, &error)
        if let error = error?.takeRetainedValue() {
            throw error
        }
        return data! as Data
    }
}
