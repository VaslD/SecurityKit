import Foundation
import Security

/// Identities and certificates in a PKCS #12-formatted blob.
public final class P12 {
    /// All identities contained in the PKCS #12 blob.
    public let identities: [SecIdentity]

    /// Trust management objects for certificates in the PKCS #12 blob.
    ///
    /// The trust reference returned by the `SecPKCS12Import(_:_:_:)` function has been evaluated against
    /// the basic X.509 policy and includes as complete a certificate chain as could be constructed
    /// from the certificates in the PKCS #12 blob, certificates on the keychain, and any other certificates
    /// available to the system.
    public let trusts: [SecTrust]

    /// Count the number of identities (and trusts) contained in the PKCS #12 blob.
    public var count: Int {
        self.identities.count
    }

    /// Import a PKCS #12–formatted blob (a file with extension *.p12*) containing certificates and identities.
    ///
    /// - Parameters:
    ///   - data: The PKCS #12 data you wish to decode.
    ///   - password: A passphrase to be used when importing from PKCS #12 format.
    public init<T: ContiguousBytes>(_ data: T, password: String) throws {
        let items = try data.withUnsafeBytes {
            let data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, $0.baseAddress!, $0.count, kCFAllocatorNull)!

            var array: CFArray?
            let status = SecPKCS12Import(data, [kSecImportExportPassphrase: password] as CFDictionary, &array)
            guard status == errSecSuccess else {
                throw SecError(status)
            }
            return (array! as [AnyObject]) as! [CFDictionary]
        }

        var identities = [SecIdentity]()
        var trusts = [SecTrust]()
        try items.forEach {
            let item = try Self.parse($0)
            identities.append(item.0)
            trusts.append(item.1)
        }
        self.identities = identities
        self.trusts = trusts
    }

    static func parse(_ properties: CFDictionary) throws -> (SecIdentity, SecTrust) {
        guard let dict = properties as? [CFString: Any] else {
            throw SecError(errSecParam)
        }

        guard let identity = dict[kSecImportItemIdentity] as? CFTypeRef,
              CFGetTypeID(identity) == SecIdentityGetTypeID() else {
            throw SecError(errSecMissingValue)
        }

        guard let trust = dict[kSecImportItemTrust] as? CFTypeRef,
              CFGetTypeID(trust) == SecTrustGetTypeID() else {
            throw SecError(errSecMissingValue)
        }

        return (identity as! SecIdentity, trust as! SecTrust)
    }
}
