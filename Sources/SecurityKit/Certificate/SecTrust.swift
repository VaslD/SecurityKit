import Foundation
import Security

/// Creates a trust management object based on certificates and policies.
///
/// - Parameters:
///   - certificates: The certificate to be verified.
///   - intermediate: Other certificates you think might be useful for verifying the certificate.
///   - policies: References to one or more policies to be evaluated.
/// - Returns: The newly created trust management object.
public func SecTrustCreateWithCertificates(_ certificate: SecCertificate, _ intermediate: [SecCertificate] = [],
                                           policies: [SecPolicy] = [.default]) throws -> SecTrust {
    var trust: SecTrust?
    let status = SecTrustCreateWithCertificates(([certificate] + intermediate) as CFArray,
                                                policies as CFArray, &trust)
    guard status == errSecSuccess else {
        throw SecError(status)
    }
    return trust!
}

public extension SecTrust {
    // MARK: Evaluation

    /// Sets the anchor certificates used when evaluating a trust management object.
    ///
    /// - Parameter certificates: A reference to an array of `SecCertificate` objects representing
    ///                           the set of anchor certificates that are to be considered valid (trusted) anchors
    ///                           by the `SecTrustEvaluate(_:_:)` function when verifying a certificate. Pass `nil`
    ///                           to restore the default set of anchor certificates.
    func setAnchor(certificates: [SecCertificate]?) throws {
        let status = SecTrustSetAnchorCertificates(self, certificates as CFArray?)
        guard status == errSecSuccess else {
            throw SecError(status)
        }
    }

    /// Reenables trusting built-in anchor certificates.
    ///
    /// - Parameter isEnabled: If `false`, disables trusting any anchors other than the ones passed in with
    ///                        the `SecTrustSetAnchorCertificates(_:_:)` function.  If `true`, the built-in
    ///                        anchor certificates are also trusted.
    func setBuiltInAnchorsEnabled(_ isEnabled: Bool) throws {
        let status = SecTrustSetAnchorCertificatesOnly(self, !isEnabled)
        guard status == errSecSuccess else {
            throw SecError(status)
        }
    }

#if os(macOS)
    /// Evaluates trust for the specified certificate and policies.
    ///
    /// This method throws when trust evaluation fails.
    ///
    /// - Parameter options: The new set of option flags.
    func evaluate(_ options: SecTrustOptionFlags) async throws {
        let status = SecTrustSetOptions(self, options)
        guard status == errSecSuccess else {
            throw SecError(status)
        }
        try await self.evaluate()
    }
#endif

    /// Evaluates trust for the specified certificate and policies.
    ///
    /// This method throws when trust evaluation fails.
    ///
    func evaluate() async throws {
        let queue = DispatchQueue.global(qos: .userInitiated)
        try await withUnsafeThrowingContinuation { (continuation: UnsafeContinuation<Void, Error>) in
            queue.async {
                let status = SecTrustEvaluateAsyncWithError(self, queue) { _, isValid, error in
                    if let error = error {
                        continuation.resume(throwing: error)
                        return
                    }
                    guard isValid else {
                        continuation.resume(throwing: SecError(errSecNotTrusted))
                        return
                    }
                    continuation.resume()
                }

                if status == errSecSuccess {
                    return
                }

                continuation.resume(throwing: SecError(status))
            }
        }
    }

    // MARK: Properties

    /// Retrieves certificates in an evaluated certificate chain.
    var certificates: [SecCertificate] {
        get throws {
            let count = SecTrustGetCertificateCount(self)
            guard count > 0 else { return [] }

            return try (0..<count).map {
                guard let certificate = SecTrustGetCertificateAtIndex(self, $0) else {
                    throw SecError(errSecMissingValue)
                }
                return certificate
            }
        }
    }

    /// Retrieves the custom anchor certificates, if any, used by this trust.
    var anchors: [SecCertificate] {
        get throws {
            var array: CFArray?
            let status = SecTrustCopyCustomAnchorCertificates(self, &array)
            guard status == errSecSuccess else {
                throw SecError(status)
            }
            if let array = array as? [AnyObject] {
                return array as! [SecCertificate]
            }
            return []
        }
    }

    /// Retrieves the policies used by this trust management object.
    var policies: [SecPolicy] {
        get throws {
            var array: CFArray?
            let status = SecTrustCopyPolicies(self, &array)
            guard status == errSecSuccess else {
                throw SecError(status)
            }
            return (array! as [AnyObject]) as! [SecPolicy]
        }
    }
}
