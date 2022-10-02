import Security

/// Creates a certificate object from a DER representation of a certificate.
///
/// - Parameter data: A DER (Distinguished Encoding Rules) representation of an X.509 certificate.
/// - Returns: The newly created certificate instance.
public func SecCertificateCreateWithData<T: ContiguousBytes>(_ data: T) throws -> SecCertificate {
    guard let certificate = data.withUnsafeBytes({
        let data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, $0.baseAddress!, $0.count, kCFAllocatorNull)!
        return SecCertificateCreateWithData(kCFAllocatorDefault, data)
    }) else {
        throw SecError(errSecParam)
    }
    return certificate
}

public func SecCertificateCreateFromPEMDocument<T: StringProtocol>(_ document: T) throws -> SecCertificate {
    let lines = document.split(whereSeparator: \.isNewline)
    guard lines.first == "-----BEGIN CERTIFICATE-----", lines.last == "-----END CERTIFICATE-----" else {
        throw SecError(errSecParam)
    }
    let base64 = lines.dropFirst().dropLast().joined()
    guard let data = Data(base64Encoded: base64, options: .ignoreUnknownCharacters) else {
        throw SecError(errSecParam)
    }
    return try SecCertificateCreateWithData(data)
}

public extension SecCertificate {
    // MARK: - Properties

    /// Retrieves the common name of the subject of a certificate.
    var commonName: String {
        get throws {
            var name: CFString?
            let status = SecCertificateCopyCommonName(self, &name)
            guard status == errSecSuccess else {
                throw SecError(status)
            }
            return name! as String
        }
    }

    /// Retrieves the email addresses for the subject of a certificate.
    var emailAddress: [String] {
        get throws {
            var emails: CFArray?
            let status = SecCertificateCopyEmailAddresses(self, &emails)
            guard status == errSecSuccess else {
                throw SecError(status)
            }
            return (emails! as [AnyObject]).map { $0 as! String }
        }
    }

    /// Returns the certificate’s serial number.
    var serialNumber: String {
        get throws {
            var error: Unmanaged<CFError>?
            let data = SecCertificateCopySerialNumberData(self, &error)
            if let error = error?.takeRetainedValue() {
                throw error
            }
            return (data! as Data).asHexString()
        }
    }

    /// Retrieves the public key for a given certificate.
    var publicKey: SecKey {
        get throws {
            guard let key = SecCertificateCopyKey(self) else {
                throw SecError(errSecInternalError)
            }
            return key
        }
    }

    // MARK: - Trust

    /// Evaluates trust for the specified certificate and policies.
    ///
    /// - Parameter policies: References to one or more policies to be evaluated.
    func evaluateTrust(policies: [SecPolicy] = [.default]) async throws {
        try await SecTrustCreateWithCertificates(self, policies: policies).evaluate()
    }

    /// Evaluates trust for the specified certificate and policies.
    ///
    /// - Parameters:
    ///   - certificates: Other certificates you think might be useful for verifying the certificate.
    ///   - policies: References to one or more policies to be evaluated.
    func evaluateTrust(intermediate certificates: [SecCertificate],
                       policies: [SecPolicy] = [.default]) async throws {
        let trust = try SecTrustCreateWithCertificates(self, certificates, policies: policies)
        try await trust.evaluate()
    }

    /// Evaluates trust for the specified certificate and policies.
    ///
    /// - Parameters:
    ///   - certificates: Other certificates you think might be useful for verifying the certificate.
    ///   - anchors: A reference to an array of `SecCertificate` objects representing the set of anchor certificates
    ///              that are to be considered valid (trusted) anchors by the `SecTrustEvaluate(_:_:)` function
    ///              when verifying a certificate.
    ///   - trustSystemAnchors: If `false`, disables trusting any anchors other than the ones passed in with
    ///                         the `SecTrustSetAnchorCertificates(_:_:)` function. If `true`, the built-in
    ///                         anchor certificates are also trusted.
    ///   - policies: References to one or more policies to be evaluated.
    func evaluateTrust(intermediate certificates: [SecCertificate],
                       anchors: [SecCertificate], trustBuiltInAnchors: Bool = true,
                       policies: [SecPolicy] = [.default]) async throws {
        let trust = try SecTrustCreateWithCertificates(self, certificates, policies: policies)
        try trust.setAnchor(certificates: anchors)
        try trust.setBuiltInAnchorsEnabled(trustBuiltInAnchors)
        try await trust.evaluate()
    }

    // MARK: - Export

    /// Returns a DER representation of a certificate given a certificate object.
    func export() -> Data {
        SecCertificateCopyData(self) as Data
    }
}
