import Foundation
import Security

// MARK: - SecRSAKey.SignatureAlgorithm

public extension SecRSAKey {
    enum SignatureAlgorithm {
        case raw
        case digest(RSASignatureAlgorithm)
        case message(RSASignatureAlgorithm)
    }
}

// MARK: - SecRSAKey.SignatureAlgorithm + RawRepresentable

extension SecRSAKey.SignatureAlgorithm: RawRepresentable {
    public var rawValue: SecKeyAlgorithm {
        switch self {
        case .raw:
            return .rsaSignatureRaw
        case .digest(.PKCS1v1_5(.SHA1)):
            return .rsaSignatureDigestPKCS1v15SHA1
        case .digest(.PKCS1v1_5(.SHA224)):
            return .rsaSignatureDigestPKCS1v15SHA224
        case .digest(.PKCS1v1_5(.SHA256)):
            return .rsaSignatureDigestPKCS1v15SHA256
        case .digest(.PKCS1v1_5(.SHA384)):
            return .rsaSignatureDigestPKCS1v15SHA384
        case .digest(.PKCS1v1_5(.SHA512)):
            return .rsaSignatureDigestPKCS1v15SHA512
        case .digest(.PSS(.SHA1)):
            return .rsaSignatureDigestPSSSHA1
        case .digest(.PSS(.SHA224)):
            return .rsaSignatureDigestPSSSHA224
        case .digest(.PSS(.SHA256)):
            return .rsaSignatureDigestPSSSHA256
        case .digest(.PSS(.SHA384)):
            return .rsaSignatureDigestPSSSHA384
        case .digest(.PSS(.SHA512)):
            return .rsaSignatureDigestPSSSHA512
        case .message(.PKCS1v1_5(.SHA1)):
            return .rsaSignatureMessagePKCS1v15SHA1
        case .message(.PKCS1v1_5(.SHA224)):
            return .rsaSignatureMessagePKCS1v15SHA224
        case .message(.PKCS1v1_5(.SHA256)):
            return .rsaSignatureMessagePKCS1v15SHA256
        case .message(.PKCS1v1_5(.SHA384)):
            return .rsaSignatureMessagePKCS1v15SHA384
        case .message(.PKCS1v1_5(.SHA512)):
            return .rsaSignatureMessagePKCS1v15SHA512
        case .message(.PSS(.SHA1)):
            return .rsaSignatureMessagePSSSHA1
        case .message(.PSS(.SHA224)):
            return .rsaSignatureMessagePSSSHA224
        case .message(.PSS(.SHA256)):
            return .rsaSignatureMessagePSSSHA256
        case .message(.PSS(.SHA384)):
            return .rsaSignatureMessagePSSSHA384
        case .message(.PSS(.SHA512)):
            return .rsaSignatureMessagePSSSHA512
        }
    }

    public init?(rawValue: SecKeyAlgorithm) {
        switch rawValue {
        case .rsaSignatureRaw:
            self = .raw
        case .rsaSignatureDigestPKCS1v15SHA1:
            self = .digest(.PKCS1v1_5(.SHA1))
        case .rsaSignatureDigestPKCS1v15SHA224:
            self = .digest(.PKCS1v1_5(.SHA224))
        case .rsaSignatureDigestPKCS1v15SHA256:
            self = .digest(.PKCS1v1_5(.SHA256))
        case .rsaSignatureDigestPKCS1v15SHA384:
            self = .digest(.PKCS1v1_5(.SHA384))
        case .rsaSignatureDigestPKCS1v15SHA512:
            self = .digest(.PKCS1v1_5(.SHA512))
        case .rsaSignatureDigestPSSSHA1:
            self = .digest(.PSS(.SHA1))
        case .rsaSignatureDigestPSSSHA224:
            self = .digest(.PSS(.SHA224))
        case .rsaSignatureDigestPSSSHA256:
            self = .digest(.PSS(.SHA256))
        case .rsaSignatureDigestPSSSHA384:
            self = .digest(.PSS(.SHA384))
        case .rsaSignatureDigestPSSSHA512:
            self = .digest(.PSS(.SHA512))
        case .rsaSignatureMessagePKCS1v15SHA1:
            self = .message(.PKCS1v1_5(.SHA1))
        case .rsaSignatureMessagePKCS1v15SHA224:
            self = .message(.PKCS1v1_5(.SHA224))
        case .rsaSignatureMessagePKCS1v15SHA256:
            self = .message(.PKCS1v1_5(.SHA256))
        case .rsaSignatureMessagePKCS1v15SHA384:
            self = .message(.PKCS1v1_5(.SHA384))
        case .rsaSignatureMessagePKCS1v15SHA512:
            self = .message(.PKCS1v1_5(.SHA512))
        case .rsaSignatureMessagePSSSHA1:
            self = .message(.PSS(.SHA1))
        case .rsaSignatureMessagePSSSHA224:
            self = .message(.PSS(.SHA224))
        case .rsaSignatureMessagePSSSHA256:
            self = .message(.PSS(.SHA256))
        case .rsaSignatureMessagePSSSHA384:
            self = .message(.PSS(.SHA384))
        case .rsaSignatureMessagePSSSHA512:
            self = .message(.PSS(.SHA512))
        default:
            return nil
        }
    }
}
