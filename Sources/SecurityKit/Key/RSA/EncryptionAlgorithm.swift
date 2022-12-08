import Foundation
import Security

public extension SecRSAKey {
    enum EncryptionAlgorithm {
        case ECB
        case PKCS1
        case OAEPSHA1
        case OAEPSHA224
        case OAEPSHA256
        case OAEPSHA384
        case OAEPSHA512
        case OAEPSHA1AESGCM
        case OAEPSHA224AESGCM
        case OAEPSHA256AESGCM
        case OAEPSHA384AESGCM
        case OAEPSHA512AESGCM
    }
}

// MARK: - SecRSAKey.EncryptionAlgorithm + RawRepresentable

extension SecRSAKey.EncryptionAlgorithm: RawRepresentable {
    public var rawValue: SecKeyAlgorithm {
        switch self {
        case .ECB:
            return .rsaEncryptionRaw
        case .PKCS1:
            return .rsaEncryptionPKCS1
        case .OAEPSHA1:
            return .rsaEncryptionOAEPSHA1
        case .OAEPSHA224:
            return .rsaEncryptionOAEPSHA224
        case .OAEPSHA256:
            return .rsaEncryptionOAEPSHA256
        case .OAEPSHA384:
            return .rsaEncryptionOAEPSHA384
        case .OAEPSHA512:
            return .rsaEncryptionOAEPSHA512
        case .OAEPSHA1AESGCM:
            return .rsaEncryptionOAEPSHA1AESGCM
        case .OAEPSHA224AESGCM:
            return .rsaEncryptionOAEPSHA224AESGCM
        case .OAEPSHA256AESGCM:
            return .rsaEncryptionOAEPSHA256AESGCM
        case .OAEPSHA384AESGCM:
            return .rsaEncryptionOAEPSHA384AESGCM
        case .OAEPSHA512AESGCM:
            return .rsaEncryptionOAEPSHA512AESGCM
        }
    }

    public init?(rawValue: SecKeyAlgorithm) {
        switch rawValue {
        case .rsaEncryptionRaw:
            self = .ECB
        case .rsaEncryptionPKCS1:
            self = .PKCS1
        case .rsaEncryptionOAEPSHA1:
            self = .OAEPSHA1
        case .rsaEncryptionOAEPSHA224:
            self = .OAEPSHA224
        case .rsaEncryptionOAEPSHA256:
            self = .OAEPSHA256
        case .rsaEncryptionOAEPSHA384:
            self = .OAEPSHA384
        case .rsaEncryptionOAEPSHA512:
            self = .OAEPSHA512
        case .rsaEncryptionOAEPSHA1AESGCM:
            self = .OAEPSHA1AESGCM
        case .rsaEncryptionOAEPSHA224AESGCM:
            self = .OAEPSHA224AESGCM
        case .rsaEncryptionOAEPSHA256AESGCM:
            self = .OAEPSHA256AESGCM
        case .rsaEncryptionOAEPSHA384AESGCM:
            self = .OAEPSHA384AESGCM
        case .rsaEncryptionOAEPSHA512AESGCM:
            self = .OAEPSHA512AESGCM
        default:
            return nil
        }
    }
}
