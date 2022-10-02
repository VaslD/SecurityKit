import Foundation
import Security

public extension SecRSAKey.SignatureAlgorithm {
    enum RSASignatureAlgorithm {
        case PKCS1v1_5(RSASignatureHashAlgorithm)
        case PSS(RSASignatureHashAlgorithm)
    }
}
