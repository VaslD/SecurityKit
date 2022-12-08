import Foundation
import Security

public extension SecRSAKey.SignatureAlgorithm {
    enum RSASignatureHashAlgorithm {
        case SHA1
        case SHA224
        case SHA256
        case SHA384
        case SHA512
    }
}
