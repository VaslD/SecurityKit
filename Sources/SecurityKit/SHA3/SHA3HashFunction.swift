import CryptoKit

protocol SHA3HashFunction: HashFunction {
    static var blockByteCount: Int { get }
    static var marker: UInt8 { get }
}
