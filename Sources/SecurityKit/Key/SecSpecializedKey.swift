import Foundation
import Security

protocol SecSpecializedKey: AnyObject {
    var isPrivate: Bool { get }
    var rawKey: SecKey { get }
    var publicKey: Self { get throws }

    init(_ key: SecKey) throws
    init(_ data: some ContiguousBytes) throws

    func export() throws -> Data
}
