import Foundation
import Security

public extension SecRSAKey {
    struct KeySize: RawRepresentable {
        public var rawValue: Int

        public init(rawValue: Int) {
            self.rawValue = rawValue
        }

        public static let bits1024 = Self(rawValue: 1024)
        public static let bits2048 = Self(rawValue: 2048)
        public static let bits4096 = Self(rawValue: 4096)
    }
}
