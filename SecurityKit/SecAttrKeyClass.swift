import Foundation
import Security

/// A value indicating the item's cryptographic key class.
public enum SecAttrKeyClass {
    /// A public key of a public-private pair.
    case publicKey
    
    /// A private key of a public-private pair.
    case privateKey
}

// MARK: RawRepresentable

extension SecAttrKeyClass: RawRepresentable {
    public var rawValue: CFString {
        switch self {
        case .publicKey:
            return kSecAttrKeyClassPublic
        case .privateKey:
            return kSecAttrKeyClassPrivate
        }
    }

    public init?(rawValue: CFString) {
        switch rawValue {
        case kSecAttrKeyClassPublic:
            self = .publicKey
        case kSecAttrKeyClassPrivate:
            self = .privateKey
        default:
            return nil
        }
    }
}

// MARK: CustomStringConvertible

extension SecAttrKeyClass: CustomStringConvertible {
    public var description: String {
        switch self {
        case .publicKey:
            return "kSecAttrKeyClassPublic"
        case .privateKey:
            return "kSecAttrKeyClassPrivate"
        }
    }
}

// MARK: _ObjectiveCBridgeable

extension SecAttrKeyClass: _ObjectiveCBridgeable {
    public typealias _ObjectiveCType = CFString

    public func _bridgeToObjectiveC() -> CFString {
        self.rawValue
    }

    public static func _forceBridgeFromObjectiveC(_ source: CFString, result: inout SecAttrKeyClass?) {
        result = Self(rawValue: source)
    }

    public static func _conditionallyBridgeFromObjectiveC(_ source: CFString, result: inout SecAttrKeyClass?) -> Bool {
        if let value = Self(rawValue: source) {
            result = value
            return true
        }
        return false
    }

    public static func _unconditionallyBridgeFromObjectiveC(_ source: CFString?) -> SecAttrKeyClass {
        Self(rawValue: source!)!
    }
}
