import Foundation
import Security

/// A value indicating the item's algorithm.
public enum SecAttrKeyType {
    /// RSA algorithm.
    case RSA
    
    /// Elliptic curve algorithm.
    case EC
}

// MARK: RawRepresentable

extension SecAttrKeyType: RawRepresentable {
    public var rawValue: CFString {
        switch self {
        case .RSA:
            return kSecAttrKeyTypeRSA
        case .EC:
            return kSecAttrKeyTypeECSECPrimeRandom
        }
    }

    public init?(rawValue: CFString) {
        switch rawValue {
        case kSecAttrKeyTypeRSA:
            self = .RSA
        case kSecAttrKeyTypeECSECPrimeRandom:
            self = .EC
        default:
            return nil
        }
    }
}

// MARK: CustomStringConvertible

extension SecAttrKeyType: CustomStringConvertible {
    public var description: String {
        switch self {
        case .RSA:
            return "kSecAttrKeyTypeRSA"
        case .EC:
            return "kSecAttrKeyTypeECSECPrimeRandom"
        }
    }
}

// MARK: _ObjectiveCBridgeable

extension SecAttrKeyType: _ObjectiveCBridgeable {
    public typealias _ObjectiveCType = CFString

    public func _bridgeToObjectiveC() -> CFString {
        self.rawValue
    }

    public static func _forceBridgeFromObjectiveC(_ source: CFString, result: inout SecAttrKeyType?) {
        result = Self(rawValue: source)
    }

    public static func _conditionallyBridgeFromObjectiveC(_ source: CFString, result: inout SecAttrKeyType?) -> Bool {
        if let value = Self(rawValue: source) {
            result = value
            return true
        }
        return false
    }

    public static func _unconditionallyBridgeFromObjectiveC(_ source: CFString?) -> SecAttrKeyType {
        Self(rawValue: source!)!
    }
}
