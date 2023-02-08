import Foundation
import Security

/// ``SecError`` wraps return codes from Security framework to interoperate with Swift error handling.
public struct SecError: RawRepresentable {
    public let rawValue: OSStatus

    public init(_ status: OSStatus) {
        self.init(rawValue: status)
    }

    public init(rawValue: OSStatus) {
        self.rawValue = rawValue
    }
}

// At this moment, I’m not sure if "errSec"s are really error codes from kCFErrorDomainOSStatus.
// If anyone can confirm, we can enable CustomNSError conformance below.

// extension SecError: CustomNSError {
//     public static var errorDomain: String {
//         kCFErrorDomainOSStatus as String
//     }
//
//     public var errorCode: Int {
//         Int(self.rawValue)
//     }
// }


// MARK: LocalizedError

extension SecError: LocalizedError {
    public var errorDescription: String? {
        SecCopyErrorMessageString(self.rawValue, nil) as String?
    }
}
