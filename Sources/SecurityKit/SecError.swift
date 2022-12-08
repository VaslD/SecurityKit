import Foundation
import Security

/// ``SecError`` wraps `OSStatus` return codes from Security framework as if they were thrown as errors from
/// `kCFErrorDomainOSStatus` domain.
public struct SecError: RawRepresentable {
    public let rawValue: OSStatus

    public init(_ status: OSStatus) {
        self.init(rawValue: status)
    }

    public init(rawValue: OSStatus) {
        self.rawValue = rawValue
    }
}

// MARK: LocalizedError

extension SecError: LocalizedError {
    public var errorDescription: String? {
        SecCopyErrorMessageString(self.rawValue, nil) as String?
    }
}
