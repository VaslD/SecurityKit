import Foundation
import XCTest
@testable import SecurityKit

final class P12Tests: XCTestCase {
    static let revoked = Data(base64Encoded:
        """
        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
        """, options: .ignoreUnknownCharacters)!

    func testP12Import() throws {
        XCTAssertNoThrow(try P12(Self.revoked, password: "YXRJS87ACU"))
    }

    /*
    func testTrustEvaluation() async throws {
        let bundle = try P12(Self.revoked, password: "YXRJS87ACU")
        for trust in bundle.trusts {
            try await trust.evaluate()
        }
    }
    */
}
