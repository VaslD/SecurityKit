import Foundation
import XCTest
@testable import SecurityKit

final class P12Tests: XCTestCase {
    func testP12Import() throws {
        XCTAssertNoThrow(try P12(
            Data(contentsOf: URL(fileURLWithPath: "/Users/yi.ding5/Desktop/Yi Ding (yi.ding5@nio.com).p12")),
            password: "dingyi691502"
        ))
    }

    func testTrustEvaluation() async throws {
        let bundle = try P12(
            Data(contentsOf: URL(fileURLWithPath: "/Users/yi.ding5/Desktop/Yi Ding (yi.ding5@nio.com).p12")),
            password: "dingyi691502"
        )
        for trust in bundle.trusts {
            try await trust.evaluate()
        }
    }
}
