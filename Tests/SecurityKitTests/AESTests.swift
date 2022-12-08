import CommonCrypto
import CryptoKit
import Foundation
import XCTest
@testable import SecurityKit

class AESTests: XCTestCase {
    func testAESRoundtripUnmanaged() throws {
        let data = try Data(randomBytes: 1000)

        let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: 2000)
        defer { buffer.deallocate() }
        XCTAssertEqual(data.copyBytes(to: buffer), 1000)
        
        let key = SymmetricKey(size: .bits256)
        let length = AES.CBC.encrypt(buffer, size: 1000, key: key)
        XCTAssert(length <= 1000 + 32)
        
        let bufferOut = UnsafeMutableBufferPointer(rebasing: buffer[..<length])
        XCTAssertEqual(AES.CBC.decrypt(bufferOut, key: key), 1000)

        XCTAssertEqual(data, Data(buffer[..<1000]))
    }
    
    func testAESRoundtripManaged() throws {
        let data = try Data(randomBytes: 1000)
        
        let key = SymmetricKey(size: .bits256)
        let cipherText = AES.CBC.encrypt(data, key: key) { Data($0!) }

        XCTAssertEqual(data, AES.CBC.decrypt(cipherText, key: key) { Data($0!) })
    }
}
