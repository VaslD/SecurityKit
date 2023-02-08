import CommonCrypto
import CryptoKit
import Foundation
import XCTest
@testable import SecurityKit

class AESTests: XCTestCase {
    func testAESDecryption() throws {
        let text =
            """
            tPgvmfytD8cn54LWgrrc
            yOJZ3IDYMyEqC1PsL06Y
            zoGJ6g0dzIA1WhLKJ0et
            dm0hvcuAUTK5TdaPaB7j
            bcU0ycGtVZKIZM3t77ec
            sqTDPdWn8akubylnfUqH
            z2BrP2JXCa55AYArZiZv
            RePB7o2EqXTryBfxBR6E
            rTxFb35DPNc7CS5kdsIW
            VABnvpoSBUWolUs0GzOD
            6uugl3J24GiDxQnHywTJ
            zes51wZ9X2j5Iz4EpOMk
            kqvEWuAKK3qm3Wy5hfzk
            g2JgE3cYCNTm1v4SidrF
            pngEn9U5tf0wjzoRBv0T
            z2EqPCoIGDtwH2raNpPZ
            jLezOUK1kJc5W8sm9geC
            GSFlXORp0qI0oLZVEMGy
            T9dVNzmAxl4wZWzB1rkx
            AQtdRNZhyQoqepeCSgFO
            5myti1A3u2jszzv6oLBR
            MJIgSl1AHuqUBDVk0GQZ
            sEoifMZNKcD3QZCyxzeI
            GFC3dJsrcE1UqgQELnKc
            esEzyH2N3hGtGHD9Jeqe
            4zxMThh27uE82451S1lT
            La0zvkZU6vnHV8LydEq2
            CIXtWVnZPKFurCMvKIOk
            tuNoxOWEL9GlaBN7ByPg
            jxq7UoAQyuUO1S4C3OqA
            ntBw1F3QhUDEBdge5IMu
            XbHrr7QnPSsApJgvm8Za
            ILrC61GFApRj7O20wQnt
            AzkJa4f3q4O5hv7Yl7s4
            rA0m9IafdtNJToa0T6Br
            38BnGY0WCpKZ05wnN4wJ
            RycaGouqRuF4QPHlTKnd
            8Va5VZXubQhcSiWI8ZOB
            QSeQPTuAoHTvT6LH80qG
            G3qliPnBYRwS7MV3xBPt
            E1lbTiu46P8RtLbKAJ2S
            FgthpW7MFLqBMABfu7LI
            ZhEvlcvAHzbb3WmQXxGM
            BUYaq7qi7xKv5HRnoTcm
            olej3HUhH3GtOONUJ1SO
            L3XbXuMM4xkPUVYLaBSd
            Q2AFtCOoYAi5HytkuQMt
            uuDjYbsb9SrSnk9h9XbW
            RUOeWLWtzUJrz9ZfPfv0
            63bO3BJyOKvedSGxWS9p
            """
        let key = SymmetricKey(data: "Yc0aUg98se1LBJQhj5sJU51w77UtCub1".data(using: .ascii)!)
        let data = "KA6VgzgSXTeYSzwx".data(using: .ascii)! + Data(base64Encoded:
            """
            fObxTwi0PRWFy4AyQhgRqpFNbKVevgytmKznwyrIXZZHwhOzHiwV40NhqafPe9r2ei6SkA2xPq1o+WTluW6Gc3zgWBnOSphWrqtuBkEtoo6f/wPwR50qV7lS7m6yhXKliYaibJjKyK6HWkcORQEs296lOxf3Y4wwAb5SpcLj6fYh9N0mUplxBtOzg/UM9Yf8+bpsVgjFCRExjcIWwuomXfH0c1ttLwqPziDdpYysErEwVoMARcTAOc9ZI734GAqahQtf1ppY/WS0bOeFHhItJyIWRKCmgeozGyqpG0qpvBgsnZtN+3oMAUE6mQqL7trNBijE6DMh58SluxLX6UJFyx7MfifZBpEZR25dVD0IpP+bH702VTGxXy2GL6nI2b+ZnHSfhSTyZ+AQDXXNB8HP5unxOEfEbmqWSvvgt7wAOYMr9yTbgy/614lfrVM8h5umzvHjY064nZGRaLQHyVf0sv2tC21xdbwWIAGilVz1FwPM0Ct3eb5/oGtI3jFj3a0OGcc43Zv76uKzAtuwQIJoH4HXJ6zLW21DzNjzMp0HQcXy7nD50lohhQZplFpaNxBMfIczBREkWLgexRrRo071anFs9GWO6OJeBWqpqK/WLn6AxfIHJC13oXilQRk03GgWiO63YaD7C829gJ/xqN6357alxJ7UO5l621CISQfpLaHcdO/55rKtkuElTxdrn/PWC0c8y+sAgVwEDb/5qetEaYJLHVA26uH+dgo+9IEs79hAf/ovbDA56YOWRNaIahhViiHdiZneZFbEdUMEyhL3409lkW9YuWk0Y2WGtZpjZQgvcLgJGA6LF9CZM2XVeaYPl/JfT7loxHokP/mUgi7DIcB3UBC97JCLMjpGY+28A9ePt0TwudM8urbp5i6Nmjc7x3QZrGkB9mqmzocNdWa8+/bP+4K5x6/Rlxny7kNyMhmCRLFpJmHe2vP5/d4jH0BiyouJTqoMR+ekZV6x+W27l3P7epw8+8f5WiP84TXYDMtsH69vMHbfTHcm6dyvfoyl7XoHPFTTQNWV5kZOAEUo677XCjYiJcJTqY6NvzirV2TgqNUNN4WV7VMUh2WVYPReZH6McPU8HeSaY31a3QCC9rz0QR/aiMGqNVfuxNWlmgk4Stiq+Kgy7UQSBc/Sqp5AkOk62BerXia7CQDVln2dlGeGD+WsKeCGAGaFrmvHCdBsAfZ6JMqBPjn0GFPjS1AoDXzERweq2BH3+yfdT2aAodXgXKQ4TMMyqo5JDOJ7+1Nb+7BWktMOhZB9nrDp7sTroFIRGI+57lQjRu5GnYloFUsfxwcQZSV5W57N5p7J4pOkTegXReAlqd7ZvqzerPa0LBaipgZRca2NhvH+FJYNlpbo+GvwuGxD/t9omjqICd8poFjUy0vyvbsVVIdvmFcm
            """
        )!

        let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: data.count)
        defer { buffer.deallocate() }
        XCTAssertEqual(data.copyBytes(to: buffer), data.count)

        let length = AES.CBC.decrypt(buffer, key: key)
        XCTAssert(length <= data.count)

        let bufferOut = UnsafeMutableBufferPointer(rebasing: buffer[..<length])
        XCTAssertEqual(text.data(using: .utf8)!, Data(bufferOut))
    }

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
