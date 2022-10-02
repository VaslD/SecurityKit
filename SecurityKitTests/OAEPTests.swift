import CryptoKit
import XCTest
@testable import SecurityKit

final class OAEPTests: XCTestCase {
    func testMGF1() throws {
        // https://en.wikipedia.org/wiki/Mask_generation_function#Example_code

        XCTAssertEqual(
            try OAEP.MGF1(seed: "foo".data(using: .ascii)!, len: 3,
                          Hash: Insecure.SHA1.self).asHexString(uppercased: false),
            "1ac907"
        )
        XCTAssertEqual(
            try OAEP.MGF1(seed: "foo".data(using: .ascii)!, len: 5,
                          Hash: Insecure.SHA1.self).asHexString(uppercased: false),
            "1ac9075cd4"
        )
        XCTAssertEqual(
            try OAEP.MGF1(seed: "bar".data(using: .ascii)!, len: 5,
                          Hash: Insecure.SHA1.self).asHexString(uppercased: false),
            "bc0c655e01"
        )
        XCTAssertEqual(
            try OAEP.MGF1(seed: "bar".data(using: .ascii)!, len: 50,
                          Hash: Insecure.SHA1.self).asHexString(uppercased: false),
            "bc0c655e016bc2931d85a2e675181adcef7f581f76df2739da74faac41627be2f7f415c89e983fd0ce80ced9878641cb4876"
        )
        XCTAssertEqual(
            try OAEP.MGF1(seed: "bar".data(using: .ascii)!, len: 50,
                          Hash: SHA256.self).asHexString(uppercased: false),
            "382576a7841021cc28fc4c0948753fb8312090cea942ea4c4e735d10dc724b155f9f6069f289d61daca0cb814502ef04eae1"
        )
    }

    func testOAEP() throws {
        let privateKey = try SecRSAKey(Data(
            base64Encoded:
                """
                MIIEpAIBAAKCAQEAvh+KGNR+Foqbjnei1oV9FEpL8FTp7a00MzBBSZo9DilBUO+E
                NPk1TivDiUlBTJ/80hArI++ZWj4YEyQT5G7BzAF1kixNgaSntCqqRr4LsZTI0PYy
                wQSO9Y/6JhKyM3BIQdNUMTyTWO/1LQqLiaYdtPUC/N0Hmhf6EKRIkEuZNcn9ClPK
                c0E77taE8D2PE8P3cQuOVyHVLSgpOH0T620O4XR6UbKIOqYMNXzpqaNp8mZqrkBZ
                mDQB9cz1AOqC4bWQVj6eyzBQpcIyTIXL/H4Vrvi4zijhJq2j5LYAOxMQ8t7d2uS6
                spHwmuzU3p1J1OdjHiFoykg6t6Ij//rCZT8IHwIDAQABAoIBADtF+ffjx6ufav/v
                rITU+TnqL+KtloDTDwMmeDRKMd7IXeStx7n8N/I3Eq8qd4E8H8Yd5FU/zb+kvDy7
                crg1D5Zanh0EUuWoP+CbrJqBhYPHrxP2rbwff7JvQL299nCzANQE3qq7B/UiWn3A
                W+B+OaTA/j13a3dPIlct4LGb4Bg0ZvKa8kcZP6fO+RHx8aJqg9yw4SRDqfs98VKw
                WNfGetkFuyEQ4ZonpVRDhKqaoZabJWgXC1nCfxnq6aMzpEWaQkWJnSUs3jxZa0QG
                xYAsh8S0NJmi06fJSLJ7l7YFFlCNMdkczNmB+ecKZzfu5Z6LmmVAmI6r7oB7BF4a
                9Ts5XoECgYEA7/8G50HJAdpUknXtcgRvWMKVFIDBQPAo3oypu50lsVpkhHNEP1eR
                yQiM6wkTlebnI+EZnspMr00jVky6c09sLpz2jIFt5MdCktDOUixgtOAT3KuVi+b9
                HkdnGSR33IEpcVjGG4JgS0Zw97PFuYud56eVm8f625V+T1tl8DNa2CUCgYEAys0h
                hlmeoekF2Ge7Ue3me7WezCqDruoamT9ZtzoKMG2YbaoofN70MZXfcbhtMdlrrjQJ
                awHaLmsxfnOrqDawubuJyrxNgTQ0JqHHy4SDHglH+dTmj9p9mLZQLaIsZBXZenZP
                D5Kjq6HPrqEK6iD6L0YYW41fP7RdGrFre4OzWfMCgYEAxd1sw5zpLC3lLBst+KLP
                ak6CurSsn+1gxJsUFSoquV3dIZYm3lJET4pNJDoHe78zMdGUXeZL8vuV9sCruAXz
                GzstygmroMLnkEO21ujfkkBsH7MXSJDYfu4/gesfJx0WHe0i5+tFmMoquQ3uJluF
                hEgWgKkPmZpW2PZxxOeSLkECgYB/bsibIGNiwAcRRZVaVRAYOjbPegOG/Mm79CfO
                z6Spa6R1fI+2b26oXdGrJsVOpp1YOJCWcfKEao0ONWbu63a/Ls3V298jygbfI5dl
                Fh5B2HkmzpYWXKfBNwZItngIaAZhQkhJs84uwh27UKyIFDLBU91oYfwxDofWhxfP
                5CDl6wKBgQCAvj9qLiavw29fBhfWpmneJbVJvxv2Tg8ilVsU+Ge8Cq7OS/i7ZM1Z
                IC0GDtdkTkb7EGNcQxKUfzUcwP1TCyLLwir501mSM9mPRmqI/vQ9YQRtoyDcjnGm
                XWyA59tz6EAHbT1Ym4qu0BSso4osXlg08tM4gXTFx+9E0QDik96f6w==
                """,
            options: .ignoreUnknownCharacters
        )!)

        let data = try Data(randomBytes: 10)
        var dataOAEP = try OAEP.pad(data, with: Insecure.SHA1.self, andMGF1Padding: Insecure.SHA1.self,
                                    for: privateKey.rawKey)
        var encrypted = try privateKey.encrypt(block: dataOAEP, algorithm: .ECB)
        var decrypted = try privateKey.decrypt(block: encrypted, algorithm: .OAEPSHA1)
        XCTAssertEqual(data, decrypted)

        dataOAEP = try OAEP.pad(data, with: SHA256.self, andMGF1Padding: SHA256.self, for: privateKey.rawKey)
        encrypted = try privateKey.encrypt(block: dataOAEP, algorithm: .ECB)
        decrypted = try privateKey.decrypt(block: encrypted, algorithm: .OAEPSHA256)
        XCTAssertEqual(data, decrypted)
    }
}
