import XCTest

@testable import SecurityKit

final class SecKeyTests: XCTestCase {
    func testCFBridging() {
        let dict = [
            kSecAttrKeyType: SecAttrKeyType.RSA,
            kSecAttrKeyClass: SecAttrKeyClass.publicKey,
        ] as CFDictionary
        XCTAssertNotNil(dict as? [String: String])
        XCTAssertEqual(dict, [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
        ] as CFDictionary)
    }

    func testKeyImport() throws {
        XCTAssertNoThrow(try SecKey.import(.RSA, .publicKey, Data(
            base64Encoded:
            """
            MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCK8VCMlISQdrpU+TtnzzNbfcNE
            zKf0+uNzxRtZ4Lx8XzEJ6X2pTk9+ZG3p7Py0WgHUWanRfbOnColeLRsIffhbR9gf
            3wvOKZoEgNIagl3o1uQ0ogMTVzZ5H+c/bLntwZw8bhUv9A6ep4CS3oBrAQq47O+W
            CFsSLX5A4coaB1xeYwIDAQAB
            """,
            options: .ignoreUnknownCharacters
        )!))

        XCTAssertNoThrow(try SecKey.import(.RSA, .privateKey, Data(
            base64Encoded:
            """
            MIIEogIBAAKCAQEA8+P+WrzmCMdRjUdK1yvYiHjl0sRKRXWzRCnmkbwyHQywOKGL
            JYVdcQTnvOoPu9xcY4/RR7VqSJozT8pnNtu9CuaDSFBzEqZOLz80etoRZRpl8APl
            z5FWdWb2P2EGMi3bDGry6eYZHiEAmrbROrJ+4HBUZhP7VKx8jj675Wycv0ISpvfm
            F7eJ1rkl3x3Q7J64NmEBjEs2Poab3iaDTSsIBlgj7YCn7LObwWHV1KCfqrEgVU4Z
            f8tg4TuUUUaRfAO9yl4CNCZyg2wpJsXFqbc72ZUUJBOeBoHloQHZcCWcFNBvy3Eu
            b6VcigtOab5rrzUokV5zZJqcXVEjymvNxUilMwIDAQABAoIBAFW2MpXA/TbolYiJ
            HYwxJJARrPM9eLygeLfj4dwlv5bl9qhwXW56SDSH/MkvmQf0kaOLz4jcANYzGwVX
            pJ5q6y0BhfHMFCThvWhtVgw2xxY5CMopFIK2GSR5YuEzP/Iym2Dp1STOcNVd09CL
            n0x5no1R7NdS/mjrlXqIIZCncw7jgfjjGWn0/mfd9FlmiPVITQ2U92jp/qlUuLvf
            v5TVaXrfaxuv/7yqqioQM0qcum/PHe7aci/gfa/nM6LEm4iiZjHepIFPACTqGa8Q
            sBbk3Gu7xbSmsRl5REVqeNnsDdehjRJGfgd+d6Kb+uikF1Y22Db968P0upUOVCeT
            O5XEBcECgYEA+ulKc1bU8VuOzdTOAuZBCrCOmxQwOoOkFB5MzrbSx1HvKAAyiEDN
            1zt5CmB3C+++d/xLvr8/G1ntr6q3Su2lpofmJXU7WVFNqmXCCc4ITj7BupHnL63e
            n4V/r2/cPUdQ//vOiHXKx4i4/GVkf/h2m4q9RggUsF2r8Fy/4WkkwH0CgYEA+NZA
            fvfa8cqceFNIZfJBjZ/DlYgBpVoaQpAvHnCWVmXiSwfyUgmA21KqUETEmNZRYdtc
            gfCfruTh572tFSW7YXXPYJ1EiRosvOVbPYH/RlcRC1Ef1FXa36/AbVp8Uu94ze9A
            TLkR/R5E68v8u6vqlWiNDPlIfpuC9A1KE4/8G28CgYAxePI/D63o8P6VQxJjq/bD
            HtDfbvmbb/1YIilO0Ol6d4NKRc+w4eY0O/u/ugl/BwRtMAfXUmolAHRHIMgHNBhn
            X4BXfmf3UnqX0HyT5lXo56LXIJGO6x9sIKxucQXh5z/nWUT9zwvuj9y5l1xbhygL
            vy1Ws50wsSeHuyHyVgLzGQKBgAQ60BnYaLZXdVVuRPrGpWqc3pw6FZ0T7QJYpRRl
            YYjSbohL+EiAtNoFi7OVl6nparS5H9dtmalFZrmjtb94RrkfYYkI41NZSI1lcKmY
            /hfZ/wYsONhJJVFMEX9KXHakb29As90aAD5HN3CypPcjsvcbMdqYmizcw9sWJr4y
            YlytAoGAD4Uh+rTVdZPoz/8iJ8MWyua32w2JB6fw1VbFeklMrYb6NqdJo9lgE4Nh
            +tl9RK3B1EPyK+ScmOGYNkhJxbet8BUtpCC+w+QgOcwckxYxi+R+pPt5QqZLlspk
            ybwWnFUXw4Z0lCVKcju3tX4nKGphCnhUR63CTt7Q2gQx4297cn8=
            """,
            options: .ignoreUnknownCharacters
        )!))
    }

    func testKeyAttributes() throws {
        let key = try SecKey.import(.RSA, .privateKey, Data(
            base64Encoded:
            """
            MIICWwIBAAKBgQCn33EwfzV6y08ZagXt9n4swfo9gWzOY0BvcVYwChJwkkkgQou3
            OMxYXQH6qmy5UaWOoCD5DMxNjo9hsg4y1NF2vVBZIc5LlX0PHBqQqbgs7HNTcuKs
            Fzx1jY80lCQhZQbWBB92yvxPVUzeHvOtlvKsc04jEq74OpWLQaVCXjD9zQIDAQAB
            AoGAPI3E7pF0YQ7lQW2VJfk8Gjj+YyFEdk4m+AwR4tI/RIwABLr8WuMKEvW5uQmw
            nkhtR71LJ4sORwudfMgVhxBtXal0NDTR/HXIrQ6J/EKQtFyt36TRDoDKMILckgKp
            1ZZw+36pcKNPl4cq8LfrsE5VqC1xJkBIfUdqHM6kNAdPLwECQQDgfB5d8CbnHLGQ
            PE6FigJTH7kjlo6yXxHUurnBXjTe6TgWFGWZd8lWr17k41XrRt28GyEzkUgb+4r1
            sYtUtN1FAkEAv3C2ucBT5gaVQoAlEe8Fzu2W0LgcKUEA0bmoUFleyiNQT4nRjbFI
            JvWakmGwL/tEEc2FMP9kk6YrsQqkzl3S6QJAW7Z51Zki27MeXDY3QlmS/5DrW73M
            CNXMfCPZdkXdxeB0eJjWtW96A39cfpjeZmQqfQp8cwv88OnA6QYjTXUjHQJAHdAR
            xK+c4S+ZQvftzfMpNmZtnCdvy0TiOcbt3UVtq5EASsKtraE0GU0aOz2XUIGSwir9
            WPoM0amJGFMOA009MQJAeIdDez+1gavlgil7eR+OQw2HweKvJT//3rDX1rph+0rw
            jHnu/Fr0rhD8se0uSvtYxBnrToM4E5wDGLr9109CYw==
            """,
            options: .ignoreUnknownCharacters
        )!)

        XCTAssertEqual(key.keyType, SecAttrKeyType.RSA)
        XCTAssertEqual(key.keyClass, SecAttrKeyClass.privateKey)
        XCTAssertEqual(key.keySize, 1024 / 8)
        XCTAssertEqual(key.blockSize, 128)
    }

    func testEncryption() throws {
        let key = try SecKey.import(.RSA, .privateKey, Data(
            base64Encoded:
            """
            MIICWwIBAAKBgGZEQql8pSLobUt8YM6eDaSbkshxb46PqpYbltYEkXgWb1HDj+BZ
            yol1dzsYjzVc2G7REb/3XuoyRlvQb8WlKCM5rT8XyHF0JEqRv+6H8iMDhnPup+95
            Ej/sWJ4gfcKnxZ9+dCdwsyP/yXRRR2uRrhSvkBxfIE/GiDv+14bbOfYFAgMBAAEC
            gYAyYC+iQ5cpAetMwuEBBpRb4JLGkDJOvHBgbwi3NhreV9bQJRBLiI+fdLCd+LQa
            qjinJe+ja1xi6w8DjUJxzrBdP5MfHvi54vraJvzWE0QDWJAs5SDmw/eO92XbtZlF
            YccESyvvAWK/jQmgmzHp/VO7lamnfv6zElPEibnLXxacwQJBAMLQ2i83mDAm2wez
            z+2imjU4+9uuqLiGFFLiofOsrVjA5Mp1Di0iaZg0TDaHqBXy1/NgG0w1RHxs4Iy0
            bQg7l9ECQQCGYnmOnlapt2fthxRhX56HdgC+NoUEveo30FhXH2wuFSK5xILrQqCa
            PsN3yT8LbkdPd5P0KBh8DOsBGiOsjLv1AkAkHsMFVCJ0cw/TKsSXg7lhutH/li+U
            Hs/v2jM60b5GIWWKIA/j0GiRnsiup5JDl4XwitYk2A99nlY34FAC4cGxAkAZ84pl
            8E3sGG8Jf7x/0Wdb4X3jPcQSVlqUzLdCm97YR1ydY0WlCQjawKQezc5O9szum7kG
            vXd8/UGkxNd+yu7BAkEAuUxKb/aprabQXcI71qh/mhGXRO8lQ3eZsDamuMgBb11J
            BHK2imbjhVDZ27rbqr9/TZI/o5+StCJenoKgAcFJFA==
            """,
            options: .ignoreUnknownCharacters
        )!)

        let random = try Data(randomBytes: SecKeyGetBlockSize(key) - 11)
        let encrypted = try key.encrypt(random, algorithm: .rsaEncryptionPKCS1)
        let decrypted = try key.decrypt(encrypted, algorithm: .rsaEncryptionPKCS1)
        XCTAssertEqual(random, decrypted)
    }

    func testSignature() throws {
        let key = try SecKey.import(.RSA, .privateKey, Data(
            base64Encoded:
            """
            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
            """,
            options: .ignoreUnknownCharacters
        )!)

        let random = try Data(randomBytes: 4 * 1024 * 1024)
        let signature = try key.sign(random, algorithm: .rsaSignatureMessagePSSSHA256)
        XCTAssertNoThrow(try key.verify(message: random, signature: signature,
                                        algorithm: .rsaSignatureMessagePSSSHA256))
    }

    func testKeyExport() throws {
        let privateKeyData = Data(
            base64Encoded:
            """
            MIICWwIBAAKBgQCfxpcTtoiLvkAOGK8jTKw4c7C8wtVAWSYBP0wJ3odnih8U/4a9
            MPXIFrt7PJqAHscvWJwpic1xJCGCinfus2UN+zsKMF/qo0nqwMYUpgeeWKWY5QwS
            nOfGEjp7uYjP8uTL81GFGfeSooFN0Nhl2RGvzJ3j0/Q3GIPFrYp71lsYYQIDAQAB
            AoGAWwzNnVNA3vnNAPt6GtCfuA/doMQayG/FI6LRjzI70Xo5mjq/quLSvXKO5nyz
            wt1HPyjs3RMFeztOyVhlXibnJ7TFOyFsW8zC5B0G3yRjHivXBNq+YsexV6YGUGsW
            IC1Oa4HxAa0pRRZJ5JdZXWYAfvjA3NqIs11jQBBAmwh4ij0CQQD1ElzFd75CtJ1N
            RvQdjTr25ZbNXung3fZDx5xr/C+AbvqntJnQNpxWVswEjje/I5h0ylTZNt7kuV2E
            8hU6xCZLAkEApuaGJlfxh4iKQllWGa2RY/L19F3VbfvYtUWbrCA2SVQNi4ypmxka
            qFOkexVOH6XEo+S2JOROlausqQvrhMKAgwJAHcu9u8RzPWj4Nw0JYQ5qvNntG8sO
            ZGiYKGV8fySKIfNcRkeO6+G34EdtRqCD5plNT+XJqx8gum5PEHreWea/QQJAChrr
            BGdOuGYL+Phvvh5EL0kGm0UTJxWYiWEti75niwkLyOc7XaindImb69feYwwmW8X9
            QT6Rg35hddrC58bfAQJAWZtEI/qbhIWCTjmaKlNS55tqy26z7Cf9kvwuMaec5/ax
            3i4VBwXjmuWF8XFX71VhxQfLZsoW/GqdWQ0fN+ihow==
            """,
            options: .ignoreUnknownCharacters
        )!
        let privateKey = try SecKey.import(.RSA, .privateKey, privateKeyData)
        XCTAssertEqual(try privateKey.export(), privateKeyData)

        let publicKeyData = Data(
            base64Encoded:
            """
            MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCfxpcTtoiLvkAOGK8jTKw4c7C8
            wtVAWSYBP0wJ3odnih8U/4a9MPXIFrt7PJqAHscvWJwpic1xJCGCinfus2UN+zsK
            MF/qo0nqwMYUpgeeWKWY5QwSnOfGEjp7uYjP8uTL81GFGfeSooFN0Nhl2RGvzJ3j
            0/Q3GIPFrYp71lsYYQIDAQAB
            """,
            options: .ignoreUnknownCharacters
        )!
        let publicKey = try SecKey.import(.RSA, .publicKey, publicKeyData)
        XCTAssertEqual(try privateKey.publicKey!.export(), try publicKey.export())
    }
}
