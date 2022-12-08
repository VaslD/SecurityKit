import CryptoKit
import XCTest
@testable import SecurityKit

final class SHA3Tests: XCTestCase {
    static let text = [
        """

        What is Lorem Ipsum?

        Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.

        """,
        """

        Why do we use it?

        It is a long established fact that a reader will be distracted by the readable content of a page when looking at its layout. The point of using Lorem Ipsum is that it has a more-or-less normal distribution of letters, as opposed to using 'Content here, content here', making it look like readable English. Many desktop publishing packages and web page editors now use Lorem Ipsum as their default model text, and a search for 'lorem ipsum' will uncover many web sites still in their infancy. Various versions have evolved over the years, sometimes by accident, sometimes on purpose (injected humour and the like).

        Where does it come from?

        Contrary to popular belief, Lorem Ipsum is not simply random text. It has roots in a piece of classical Latin literature from 45 BC, making it over 2000 years old. Richard McClintock, a Latin professor at Hampden-Sydney College in Virginia, looked up one of the more obscure Latin words, consectetur, from a Lorem Ipsum passage, and going through the cites of the word in classical literature, discovered the undoubtable source. Lorem Ipsum comes from sections 1.10.32 and 1.10.33 of "de Finibus Bonorum et Malorum" (The Extremes of Good and Evil) by Cicero, written in 45 BC. This book is a treatise on the theory of ethics, very popular during the Renaissance. The first line of Lorem Ipsum, "Lorem ipsum dolor sit amet..", comes from a line in section 1.10.32.


        """,
        """
        The standard chunk of Lorem Ipsum used since the 1500s is reproduced below for those interested. Sections 1.10.32 and 1.10.33 from "de Finibus Bonorum et Malorum" by Cicero are also reproduced in their exact original form, accompanied by English versions from the 1914 translation by H. Rackham.
        Where can I get some?

        There are many variations of passages of Lorem Ipsum available, but the majority have suffered alteration in some form, by injected humour, or randomised words which don't look even slightly believable. If you are going to use a passage of Lorem Ipsum, you need to be sure there isn't anything embarrassing hidden in the middle of text. All the Lorem Ipsum generators on the Internet tend to repeat predefined chunks as necessary, making this the first true generator on the Internet. It uses a dictionary of over 200 Latin words, combined with a handful of model sentence structures, to generate Lorem Ipsum which looks reasonable. The generated Lorem Ipsum is therefore always free from repetition, injected humour, or non-characteristic words etc.
        """,
    ]

    // https://emn178.github.io/online-tools/index.html

    func testSHA224() {
        XCTAssertEqual(SHA3.SHA224.hash(data: Data()).asHexString(uppercased: false),
                       "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7")

        XCTAssertEqual(SHA3.SHA224.hash(data: Self.text.joined().data(using: .utf8)!).asHexString(uppercased: false),
                       "61c8db31c49a98ef5f166178a2bbfe674403848b9099000288cfe75a")

        var hasher = SHA3.SHA224()
        Self.text.forEach {
            hasher.update(data: $0.data(using: .utf8)!)
        }
        XCTAssertEqual(hasher.finalize().asHexString(uppercased: false),
                       "61c8db31c49a98ef5f166178a2bbfe674403848b9099000288cfe75a")
    }

    func testSHA256() {
        XCTAssertEqual(SHA3.SHA256.hash(data: Data()).asHexString(uppercased: false),
                       "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")

        XCTAssertEqual(SHA3.SHA256.hash(data: Self.text.joined().data(using: .utf8)!).asHexString(uppercased: false),
                       "c41a72b1a512d889cc8a2318931dd677a7ffb741215bd00c16c7d2e0c5637681")

        var hasher = SHA3.SHA256()
        Self.text.forEach {
            hasher.update(data: $0.data(using: .utf8)!)
        }
        XCTAssertEqual(hasher.finalize().asHexString(uppercased: false),
                       "c41a72b1a512d889cc8a2318931dd677a7ffb741215bd00c16c7d2e0c5637681")
    }

    func testSHA384() {
        XCTAssertEqual(SHA3.SHA384.hash(data: Data()).asHexString(uppercased: false),
                       "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004")

        XCTAssertEqual(SHA3.SHA384.hash(data: Self.text.joined().data(using: .utf8)!).asHexString(uppercased: false),
                       "c11c6f808343479b6bf0b096e47e770771bd33505a969a2fffb5baf3e05aa4f16ff5d418c656dc66e13ee7640576f432")

        var hasher = SHA3.SHA384()
        Self.text.forEach {
            hasher.update(data: $0.data(using: .utf8)!)
        }
        XCTAssertEqual(hasher.finalize().asHexString(uppercased: false),
                       "c11c6f808343479b6bf0b096e47e770771bd33505a969a2fffb5baf3e05aa4f16ff5d418c656dc66e13ee7640576f432")
    }

    func testSHA512() {
        XCTAssertEqual(SHA3.SHA512.hash(data: Data()).asHexString(uppercased: false),
                       "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26")

        XCTAssertEqual(SHA3.SHA512.hash(data: Self.text.joined().data(using: .utf8)!).asHexString(uppercased: false),
                       "c259192d81b6e853fc6f982e77f65dd7f2e0486989c291c09de5f16bd211aeb83f96d4006428fefeb4eaa4482aac8374a43a6e9ff0d14a238967f5d610e929af")

        var hasher = SHA3.SHA512()
        Self.text.forEach {
            hasher.update(data: $0.data(using: .utf8)!)
        }
        XCTAssertEqual(hasher.finalize().asHexString(uppercased: false),
                       "c259192d81b6e853fc6f982e77f65dd7f2e0486989c291c09de5f16bd211aeb83f96d4006428fefeb4eaa4482aac8374a43a6e9ff0d14a238967f5d610e929af")
    }

    func testKeccak224() {
        XCTAssertEqual(SHA3.Keccak224.hash(data: Data()).asHexString(uppercased: false),
                       "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd")

        XCTAssertEqual(SHA3.Keccak224.hash(data: Self.text.joined().data(using: .utf8)!).asHexString(uppercased: false),
                       "40a9c0b4b63f4c68c1f9af71900b4a8e17610592db119d78bd5c01de")

        var hasher = SHA3.Keccak224()
        Self.text.forEach {
            hasher.update(data: $0.data(using: .utf8)!)
        }
        XCTAssertEqual(hasher.finalize().asHexString(uppercased: false),
                       "40a9c0b4b63f4c68c1f9af71900b4a8e17610592db119d78bd5c01de")
    }

    func testKeccak256() {
        XCTAssertEqual(SHA3.Keccak256.hash(data: Data()).asHexString(uppercased: false),
                       "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

        XCTAssertEqual(SHA3.Keccak256.hash(data: Self.text.joined().data(using: .utf8)!).asHexString(uppercased: false),
                       "0a662cb1b816d0ed421ae0547dc9cf8fd3a436eb13e9416d4cab2b0a1bc4b497")

        var hasher = SHA3.Keccak256()
        Self.text.forEach {
            hasher.update(data: $0.data(using: .utf8)!)
        }
        XCTAssertEqual(hasher.finalize().asHexString(uppercased: false),
                       "0a662cb1b816d0ed421ae0547dc9cf8fd3a436eb13e9416d4cab2b0a1bc4b497")
    }

    func testKeccak384() {
        XCTAssertEqual(SHA3.Keccak384.hash(data: Data()).asHexString(uppercased: false),
                       "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff")

        XCTAssertEqual(SHA3.Keccak384.hash(data: Self.text.joined().data(using: .utf8)!).asHexString(uppercased: false),
                       "e557476246eff018508893c0ee578d01bfefac9c3610c7493eafc5a718ebb0c0fe235e60ed01b37ec4cbfe37b66273fb")

        var hasher = SHA3.Keccak384()
        Self.text.forEach {
            hasher.update(data: $0.data(using: .utf8)!)
        }
        XCTAssertEqual(hasher.finalize().asHexString(uppercased: false),
                       "e557476246eff018508893c0ee578d01bfefac9c3610c7493eafc5a718ebb0c0fe235e60ed01b37ec4cbfe37b66273fb")
    }

    func testKeccak512() {
        XCTAssertEqual(SHA3.Keccak512.hash(data: Data()).asHexString(uppercased: false),
                       "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")

        XCTAssertEqual(SHA3.Keccak512.hash(data: Self.text.joined().data(using: .utf8)!).asHexString(uppercased: false),
                       "212794e257289625c48efae0ce5074aadfb3f66354c24b9dbd28e329af22ed0ecbb658631ce6727683a003a7c653a3b2b76142256c4b7a2c50810aaf941d9621")

        var hasher = SHA3.Keccak512()
        Self.text.forEach {
            hasher.update(data: $0.data(using: .utf8)!)
        }
        XCTAssertEqual(hasher.finalize().asHexString(uppercased: false),
                       "212794e257289625c48efae0ce5074aadfb3f66354c24b9dbd28e329af22ed0ecbb658631ce6727683a003a7c653a3b2b76142256c4b7a2c50810aaf941d9621")
    }
}
