import CryptoKit
import Foundation

/// Optimal Asymmetric Encryption Padding (OAEP) internals, for use with (non-standard) raw encryption schemes.
///
/// OAEP is part of PKCS #1. See [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017)
/// for implementation details and usages.
public enum OAEP {
    // 4.1.  I2OSP
    //
    // I2OSP converts a nonnegative integer to an octet string of a
    // specified length.
    //
    // I2OSP (x, xLen)
    //
    // Input:
    //
    //   x        nonnegative integer to be converted
    //
    //   xLen     intended length of the resulting octet string
    //
    // Output:
    //
    //   X        corresponding octet string of length xLen
    //
    // Error:     "integer too large"
    //
    // Steps:
    //
    //   1.  If x >= 256^xLen, output "integer too large" and stop.
    //
    //   2.  Write the integer x in its unique xLen-digit representation in
    //       base 256:
    //
    //          x = x_(xLen-1) 256^(xLen-1) + x_(xLen-2) 256^(xLen-2) + ...
    //          + x_1 256 + x_0,
    //
    //       where 0 <= x_i < 256 (note that one or more leading digits
    //       will be zero if x is less than 256^(xLen-1)).
    static func I2OSP<T: FixedWidthInteger>(x: T, xLen: Int) throws -> Data {
        guard x < T(pow(256, Double(xLen))) else {
            // "Integer too large."
            throw SecError(errSecInternalError)
        }

        var integer = x
        let array = Array((1...xLen).map { _ in
            defer { integer = integer / 256 }
            return UInt8(integer % 256)
        })
        return Data(array.reversed())
    }

    // B.2.1.  MGF1
    //
    // MGF1 is a mask generation function based on a hash function.
    //
    // MGF1 (mgfSeed, maskLen)
    //
    // Options:
    //
    //   Hash     hash function (hLen denotes the length in octets of
    //            the hash function output)
    //
    // Input:
    //
    //   mgfSeed  seed from which mask is generated, an octet string
    //   maskLen  intended length in octets of the mask, at most 2^32 hLen
    //
    // Output:
    //
    //   mask     mask, an octet string of length maskLen
    //
    // Error:     "mask too long"
    //
    // Steps:
    //
    // 1.  If maskLen > 2^32 hLen, output "mask too long" and stop.
    //
    // 2.  Let T be the empty octet string.
    //
    // 3.  For counter from 0 to ceil(maskLen / hLen) - 1, do the
    //     following:
    //
    //     A.  Convert counter to an octet string C of length 4 octets (see
    //         Section 4.1):
    //
    //           C = I2OSP (counter, 4) .
    //
    //     B.  Concatenate the hash of the seed mgfSeed and C to the octet
    //         string T:
    //
    //           T = T || Hash(mgfSeed || C) .
    //
    // 4.  Output the leading maskLen octets of T as the octet string mask.
    public static func MGF1<T: DataProtocol, H: HashFunction>(seed: T, len: Int, Hash: H.Type) throws -> Data {
        let hLen = H.Digest.byteCount
        guard len <= (hLen << 32) else {
            // "Mask too long."
            throw SecError(errSecInternalError)
        }

        var T = Data()

        for counter in 0..<Int(ceil(Double(len) / Double(hLen))) {
            let C = try Self.I2OSP(x: counter, xLen: 4)
            T += Hash.hash(data: seed + C)
        }

        return T[..<len]
    }

    // 2.  EME-OAEP encoding (see Figure 1 below):
    //
    //     a.  If the label L is not provided, let L be the empty string.
    //         Let lHash = Hash(L), an octet string of length hLen (see
    //         the note below).
    //
    //     b.  Generate a padding string PS consisting of k - mLen -
    //         2hLen - 2 zero octets.  The length of PS may be zero.
    //
    //     c.  Concatenate lHash, PS, a single octet with hexadecimal
    //         value 0x01, and the message M to form a data block DB of
    //         length k - hLen - 1 octets as
    //
    //            DB = lHash || PS || 0x01 || M.
    //
    //     d.  Generate a random octet string seed of length hLen.
    //
    //     e.  Let dbMask = MGF(seed, k - hLen - 1).
    //
    //     f.  Let maskedDB = DB xor dbMask.
    //
    //     g.  Let seedMask = MGF(maskedDB, hLen).
    //
    //     h.  Let maskedSeed = seed xor seedMask.
    //
    //     i.  Concatenate a single octet with hexadecimal value 0x00,
    //         maskedSeed, and maskedDB to form an encoded message EM of
    //         length k octets as
    //
    //            EM = 0x00 || maskedSeed || maskedDB.
    //
    // Figure 1:
    //                     +----------+------+--+-------+
    //                DB = |  lHash   |  PS  |01|   M   |
    //                     +----------+------+--+-------+
    //                                    |
    //          +----------+              |
    //          |   seed   |              |
    //          +----------+              |
    //                |                   |
    //                |-------> MGF ---> xor
    //                |                   |
    //       +--+     V                   |
    //       |00|    xor <----- MGF <-----|
    //       +--+     |                   |
    //         |      |                   |
    //         V      V                   V
    //       +--+----------+----------------------------+
    // EM =  |00|maskedSeed|          maskedDB          |
    //       +--+----------+----------------------------+
    public static func EMEOAEP<T: DataProtocol, H: HashFunction, MH: HashFunction>(
        MGFHash: MH.Type, Hash: H.Type,
        k: Int, M: T,
        L: String = String()
    ) throws -> Data {
        let hLen = H.Digest.byteCount
        guard M.count <= k - 2 * hLen - 2 else {
            // "Message too large."
            throw SecError(errSecDataTooLarge)
        }

        let lHash = Hash.hash(data: L.data(using: .utf8)!)
        let mLen = M.count
        let PS = Data(repeating: 0x00, count: k - mLen - 2 * hLen - 2)

        let DB = lHash + PS + [0x01] + M
        guard DB.count == k - hLen - 1 else {
            throw SecError(errSecInternalError)
        }

        let seed = try Data(randomBytes: hLen)
        let dbMask = try Self.MGF1(seed: seed, len: k - hLen - 1, Hash: MGFHash.self)
        let maskedDB = DB.enumerated().map {
            guard dbMask.indices.contains($0.0) else {
                return $0.1 ^ 0
            }
            return $0.1 ^ dbMask[$0.0]
        }

        let seedMask = try Self.MGF1(seed: maskedDB, len: hLen, Hash: MGFHash.self)
        let maskedSeed = seed.enumerated().map {
            guard seedMask.indices.contains($0.0) else {
                return $0.1 ^ 0
            }
            return $0.1 ^ seedMask[$0.0]
        }

        return Data([0x00] + maskedSeed + maskedDB)
    }

    public static func pad<T: DataProtocol, H: HashFunction, MH: HashFunction>(
        _ message: T, with hash: H.Type, andMGF1Padding hashMGF: MH.Type, for key: SecKey
    ) throws -> Data {
        let keySize = SecKeyGetBlockSize(key)
        return try Self.EMEOAEP(MGFHash: hashMGF, Hash: hash, k: keySize, M: message)
    }

    public static func pad<T: DataProtocol, H: HashFunction, MH: HashFunction>(
        _ message: T, with hash: H.Type, andMGF1Padding hashMGF: MH.Type, toBlockSize bytes: Int
    ) throws -> Data {
        try Self.EMEOAEP(MGFHash: hashMGF, Hash: hash, k: bytes, M: message)
    }
}
