import CryptoKit
import Foundation

// This file contains source code taken from CryptoSwift, version 1.6.0
// https://raw.githubusercontent.com/krzyzanowskim/CryptoSwift/1.6.0/Sources/CryptoSwift/SHA3.swift
//
// Source has been altered to accept generic UInt8 collections with arbitrary start and end indices.

// CryptoSwift
//
// Copyright (C) 2014-2022 Marcin Krzyżanowski <marcin@krzyzanowskim.com>
// This software is provided 'as-is', without any express or implied warranty.
//
// In no event will the authors be held liable for any damages arising from the use of this software.
//
// Permission is granted to anyone to use this software for any purpose, including commercial applications,
// and to alter it and redistribute it freely, subject to the following restrictions:
//
// - The origin of this software must not be misrepresented; you must not claim that you wrote the original software.
//   If you use this software in a product, an acknowledgement in the product documentation is required.
// - Altered source versions must be plainly marked as such, and must not be misrepresented as being
//   the original software.
// - This notice may not be removed or altered from any source or binary distribution.

// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

/// NIST Secure Hash Algorithm 3 algorithms.
public enum SHA3 {
    static let roundConstants: [UInt64] = [
        0x0000_0000_0000_0001, 0x0000_0000_0000_8082, 0x8000_0000_0000_808A, 0x8000_0000_8000_8000,
        0x0000_0000_0000_808B, 0x0000_0000_8000_0001, 0x8000_0000_8000_8081, 0x8000_0000_0000_8009,
        0x0000_0000_0000_008A, 0x0000_0000_0000_0088, 0x0000_0000_8000_8009, 0x0000_0000_8000_000A,
        0x0000_0000_8000_808B, 0x8000_0000_0000_008B, 0x8000_0000_0000_8089, 0x8000_0000_0000_8003,
        0x8000_0000_0000_8002, 0x8000_0000_0000_0080, 0x0000_0000_0000_800A, 0x8000_0000_8000_000A,
        0x8000_0000_8000_8081, 0x8000_0000_0000_8080, 0x0000_0000_8000_0001, 0x8000_0000_8000_8008,
    ]

    // 1. For all pairs (x, z) such that 0 <= x < 5 and 0 <= z < w,
    //    let C[x, z] = A[x, 0,z] ⊕ A[x, 1, z] ⊕ A[x, 2, z] ⊕ A[x, 3, z] ⊕ A[x, 4, z].
    // 2. For all pairs (x, z) such that 0 <= x < 5 and 0 <= z < w,
    //    let D[x, z]=C[(x - 1) mod 5, z] ⊕ C[(x + 1) mod 5, (z – 1) mod w].
    // 3. For all triples (x, y, z) such that 0 <= x < 5, 0 <= y < 5, and 0 <= z < w,
    //    let A′[x, y, z] = A[x, y, z] ⊕ D[x, z].
    static func θ<T: MutableCollection>(_ a: inout T) where T.Element == UInt64, T.Index == Int {
        let c = UnsafeMutablePointer<UInt64>.allocate(capacity: 5)
        c.initialize(repeating: 0, count: 5)
        defer {
            c.deinitialize(count: 5)
            c.deallocate()
        }
        let d = UnsafeMutablePointer<UInt64>.allocate(capacity: 5)
        d.initialize(repeating: 0, count: 5)
        defer {
            d.deinitialize(count: 5)
            d.deallocate()
        }

        for i in 0..<5 {
            c[i] = a[a.startIndex + i] ^ a[a.startIndex + i &+ 5] ^ a[a.startIndex + i &+ 10]
                ^ a[a.startIndex + i &+ 15] ^ a[a.startIndex + i &+ 20]
        }

        d[0] = rotateLeft(c[1], by: 1) ^ c[4]
        d[1] = rotateLeft(c[2], by: 1) ^ c[0]
        d[2] = rotateLeft(c[3], by: 1) ^ c[1]
        d[3] = rotateLeft(c[4], by: 1) ^ c[2]
        d[4] = rotateLeft(c[0], by: 1) ^ c[3]

        for i in 0..<5 {
            a[a.startIndex + i] ^= d[i]
            a[a.startIndex + i &+ 5] ^= d[i]
            a[a.startIndex + i &+ 10] ^= d[i]
            a[a.startIndex + i &+ 15] ^= d[i]
            a[a.startIndex + i &+ 20] ^= d[i]
        }
    }

    // A′[x, y, z] = A[(x &+ 3y) mod 5, x, z]
    static func π<T: MutableCollection>(_ a: inout T) where T.Element == UInt64, T.Index == Int {
        let a1 = a[1]
        a[a.startIndex + 1] = a[a.startIndex + 6]
        a[a.startIndex + 6] = a[a.startIndex + 9]
        a[a.startIndex + 9] = a[a.startIndex + 22]
        a[a.startIndex + 22] = a[a.startIndex + 14]
        a[a.startIndex + 14] = a[a.startIndex + 20]
        a[a.startIndex + 20] = a[a.startIndex + 2]
        a[a.startIndex + 2] = a[a.startIndex + 12]
        a[a.startIndex + 12] = a[a.startIndex + 13]
        a[a.startIndex + 13] = a[a.startIndex + 19]
        a[a.startIndex + 19] = a[a.startIndex + 23]
        a[a.startIndex + 23] = a[a.startIndex + 15]
        a[a.startIndex + 15] = a[a.startIndex + 4]
        a[a.startIndex + 4] = a[a.startIndex + 24]
        a[a.startIndex + 24] = a[a.startIndex + 21]
        a[a.startIndex + 21] = a[a.startIndex + 8]
        a[a.startIndex + 8] = a[a.startIndex + 16]
        a[a.startIndex + 16] = a[a.startIndex + 5]
        a[a.startIndex + 5] = a[a.startIndex + 3]
        a[a.startIndex + 3] = a[a.startIndex + 18]
        a[a.startIndex + 18] = a[a.startIndex + 17]
        a[a.startIndex + 17] = a[a.startIndex + 11]
        a[a.startIndex + 11] = a[a.startIndex + 7]
        a[a.startIndex + 7] = a[a.startIndex + 10]
        a[a.startIndex + 10] = a1
    }

    // For all triples (x, y, z) such that 0 <= x < 5, 0 <= y < 5, and 0 <= z < w,
    // let A′[x, y,z] = A[x, y,z] ⊕ ( ( A[(x + 1) mod 5, y, z] ⊕ 1 ) ⋅ A[(x + 2) mod 5, y, z] ).
    static func χ<T: MutableCollection>(_ a: inout T) where T.Element == UInt64, T.Index == Int {
        for i in stride(from: 0, to: 25, by: 5) {
            let a0 = a[a.startIndex + 0 &+ i]
            let a1 = a[a.startIndex + 1 &+ i]
            a[a.startIndex + 0 &+ i] ^= ~a1 & a[a.startIndex + 2 &+ i]
            a[a.startIndex + 1 &+ i] ^= ~a[a.startIndex + 2 &+ i] & a[a.startIndex + 3 &+ i]
            a[a.startIndex + 2 &+ i] ^= ~a[a.startIndex + 3 &+ i] & a[a.startIndex + 4 &+ i]
            a[a.startIndex + 3 &+ i] ^= ~a[a.startIndex + 4 &+ i] & a0
            a[a.startIndex + 4 &+ i] ^= ~a0 & a1
        }
    }

    static func ι<T: MutableCollection>(_ a: inout T, round: Int) where T.Element == UInt64, T.Index == Int {
        a[a.startIndex + 0] ^= Self.roundConstants[round]
    }

    static func process<T: Collection>(
        _ function: (some SHA3HashFunction).Type, block: T, hash: inout [UInt64]
    ) where T.Element == UInt64, T.Index == Int {
        // Expand
        hash[0] ^= block[block.startIndex + 0].littleEndian
        hash[1] ^= block[block.startIndex + 1].littleEndian
        hash[2] ^= block[block.startIndex + 2].littleEndian
        hash[3] ^= block[block.startIndex + 3].littleEndian
        hash[4] ^= block[block.startIndex + 4].littleEndian
        hash[5] ^= block[block.startIndex + 5].littleEndian
        hash[6] ^= block[block.startIndex + 6].littleEndian
        hash[7] ^= block[block.startIndex + 7].littleEndian
        hash[8] ^= block[block.startIndex + 8].littleEndian

        let blockSize = function.blockByteCount
        if blockSize > 72 {
            // SHA-512
            hash[9] ^= block[block.startIndex + 9].littleEndian
            hash[10] ^= block[block.startIndex + 10].littleEndian
            hash[11] ^= block[block.startIndex + 11].littleEndian
            hash[12] ^= block[block.startIndex + 12].littleEndian
            if blockSize > 104 {
                // SHA-384
                hash[13] ^= block[block.startIndex + 13].littleEndian
                hash[14] ^= block[block.startIndex + 14].littleEndian
                hash[15] ^= block[block.startIndex + 15].littleEndian
                hash[16] ^= block[block.startIndex + 16].littleEndian
                if blockSize > 136 {
                    // SHA256
                    hash[17] ^= block[block.startIndex + 17].littleEndian
                    // FULL_SHA3_FAMILY_SUPPORT
                    if blockSize > 144 {
                        // SHA224
                        hash[18] ^= block[block.startIndex + 18].littleEndian
                        hash[19] ^= block[block.startIndex + 19].littleEndian
                        hash[20] ^= block[block.startIndex + 20].littleEndian
                        hash[21] ^= block[block.startIndex + 21].littleEndian
                        hash[22] ^= block[block.startIndex + 22].littleEndian
                        hash[23] ^= block[block.startIndex + 23].littleEndian
                        hash[24] ^= block[block.startIndex + 24].littleEndian
                    }
                }
            }
        }

        // Keccak-f
        for round in 0..<24 {
            self.θ(&hash)

            hash[1] = rotateLeft(hash[1], by: 1)
            hash[2] = rotateLeft(hash[2], by: 62)
            hash[3] = rotateLeft(hash[3], by: 28)
            hash[4] = rotateLeft(hash[4], by: 27)
            hash[5] = rotateLeft(hash[5], by: 36)
            hash[6] = rotateLeft(hash[6], by: 44)
            hash[7] = rotateLeft(hash[7], by: 6)
            hash[8] = rotateLeft(hash[8], by: 55)
            hash[9] = rotateLeft(hash[9], by: 20)
            hash[10] = rotateLeft(hash[10], by: 3)
            hash[11] = rotateLeft(hash[11], by: 10)
            hash[12] = rotateLeft(hash[12], by: 43)
            hash[13] = rotateLeft(hash[13], by: 25)
            hash[14] = rotateLeft(hash[14], by: 39)
            hash[15] = rotateLeft(hash[15], by: 41)
            hash[16] = rotateLeft(hash[16], by: 45)
            hash[17] = rotateLeft(hash[17], by: 15)
            hash[18] = rotateLeft(hash[18], by: 21)
            hash[19] = rotateLeft(hash[19], by: 8)
            hash[20] = rotateLeft(hash[20], by: 18)
            hash[21] = rotateLeft(hash[21], by: 2)
            hash[22] = rotateLeft(hash[22], by: 61)
            hash[23] = rotateLeft(hash[23], by: 56)
            hash[24] = rotateLeft(hash[24], by: 14)

            self.π(&hash)
            self.χ(&hash)
            self.ι(&hash, round: round)
        }
    }
}

// MARK: Utility

@inlinable
func rotateLeft(_ value: UInt64, by: UInt64) -> UInt64 {
    (value << by) | (value >> (64 - by))
}

@inlinable
func read<T>(_ buffer: ContiguousBytes, as type: T.Type) -> [T] {
    buffer.withUnsafeBytes { pointer in
        defer { pointer.bindMemory(to: UInt8.self) }
        return Array(pointer.bindMemory(to: type))
    }
}
