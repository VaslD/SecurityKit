import CryptoKit
import Foundation

public extension SHA3 {
    struct SHA256 {
        public static let blockByteCount = 136

        static let marker: UInt8 = 0x06

        var processedBytes = 0
        var lastBlock = [UInt8]()

        var accumulatedHash: [UInt64]

        public init() {
            self.accumulatedHash = [UInt64](repeating: 0, count: Self.Digest.byteCount)
        }

        public mutating func update(bufferPointer pointer: UnsafeRawBufferPointer) {
            guard !pointer.isEmpty else { return }

            let batch = self.lastBlock + pointer
            guard batch.count >= Self.blockByteCount else {
                self.lastBlock = batch
                return
            }
            self.lastBlock = Self.accumulate(batch: batch, hash: &self.accumulatedHash,
                                             processedBytes: &self.processedBytes)
        }

        static func accumulate(batch: [UInt8], hash: inout [UInt64], processedBytes: inout Int) -> [UInt8] {
            let count = batch.count / Self.blockByteCount
            for start in 0..<count {
                let block = read(batch[start * Self.blockByteCount..<((start + 1) * Self.blockByteCount)],
                                 as: UInt64.self)
                SHA3.process(Self.self, block: block, hash: &hash)
                processedBytes += Self.blockByteCount
            }
            return Array(batch[(count * Self.blockByteCount)...])
        }

        public func finalize() -> SHA256Digest {
            let block = read(self.pad(), as: UInt64.self)

            var hash = self.accumulatedHash
            SHA3.process(Self.self, block: block, hash: &hash)
            return SHA256Digest(hash.reduce(into: [UInt8]()) {
                $0 += withUnsafeBytes(of: $1.bigEndian) {
                    Array($0).reversed()
                }
            })
        }

        func pad() -> [UInt8] {
            var block = self.lastBlock
            var count = self.processedBytes + block.count

            let r = Self.blockByteCount * 8
            let q = (r / 8) - (count % (r / 8))
            count = block.count
            block += [UInt8](repeating: 0, count: q)

            block[count] |= Self.marker
            block[block.count - 1] |= 0x80
            return block
        }
    }
}

public extension SHA3.SHA256 {
    struct SHA256Digest: Sequence, Hashable, ContiguousBytes, CustomStringConvertible {
        public static let byteCount = 32

        private var digest: Data

        init<T: DataProtocol>(_ digest: T) {
            let digest = (digest as? Data) ?? Data(digest)
            self.digest = digest[..<Self.byteCount]
        }

        // MARK: Sequence

        public func makeIterator() -> Data.Iterator {
            self.digest.makeIterator()
        }

        // MARK: Hashable

        public func hash(into hasher: inout Hasher) {
            hasher.combine(self.digest)
        }

        // MARK: ContiguousBytes

        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try self.digest.withUnsafeBytes(body)
        }

        // MARK: CustomStringConvertible

        public var description: String {
            "SHA3-256 digest: \(self.map { String(format: "%02x", $0) }.joined())"
        }
    }
}

// MARK: - SHA3.SHA256 + HashFunction

extension SHA3.SHA256: HashFunction {}

// MARK: - SHA3.SHA256 + SHA3HashFunction

extension SHA3.SHA256: SHA3HashFunction {}

// MARK: - SHA3.SHA256.SHA256Digest + Digest

extension SHA3.SHA256.SHA256Digest: Digest {}
