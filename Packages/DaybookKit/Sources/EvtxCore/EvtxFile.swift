import Foundation
import zlib

public struct EvtxFileHeader: Sendable {
    public let firstChunkNumber: UInt64
    public let lastChunkNumber: UInt64
    public let nextRecordId: UInt64
    public let headerSize: UInt32
    public let minorVersion: UInt16
    public let majorVersion: UInt16
    public let headerBlockSize: UInt16
    public let chunkCount: UInt16
    public let flags: UInt32
    public let checksum: UInt32
    /// CRC32 of the first 120 bytes matches `checksum`.
    public let checksumValid: Bool

    public var isDirty: Bool { flags & 0x1 != 0 }
    public var isFull: Bool { flags & 0x2 != 0 }

    static let signature: [UInt8] = Array("ElfFile\0".utf8)

    init(_ b: UnsafeRawBufferPointer) throws {
        guard b.count >= 128 else { throw EvtxError.notEvtx }
        guard b.prefix(8).elementsEqual(Self.signature) else {
            if b.count >= 8, b.u32u(0) == 0x30, b[4...7].elementsEqual(Array("LfLe".utf8)) {
                throw EvtxError.legacyEvt
            }
            throw EvtxError.notEvtx
        }
        firstChunkNumber = b.u64u(8)
        lastChunkNumber = b.u64u(16)
        nextRecordId = b.u64u(24)
        headerSize = b.u32u(32)
        minorVersion = b.u16u(36)
        majorVersion = b.u16u(38)
        headerBlockSize = b.u16u(40)
        chunkCount = b.u16u(42)
        flags = b.u32u(120)
        checksum = b.u32u(124)
        checksumValid = UInt32(crc32(0, b.baseAddress!.assumingMemoryBound(to: Bytef.self), 120)) == checksum
    }
}

/// An opened `.evtx` file. Chunks are enumerated by physical file size, never by the
/// header's chunk counter: on live-collected (dirty) logs that counter is stale and the
/// chunks past it hold the newest events.
public final class EvtxFile: @unchecked Sendable {
    public static let chunkSize = 65_536

    public let url: URL
    public let mapped: MappedFile
    public let header: EvtxFileHeader
    public let dataOffset: Int
    public let physicalChunkCount: Int
    /// Bytes after the last whole chunk (a truncated copy, typically).
    public let trailingBytes: Int

    public init(url: URL) throws {
        self.url = url
        mapped = try MappedFile(url: url)
        header = try EvtxFileHeader(mapped.bytes)
        let block = Int(header.headerBlockSize)
        dataOffset = (block >= 128 && block <= mapped.size) ? block : 4096
        let body = max(0, mapped.size - dataOffset)
        physicalChunkCount = body / Self.chunkSize
        trailingBytes = body % Self.chunkSize
    }

    public var fileSize: Int { mapped.size }

    public func chunkBytes(_ index: Int) -> UnsafeRawBufferPointer {
        mapped.slice(dataOffset + index * Self.chunkSize, Self.chunkSize)
    }

    /// Cheap check used when scanning folders: does the file start with the EVTX signature?
    public static func looksLikeEvtx(_ url: URL) -> Bool {
        guard let h = FileHandle(forReadingAtPath: url.path) else { return false }
        defer { try? h.close() }
        let d = (try? h.read(upToCount: 8)) ?? Data()
        return d.elementsEqual(EvtxFileHeader.signature)
    }
}
