import Foundation
import zlib

public struct EvtxChunkHeader: Sendable {
    public let firstRecordNumber: UInt64
    public let lastRecordNumber: UInt64
    public let firstRecordId: UInt64
    public let lastRecordId: UInt64
    public let headerSize: UInt32
    public let lastRecordOffset: UInt32
    public let freeSpaceOffset: UInt32
    public let recordsChecksum: UInt32
    public let flags: UInt32
    public let headerChecksum: UInt32
    /// CRC32 over bytes 0..<120 and 128..<512.
    public let headerChecksumValid: Bool
    /// CRC32 over the record area 512..<freeSpaceOffset.
    public let recordsChecksumValid: Bool

    static let signature: UInt64 = 0x006B_6E68_4366_6C45 // "ElfChnk\0"

    init?(_ b: UnsafeRawBufferPointer) {
        guard b.count == EvtxFile.chunkSize, b.u64u(0) == Self.signature else { return nil }
        firstRecordNumber = b.u64u(8)
        lastRecordNumber = b.u64u(16)
        firstRecordId = b.u64u(24)
        lastRecordId = b.u64u(32)
        headerSize = b.u32u(40)
        lastRecordOffset = b.u32u(44)
        freeSpaceOffset = b.u32u(48)
        recordsChecksum = b.u32u(52)
        flags = b.u32u(120)
        headerChecksum = b.u32u(124)

        let p = b.baseAddress!.assumingMemoryBound(to: Bytef.self)
        var crc = crc32(0, p, 120)
        crc = crc32(crc, p + 128, 384)
        headerChecksumValid = UInt32(crc) == headerChecksum

        let fso = Int(freeSpaceOffset)
        if fso >= 512 && fso <= b.count {
            recordsChecksumValid = UInt32(crc32(0, p + 512, uInt(fso - 512))) == recordsChecksum
        } else {
            recordsChecksumValid = false
        }
    }
}

/// Location and header of one event record.
public struct EvtxRecordRef: Sendable, Hashable {
    public let chunk: Int
    /// Offset of the record inside its chunk.
    public let offset: Int
    public let size: Int
    public let recordId: UInt64
    public let writtenTime: Int64
    public var flags: RecordFlags
}

/// One 64 KiB chunk with its own name/template caches. Not thread-safe: parse each
/// chunk on one thread (chunks are fully independent, so parallelise across chunks).
public final class EvtxChunk {
    public static let recordMagic: UInt32 = 0x0000_2A2A

    public let file: EvtxFile
    public let index: Int
    public let bytes: UnsafeRawBufferPointer
    /// Nil when the chunk has no valid signature (empty or overwritten).
    public let header: EvtxChunkHeader?
    let ctx: ChunkContext

    public init(file: EvtxFile, index: Int, library: TemplateLibrary? = nil) {
        self.file = file
        self.index = index
        bytes = file.chunkBytes(index)
        header = EvtxChunkHeader(bytes)
        ctx = ChunkContext(buf: bytes, library: library)
    }

    public var isValid: Bool { header != nil }

    private var baseFlags: RecordFlags {
        var f: RecordFlags = []
        if let h = header {
            if !h.headerChecksumValid { f.insert(.chunkHeaderCRC) }
            if !h.recordsChecksumValid { f.insert(.chunkDataCRC) }
        }
        return f
    }

    /// Plausible record start: magic, size within chunk, trailing size copy, BinXML fragment.
    private func record(at p: Int, limit: Int, strict: Bool) -> EvtxRecordRef? {
        guard p >= 0, p + 28 <= limit, bytes.u32u(p) == Self.recordMagic else { return nil }
        let size = Int(bytes.u32u(p + 4))
        guard size >= 28, p + size <= limit else { return nil }
        let copyMatches = bytes.u32u(p + size - 4) == UInt32(size)
        if strict {
            guard copyMatches, bytes[p + 24] == 0x0F || bytes[p + 24] == 0x0C else { return nil }
        }
        var flags = baseFlags
        if !copyMatches { flags.insert(.sizeMismatch) }
        return EvtxRecordRef(chunk: index, offset: p, size: size, recordId: bytes.u64u(p + 8),
                             writtenTime: Int64(bitPattern: bytes.u64u(p + 16)), flags: flags)
    }

    /// The record starting at `offset` (as stored by an index), if it is still plausible.
    public func record(at offset: Int) -> EvtxRecordRef? {
        record(at: offset, limit: bytes.count, strict: false)
    }

    /// Live records: 512 ..< freeSpaceOffset. On corruption, resynchronises on the next
    /// plausible record instead of abandoning the rest of the chunk.
    public func records() -> [EvtxRecordRef] {
        guard let h = header else { return [] }
        let fso = Int(h.freeSpaceOffset)
        let limit = (fso >= 512 && fso <= bytes.count) ? fso : bytes.count
        var out: [EvtxRecordRef] = []
        var p = 512
        var afterGap = false
        while p + 28 <= limit {
            if var r = record(at: p, limit: limit, strict: false) {
                if afterGap { r.flags.insert(.afterGap) }
                out.append(r)
                p += r.size
                continue
            }
            // Resync on the next strictly valid record (records are 8-byte aligned).
            var q = (p + 8) & ~7
            while q + 28 <= limit, record(at: q, limit: limit, strict: true) == nil { q += 8 }
            p = q
            afterGap = true
        }
        return out
    }

    /// Records left in slack space (after the free-space offset, or anywhere in a chunk
    /// without a valid header). Each is flagged `.carved`.
    public func carve() -> [EvtxRecordRef] {
        let start: Int
        if let h = header {
            let fso = Int(h.freeSpaceOffset)
            start = (fso >= 512 && fso <= bytes.count) ? (fso + 7) & ~7 : bytes.count
        } else {
            start = 512
        }
        var out: [EvtxRecordRef] = []
        var p = start
        while p + 28 <= bytes.count {
            if var r = record(at: p, limit: bytes.count, strict: true), Self.plausibleTime(r.writtenTime) {
                r.flags.insert(.carved)
                out.append(r)
                p += (r.size + 7) & ~7
                continue
            }
            p += 8
        }
        return out
    }

    private static let minPlausible = FileTime.fromUnixSeconds(631_152_000)   // 1990-01-01
    private static let maxPlausible = FileTime.fromUnixSeconds(4_102_444_800) // 2100-01-01

    static func plausibleTime(_ ft: Int64) -> Bool { ft > minPlausible && ft < maxPlausible }

    /// Parses a record into structured form. `systemOnly` skips EventData/UserData.
    /// Never fails: on a parse error whatever was decoded is kept and `.parseError` is set.
    public func event(_ r: EvtxRecordRef, systemOnly: Bool = false) -> EvtxEvent {
        eventWithError(r, systemOnly: systemOnly).event
    }

    public func eventWithError(_ r: EvtxRecordRef, systemOnly: Bool = false) -> (event: EvtxEvent, error: Error?) {
        var walker = BinXmlWalker(ctx: ctx, visitor: EventExtractor(systemOnly: systemOnly))
        var flags = r.flags
        var failure: Error?
        do {
            try walker.walkFragment(r.offset + 24, r.offset + r.size - 4)
        } catch {
            flags.insert(.parseError)
            failure = error
        }
        var e = walker.visitor.event
        flags.formUnion(walker.flags)
        if walker.invalidText || walker.visitor.invalidText || ctx.names.invalidText { flags.insert(.invalidText) }
        e.recordId = r.recordId
        e.writtenTime = r.writtenTime
        if let tc = e.timeCreated, abs(tc - r.writtenTime) > 60 * FileTime.ticksPerSecond {
            flags.insert(.timeSkew)
        }
        e.flags = flags
        return (e, failure)
    }

    /// Indented XML of a record (Event Viewer style). For damaged records the part decoded
    /// before the error is returned, followed by an XML comment describing the error.
    public func xml(_ r: EvtxRecordRef) throws -> String {
        var walker = BinXmlWalker(ctx: ctx, visitor: XmlWriter())
        do {
            try walker.walkFragment(r.offset + 24, r.offset + r.size - 4)
        } catch {
            let partial = walker.visitor.out
            if partial.isEmpty { throw error }
            return partial + "\n<!-- DayBook: parse error, record truncated here: \(error) -->"
        }
        return walker.visitor.out
    }

    /// Raw bytes of a record (for the hex view and hashing).
    public func rawBytes(_ r: EvtxRecordRef) -> UnsafeRawBufferPointer {
        UnsafeRawBufferPointer(rebasing: bytes[r.offset..<(r.offset + r.size)])
    }

    /// Compiles every template listed in the chunk's template pointer table (32 hash
    /// buckets at offset 384, each a chain linked by the definition's "next" field), so
    /// nested EventData templates are known without parsing any record. A pointer is
    /// trusted only if it is the inline definition of a TemplateInstance: token 0x0C at
    /// `ofs - 10` and the instance's definition offset at `ofs - 4` equal to `ofs`.
    public func compileTableTemplates() {
        guard header != nil else { return }
        for bucket in 0..<32 {
            var ofs = Int(bytes.u32u(384 + bucket * 4))
            var steps = 0
            while ofs >= 522, ofs + 24 <= bytes.count, steps < 4096 {
                steps += 1
                guard bytes[ofs - 10] == 0x0C, Int(bytes.u32u(ofs - 4)) == ofs else { break }
                _ = ctx.compile(ofs)
                let next = Int(bytes.u32u(ofs))
                guard next != ofs else { break }
                ofs = next
            }
        }
    }

    /// Templates of this chunk (pointer table plus any compiled while parsing), to feed a
    /// `TemplateLibrary` for decoding carved records.
    public func registerTemplates(in library: TemplateLibrary) {
        compileTableTemplates()
        for t in ctx.templates.values { library.add(t) }
    }
}

/// Cheap per-chunk overview used to classify chunks beyond the header's chunk count.
public struct EvtxChunkSummary: Sendable {
    public let index: Int
    public let valid: Bool
    public let recordCount: Int
    public let minRecordId: UInt64
    public let maxRecordId: UInt64
    public let headerChecksumValid: Bool
    public let recordsChecksumValid: Bool
}

extension EvtxFile {
    public func summarizeChunks() -> [EvtxChunkSummary] {
        (0..<physicalChunkCount).map { i in
            let c = EvtxChunk(file: self, index: i)
            let recs = c.records()
            return EvtxChunkSummary(index: i, valid: c.isValid, recordCount: recs.count,
                                    minRecordId: recs.map(\.recordId).min() ?? 0,
                                    maxRecordId: recs.map(\.recordId).max() ?? 0,
                                    headerChecksumValid: c.header?.headerChecksumValid ?? false,
                                    recordsChecksumValid: c.header?.recordsChecksumValid ?? false)
        }
    }

    /// Flags for records of chunk `index`: chunks past the header's count are either the
    /// newest data (header not flushed) or stale leftovers (ids below the live range).
    public func positionFlags(chunk index: Int, summaries: [EvtxChunkSummary]) -> RecordFlags {
        guard index >= Int(header.chunkCount), index < summaries.count else { return [] }
        let liveMax = summaries.prefix(Int(header.chunkCount)).map(\.maxRecordId).max() ?? 0
        let s = summaries[index]
        return s.recordCount > 0 && s.maxRecordId <= liveMax ? [.beyondHeader, .staleChunk] : [.beyondHeader]
    }
}
