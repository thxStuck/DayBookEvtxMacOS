import CryptoKit
import EvtxCore
import Foundation

public struct ImportOptions: Sendable {
    /// Recover records from chunk slack space.
    public var carveSlack = true
    /// SHA-256 of every source file (chain of custody).
    public var hashSources = true
    /// Collapse identical events (live copy + VSS copy + slack remnant) into one event that
    /// carries the `.duplicate` ("has copies") flag. When off, every copy is its own event.
    public var mergeDuplicates = true
    public init() {}
}

public struct ImportProgress: Sendable {
    public enum Phase: String, Sendable {
        case scanning, hashing, indexing, carving, sorting, writing, postings, finishing, fullText, entities, done
    }
    public var phase: Phase
    public var fraction: Double
    public var events: Int
}

public struct ImportSummary: Sendable, Codable {
    public var files = 0
    public var failedFiles: [String] = []
    public var events = 0
    public var duplicates = 0
    /// Plausible records found in slack (before collapsing copies).
    public var carvedFound = 0
    public var carved = 0
    public var parseErrors = 0
    public var elapsed: Double = 0
}

private final class Box<T>: @unchecked Sendable {
    var value: T
    init(_ v: T) { value = v }
}

/// Sort key gathered in pass 1 (one per record, ~40 bytes).
private struct Entry {
    var ts: Int64
    var key: UInt64      // stable hash of computer + channel
    var rid: UInt64
    var eid: UInt16
    var src: UInt16
    var chunk: UInt32
    var off: UInt32
    var flags: UInt32
}

private struct Row: Sendable {
    var id: Int32         // event id, or -1 for a duplicate
    var dupOf: Int32
    var src: Int
    var chunk: Int
    var off: Int
    var flags: UInt32
    var event: EvtxEvent?
    var xml: String?
}

/// Builds a case database from EVTX sources. Two passes: (1) parse every record's System
/// part in parallel to get sort keys, sort globally and assign time-ordered ids;
/// (2) re-parse in parallel and stream rows to a single SQLite writer.
public final class CaseImporter: @unchecked Sendable {
    public let sources: [URL]
    public let caseURL: URL
    public let options: ImportOptions

    public init(sources: [URL], caseURL: URL, options: ImportOptions = ImportOptions()) {
        self.sources = sources
        self.caseURL = caseURL
        self.options = options
    }

    public func run(progress: @escaping @Sendable (ImportProgress) -> Void,
                    cancelled: @escaping @Sendable () -> Bool = { false }) throws -> ImportSummary {
        let t0 = Date()
        var summary = ImportSummary()
        let fm = FileManager.default
        guard !fm.fileExists(atPath: caseURL.path) else {
            throw CocoaError(.fileWriteFileExists, userInfo: [NSFilePathErrorKey: caseURL.path])
        }
        try fm.createDirectory(at: caseURL, withIntermediateDirectories: true)
        do {
            summary = try build(progress: progress, cancelled: cancelled)
        } catch {
            try? fm.removeItem(at: caseURL)
            throw error
        }
        progress(ImportProgress(phase: .entities, fraction: 0, events: summary.events))
        try EntityBuilder(caseURL: caseURL).run()
        summary.elapsed = Date().timeIntervalSince(t0)
        try writeManifest(summary)
        progress(ImportProgress(phase: .done, fraction: 1, events: summary.events))
        return summary
    }

    private func checkCancel(_ cancelled: @Sendable () -> Bool) throws {
        if cancelled() { throw CancellationError() }
    }

    // swiftlint:disable:next function_body_length
    private func build(progress: @escaping @Sendable (ImportProgress) -> Void,
                       cancelled: @escaping @Sendable () -> Bool) throws -> ImportSummary {
        var summary = ImportSummary()
        progress(ImportProgress(phase: .scanning, fraction: 0, events: 0))

        // Open sources.
        var opened: [EvtxFile] = []
        for url in findEvtxFiles(sources) {
            do { opened.append(try EvtxFile(url: url)) } catch {
                summary.failedFiles.append("\(url.path): \(error)")
            }
        }
        let files = opened
        guard files.count < Int(UInt16.max) else { throw EvtxError.badRecord(offset: 0, reason: "too many files") }
        guard !files.isEmpty else {
            throw CocoaError(.fileReadNoSuchFile, userInfo: [NSLocalizedDescriptionKey: String(localized: "В выбранных источниках не найдено ни одного файла EVTX") + (summary.failedFiles.isEmpty ? "" : ": " + summary.failedFiles.joined(separator: "; "))])
        }
        summary.files = files.count

        progress(ImportProgress(phase: .hashing, fraction: 0, events: 0))
        let hashes: [String] = options.hashSources ? parallelMap(files.count) { i in
            SHA256.hash(data: files[i].mapped.bytes).map { String(format: "%02x", $0) }.joined()
        } : Array(repeating: "", count: files.count)
        try checkCancel(cancelled)

        // Pass 1a: live records → sort keys; compile templates into the shared library.
        let library = TemplateLibrary()
        let summaries = parallelMap(files.count) { files[$0].summarizeChunks() }
        let jobs: [(Int, Int)] = files.indices.flatMap { f in (0..<files[f].physicalChunkCount).map { (f, $0) } }
        progress(ImportProgress(phase: .indexing, fraction: 0, events: 0))
        let live: [[Entry]] = parallelMap(jobs.count) { j in
            let (fi, ci) = jobs[j]
            let chunk = EvtxChunk(file: files[fi], index: ci)
            let pos = files[fi].positionFlags(chunk: ci, summaries: summaries[fi])
            let out = chunk.records().map { r -> Entry in
                Self.entry(chunk.event(r, systemOnly: true), r, fi, ci, extra: pos)
            }
            chunk.registerTemplates(in: library)
            return out
        }
        try checkCancel(cancelled)

        // Pass 1b: slack carving with templates from the whole case.
        progress(ImportProgress(phase: .carving, fraction: 0, events: 0))
        let carved: [[Entry]] = options.carveSlack ? parallelMap(jobs.count) { j in
            let (fi, ci) = jobs[j]
            let chunk = EvtxChunk(file: files[fi], index: ci, library: library)
            return chunk.carve().map { r in Self.entry(chunk.event(r, systemOnly: true), r, fi, ci, extra: []) }
        } : Array(repeating: [], count: jobs.count)
        try checkCancel(cancelled)

        // Sort globally and assign ids; identical events (same computer, channel, record id,
        // time and event id) from several copies or from slack collapse into one.
        progress(ImportProgress(phase: .sorting, fraction: 0, events: 0))
        summary.carvedFound = carved.reduce(0) { $0 + $1.count }
        var jobStart = [Int](repeating: 0, count: jobs.count + 1)
        for j in jobs.indices { jobStart[j + 1] = jobStart[j] + live[j].count + carved[j].count }
        var entries = [Entry]()
        entries.reserveCapacity(jobStart[jobs.count])
        for j in jobs.indices { entries += live[j]; entries += carved[j] }
        let order = (0..<entries.count).sorted { a, b in
            let x = entries[a], y = entries[b]
            if x.ts != y.ts { return x.ts < y.ts }
            if x.key != y.key { return x.key < y.key }
            if x.rid != y.rid { return x.rid < y.rid }
            if x.eid != y.eid { return x.eid < y.eid }
            let cx = x.flags & RecordFlags.carved.rawValue, cy = y.flags & RecordFlags.carved.rawValue
            if cx != cy { return cx < cy }
            if x.src != y.src { return x.src < y.src }
            if x.chunk != y.chunk { return x.chunk < y.chunk }
            return x.off < y.off
        }
        var assigned = [Int32](repeating: -1, count: entries.count)
        var dupOf = [Int32](repeating: -1, count: entries.count)
        var timestamps = [Int64]()
        timestamps.reserveCapacity(entries.count)
        var lastKept = -1
        var hasCopies = Set<Int32>()
        let merge = options.mergeDuplicates
        for i in order {
            let e = entries[i]
            if merge, lastKept >= 0 {
                let k = entries[lastKept]
                if k.ts == e.ts && k.key == e.key && k.rid == e.rid && k.eid == e.eid {
                    dupOf[i] = assigned[lastKept]
                    hasCopies.insert(assigned[lastKept])
                    summary.duplicates += 1
                    continue
                }
            }
            assigned[i] = Int32(timestamps.count)
            timestamps.append(e.ts)
            lastKept = i
        }
        entries = []
        summary.events = timestamps.count
        try checkCancel(cancelled)

        // Database.
        let db = try SQLiteDB(path: caseURL.appendingPathComponent(CaseSchema.databaseName).path, create: true)
        try db.exec(CaseSchema.create)
        try db.exec("PRAGMA journal_mode = OFF; PRAGMA synchronous = OFF; PRAGMA cache_size = -262144; PRAGMA temp_store = MEMORY; PRAGMA locking_mode = EXCLUSIVE;")
        try db.exec("BEGIN")
        let interner = try Interner(db: db)
        let insertEv = try db.prepare("""
            INSERT INTO ev(id, ts, wts, src, chunk, off, rid, eid, qual, ver, lvl, task, opc, kw, prov, chan, comp, usr, pid, tid, flags, fv)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, persistent: true)
        let insertDup = try db.prepare("INSERT INTO dup(ev, src, chunk, off, flags) VALUES (?,?,?,?,?)", persistent: true)
        let insertXml = try db.prepare("INSERT INTO xml_cache(ev, xml) VALUES (?,?)", persistent: true)
        var postings: [UInt64: [UInt32]] = [:]
        var keyIds: [String: UInt32] = [:]
        func key(_ name: String) throws -> UInt32 {
            if let k = keyIds[name] { return k }
            let k = try interner.id(name, kind: CaseSchema.StrKind.name)
            keyIds[name] = k
            return k
        }
        func post(_ k: UInt32, _ v: UInt32, _ id: UInt32) {
            postings[UInt64(k) << 32 | UInt64(v), default: []].append(id)
        }
        let sysKeys = try CaseSchema.SystemKey.all.map { try key($0) }
        let (kEid, kChan, kProv, kComp, kLvl, kUser, kSrc, kTask, kOpc, kFlag) =
            (sysKeys[0], sysKeys[1], sysKeys[2], sysKeys[3], sysKeys[4], sysKeys[5], sysKeys[6], sysKeys[7], sysKeys[8], sysKeys[9])
        let kKw = sysKeys[10]
        let flagNames: [(RecordFlags, String)] = [
            (.carved, "carved"), (.beyondHeader, "beyondHeader"), (.staleChunk, "stale"), (.afterGap, "afterGap"),
            (.parseError, "parseError"), (.chunkDataCRC, "crcMismatch"), (.chunkHeaderCRC, "headerCrcMismatch"),
            (.timeSkew, "timeSkew"), (.foreignTemplate, "foreignTemplate"), (.missingTemplate, "missingTemplate"),
            (.invalidText, "invalidText"), (.sizeMismatch, "sizeMismatch"), (.duplicate, "hasCopies"),
        ]
        let labels = Self.uniqueLabels(files.map(\.url))
        let sourceNames = try labels.map { try interner.id($0) }

        // Pass 2: re-parse in parallel (in groups) while the writer stores the previous group.
        let assignedC = assigned, dupOfC = dupOf, jobStartC = jobStart, hasCopiesC = hasCopies
        let carveSlack = options.carveSlack
        let produce: @Sendable (Range<Int>) -> [[Row]] = { range in
            parallelMap(range.count) { k in
                let j = range.lowerBound + k
                let (fi, ci) = jobs[j]
                let chunk = EvtxChunk(file: files[fi], index: ci, library: library)
                let pos = files[fi].positionFlags(chunk: ci, summaries: summaries[fi])
                var refs = chunk.records().map { r -> EvtxRecordRef in var r = r; r.flags.formUnion(pos); return r }
                if carveSlack { refs += chunk.carve() }
                var rows: [Row] = []
                rows.reserveCapacity(refs.count)
                for (i, r) in refs.enumerated() {
                    let slot = jobStartC[j] + i
                    let id = assignedC[slot]
                    guard id >= 0 else {
                        rows.append(Row(id: -1, dupOf: dupOfC[slot], src: fi, chunk: ci, off: r.offset,
                                        flags: r.flags.rawValue, event: nil, xml: nil))
                        continue
                    }
                    let e = chunk.event(r)
                    let needsXml = e.flags.contains(.foreignTemplate) || e.flags.contains(.missingTemplate)
                    rows.append(Row(id: id, dupOf: -1, src: fi, chunk: ci, off: r.offset, flags: e.flags.rawValue,
                                    event: e, xml: needsXml ? (try? chunk.xml(r)) : nil))
                }
                return rows
            }
        }

        var perSource = [(records: Int, carved: Int, dups: Int, first: Int64, last: Int64)](
            repeating: (0, 0, 0, .max, .min), count: files.count)
        let groupSize = 256
        let groups = stride(from: 0, to: jobs.count, by: groupSize).map { $0..<min($0 + groupSize, jobs.count) }
        var written = 0
        var lastReport = Date.distantPast
        var current = groups.isEmpty ? [] : produce(groups[0])
        for gi in groups.indices {
            let next = Box<[[Row]]>([])
            let pending = DispatchGroup()
            if gi + 1 < groups.count {
                let range = groups[gi + 1]
                DispatchQueue.global(qos: .userInitiated).async(group: pending) { next.value = produce(range) }
            }
            for rows in current {
                for row in rows {
                    guard var e = row.event else {
                        try insertDup.bind(1, Int64(row.dupOf)).bind(2, row.src).bind(3, row.chunk)
                            .bind(4, row.off).bind(5, Int64(row.flags)).run()
                        perSource[row.src].dups += 1
                        continue
                    }
                    let id = UInt32(row.id)
                    if hasCopiesC.contains(row.id) { e.flags.insert(.duplicate) }
                    let prov = try interner.id(e.provider)
                    let chan = try interner.id(e.channel)
                    let comp = try interner.id(e.computer)
                    let usr = try e.userSid.map { try interner.id($0) }
                    var fv = [UInt8]()
                    fv.reserveCapacity(e.fields.count * 6)
                    for f in e.fields {
                        let k = try key(f.name)
                        let v = try interner.id(f.value, kind: f.type == ValueType.binary ? CaseSchema.StrKind.binary : CaseSchema.StrKind.text)
                        Varint.append(k, to: &fv)
                        Varint.append(v, to: &fv)
                        post(k, v, id)
                    }
                    post(kEid, try interner.id(String(e.eventId)), id)
                    post(kChan, chan, id)
                    post(kProv, prov, id)
                    post(kComp, comp, id)
                    post(kSrc, sourceNames[row.src], id)
                    if let l = e.level { post(kLvl, try interner.id(String(l)), id) }
                    if let usr { post(kUser, usr, id) }
                    if let t = e.task { post(kTask, try interner.id(String(t)), id) }
                    if let o = e.opcode { post(kOpc, try interner.id(String(o)), id) }
                    if let kw = e.keywords { post(kKw, try interner.id(String(format: "0x%016llx", kw)), id) }
                    for (flag, name) in flagNames where e.flags.contains(flag) { post(kFlag, try interner.id(name), id) }

                    try insertEv.bind(1, Int64(id)).bind(2, e.timestamp).bind(3, e.writtenTime).bind(4, row.src)
                        .bind(5, row.chunk).bind(6, row.off).bind(7, Int64(bitPattern: e.recordId)).bind(8, Int64(e.eventId))
                        .bind(9, e.qualifiers.map { Int64($0) }).bind(10, e.version.map { Int64($0) })
                        .bind(11, e.level.map { Int64($0) }).bind(12, e.task.map { Int64($0) })
                        .bind(13, e.opcode.map { Int64($0) }).bind(14, e.keywords.map { Int64(bitPattern: $0) })
                        .bind(15, Int64(prov)).bind(16, Int64(chan)).bind(17, Int64(comp)).bind(18, usr.map { Int64($0) })
                        .bind(19, e.processId.map { Int64($0) }).bind(20, e.threadId.map { Int64($0) })
                        .bind(21, Int64(e.flags.rawValue)).bind(22, blob: fv).run()
                    if let xml = row.xml { try insertXml.bind(1, Int64(id)).bind(2, xml).run() }

                    var s = perSource[row.src]
                    if e.flags.contains(.carved) { s.carved += 1 } else { s.records += 1 }
                    s.first = min(s.first, e.timestamp)
                    s.last = max(s.last, e.timestamp)
                    perSource[row.src] = s
                    if e.flags.contains(.carved) { summary.carved += 1 }
                    if e.flags.contains(.parseError) { summary.parseErrors += 1 }
                    written += 1
                }
            }
            pending.wait()
            current = next.value
            if Date().timeIntervalSince(lastReport) > 0.1 {
                lastReport = Date()
                progress(ImportProgress(phase: .writing, fraction: Double(gi + 1) / Double(groups.count), events: written))
            }
            try checkCancel(cancelled)
        }

        // Posting lists.
        progress(ImportProgress(phase: .postings, fraction: 0, events: written))
        let insertPost = try db.prepare("INSERT INTO post(k, v, n, ids) VALUES (?,?,?,?)", persistent: true)
        for pk in postings.keys.sorted() {
            var ids = postings[pk]!
            ids.sort()
            try insertPost.bind(1, Int64(pk >> 32)).bind(2, Int64(pk & 0xFFFF_FFFF)).bind(3, ids.count)
                .bind(4, blob: Varint.encodeDeltas(ids)).run()
        }
        postings = [:]

        // Sources and metadata.
        let insertSource = try db.prepare("""
            INSERT INTO source(id, path, name, size, sha256, mtime, header_chunks, chunks, dirty, records, carved, duplicates,
                               first_ts, last_ts, empty_chunks, beyond_new, beyond_stale, bad_header_crc, bad_data_crc,
                               trailing_bytes, version)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """)
        for (i, f) in files.enumerated() {
            let s = perSource[i]
            var empty = 0, beyondNew = 0, beyondStale = 0, badHeader = 0, badData = 0
            for c in summaries[i] {
                guard c.valid else { empty += 1; continue }
                if !c.headerChecksumValid { badHeader += 1 }
                if !c.recordsChecksumValid { badData += 1 }
                guard c.recordCount > 0 else { continue }
                let pos = f.positionFlags(chunk: c.index, summaries: summaries[i])
                if pos.contains(.staleChunk) { beyondStale += 1 } else if pos.contains(.beyondHeader) { beyondNew += 1 }
            }
            let mtime = (try? f.url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate)?.timeIntervalSince1970
            try insertSource.bind(1, i).bind(2, f.url.path).bind(3, labels[i]).bind(4, f.fileSize)
                .bind(5, hashes[i]).bind(6, mtime.map { Int64($0) }).bind(7, Int(f.header.chunkCount))
                .bind(8, f.physicalChunkCount).bind(9, f.header.isDirty ? 1 : 0).bind(10, s.records)
                .bind(11, s.carved).bind(12, s.dups).bind(13, s.first == .max ? nil : s.first)
                .bind(14, s.last == .min ? nil : s.last).bind(15, empty).bind(16, beyondNew).bind(17, beyondStale)
                .bind(18, badHeader).bind(19, badData).bind(20, f.trailingBytes)
                .bind(21, "\(f.header.majorVersion).\(f.header.minorVersion)").run()
        }
        let meta = try db.prepare("INSERT INTO meta(key, value) VALUES (?, ?)")
        let failed = summary.failedFiles.joined(separator: "\n")
        for (k, v) in [("schema", String(CaseSchema.version)), ("events", String(written)),
                       ("created", ISO8601DateFormatter().string(from: Date())), ("fulltext", "0"),
                       ("option.carveSlack", options.carveSlack ? "1" : "0"),
                       ("option.mergeDuplicates", options.mergeDuplicates ? "1" : "0"),
                       ("option.hashSources", options.hashSources ? "1" : "0"),
                       ("carvedFound", String(summary.carvedFound)), ("carvedKept", String(summary.carved)),
                       ("duplicates", String(summary.duplicates)), ("parseErrors", String(summary.parseErrors)),
                       ("failedFiles", failed), ("sources", sources.map(\.path).joined(separator: "\n"))] {
            try meta.bind(1, k).bind(2, v).run()
        }
        try db.exec("COMMIT")

        progress(ImportProgress(phase: .finishing, fraction: 0, events: written))
        try db.exec(CaseSchema.indexes)
        try timestamps.withUnsafeBytes { try Data($0).write(to: caseURL.appendingPathComponent(CaseSchema.timestampsName)) }

        progress(ImportProgress(phase: .fullText, fraction: 0, events: written))
        try db.exec(CaseSchema.fullText)
        try db.exec("UPDATE meta SET value = '1' WHERE key = 'fulltext'")
        try db.exec("PRAGMA locking_mode = NORMAL; PRAGMA journal_mode = WAL; PRAGMA wal_checkpoint(TRUNCATE);")
        return summary
    }

    /// Shortest distinguishing labels: the file name, extended with parent folders only
    /// where names collide (several hosts each have a Security.evtx).
    static func uniqueLabels(_ urls: [URL]) -> [String] {
        let parts = urls.map { $0.standardizedFileURL.pathComponents }
        var depth = [Int](repeating: 1, count: urls.count)
        func label(_ i: Int) -> String { parts[i].suffix(depth[i]).joined(separator: "/") }
        for _ in 0..<64 {
            var groups: [String: [Int]] = [:]
            for i in urls.indices { groups[label(i), default: []].append(i) }
            let clashes = groups.values.filter { $0.count > 1 }
            if clashes.isEmpty { break }
            var progressed = false
            for g in clashes { for i in g where depth[i] < parts[i].count { depth[i] += 1; progressed = true } }
            if !progressed { break }
        }
        return urls.indices.map(label)
    }

    private static func entry(_ e: EvtxEvent, _ r: EvtxRecordRef, _ fi: Int, _ ci: Int, extra: RecordFlags) -> Entry {
        let key = UInt64(bitPattern: StringKey.lowerHash(e.computer)) &* 31 &+ UInt64(bitPattern: StringKey.lowerHash(e.channel))
        return Entry(ts: e.timestamp, key: key, rid: e.recordId, eid: e.eventId, src: UInt16(fi),
                     chunk: UInt32(ci), off: UInt32(r.offset), flags: r.flags.union(extra).rawValue)
    }

    private func writeManifest(_ summary: ImportSummary) throws {
        struct Manifest: Codable {
            var app = "DayBookEvtxMacOS"
            var schema = CaseSchema.version
            var created = Date()
            var sources: [String]
            var summary: ImportSummary
        }
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        enc.dateEncodingStrategy = .iso8601
        let data = try enc.encode(Manifest(sources: sources.map(\.path), summary: summary))
        try data.write(to: caseURL.appendingPathComponent(CaseSchema.manifestName))
    }
}
