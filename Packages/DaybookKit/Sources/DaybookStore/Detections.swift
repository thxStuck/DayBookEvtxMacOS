import EvtxCore
import Foundation

/// One detection rule as evaluated against a case (also rules that could not be evaluated,
/// with the reason), so the analyst sees exactly what ran, how it was translated and why
/// something was skipped.
public struct DetectionRule: Sendable, Identifiable, Hashable {
    public var id: Int64 = 0
    public let ruleId: String
    /// Rule set the rule came from (SigmaHQ, Hayabusa, a custom folder name).
    public let source: String
    public let path: String
    public let title: String
    public let level: String?
    public let status: String?
    public let author: String?
    public let description: String?
    public let date: String?
    public let modified: String?
    public let tags: [String]
    public let references: [String]
    public let falsePositives: [String]
    public let logsource: String
    /// DQL that was evaluated (empty when unsupported).
    public let query: String
    /// Event families the rule was evaluated on, with field renames (e.g. "Security 4688: Image→NewProcessName").
    public let variants: [String]
    /// Rule fields that never occur in this case (conditions on them are false; `null` is true).
    public let absentFields: [String]
    /// Why the rule was not evaluated (unsupported syntax / logsource / parse error).
    public let unsupported: String?
    /// Evaluation error (e.g. invalid regular expression).
    public let error: String?
    /// Evaluation caveats (e.g. values a regular expression could not check within the time limit).
    public var warnings: [String] = []
    public var hits = 0
    public var hosts = 0
    public var firstTs: Int64?
    public var lastTs: Int64?
    public var elapsedMs = 0.0

    public init(ruleId: String, source: String, path: String, title: String, level: String?, status: String?,
                author: String?, description: String?, date: String?, modified: String?, tags: [String],
                references: [String], falsePositives: [String], logsource: String, query: String,
                variants: [String], absentFields: [String], unsupported: String?, error: String?) {
        self.ruleId = ruleId
        self.source = source
        self.path = path
        self.title = title
        self.level = level
        self.status = status
        self.author = author
        self.description = description
        self.date = date
        self.modified = modified
        self.tags = tags
        self.references = references
        self.falsePositives = falsePositives
        self.logsource = logsource
        self.query = query
        self.variants = variants
        self.absentFields = absentFields
        self.unsupported = unsupported
        self.error = error
    }

    /// Sort weight of `level` (critical first).
    public var levelRank: Int { Self.rank(level) }

    public static func rank(_ level: String?) -> Int {
        switch level?.lowercased() {
        case "critical", "crit": 5
        case "high": 4
        case "medium", "med": 3
        case "low": 2
        case "informational", "info": 1
        default: 0
        }
    }

    public var evaluated: Bool { unsupported == nil && error == nil }
}

enum DetectionSchema {
    static let create = """
    CREATE TABLE IF NOT EXISTS det_rule(
        id INTEGER PRIMARY KEY, rule_id TEXT NOT NULL, source TEXT NOT NULL, path TEXT NOT NULL,
        title TEXT NOT NULL, level TEXT, status TEXT, author TEXT, description TEXT, date TEXT, modified TEXT,
        tags TEXT, refs TEXT, falsepositives TEXT, logsource TEXT, query TEXT, variants TEXT, absent TEXT,
        unsupported TEXT, error TEXT, warnings TEXT, hits INTEGER NOT NULL DEFAULT 0, hosts INTEGER NOT NULL DEFAULT 0,
        first_ts INTEGER, last_ts INTEGER, elapsed_ms REAL, yaml TEXT);
    CREATE TABLE IF NOT EXISTS det_hit(rule INTEGER PRIMARY KEY, n INTEGER NOT NULL, ids BLOB NOT NULL);
    CREATE TABLE IF NOT EXISTS det_meta(key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
    """

    static func json(_ list: [String]) -> String {
        (try? JSONSerialization.data(withJSONObject: list)).flatMap { String(data: $0, encoding: .utf8) } ?? "[]"
    }

    static func list(_ text: String) -> [String] {
        guard let data = text.data(using: .utf8),
              let arr = try? JSONSerialization.jsonObject(with: data) as? [String] else { return [] }
        return arr
    }
}

/// Replaces the stored detection results of a case (own read-write connection; WAL).
public final class DetectionWriter: @unchecked Sendable {
    private let db: SQLiteDB

    public init(store: CaseStore) throws {
        db = try SQLiteDB(path: store.url.appendingPathComponent(CaseSchema.databaseName).path)
        try db.exec("PRAGMA busy_timeout = 5000")
    }

    /// `hits[i]` are the (time-ordered) event ids of `rules[i]`; `yaml[i]` its source text.
    public func replace(rules: [DetectionRule], yaml: [String], hits: [[UInt32]], meta: [String: String]) throws {
        precondition(rules.count == hits.count && rules.count == yaml.count)
        try db.transaction {
            // Recreated on every run, so the stored results always match the current schema.
            try db.exec("DROP TABLE IF EXISTS det_rule; DROP TABLE IF EXISTS det_hit; DROP TABLE IF EXISTS det_meta;")
            try db.exec(DetectionSchema.create)
            let ins = try db.prepare("""
                INSERT INTO det_rule(id, rule_id, source, path, title, level, status, author, description, date, modified,
                    tags, refs, falsepositives, logsource, query, variants, absent, unsupported, error, warnings, hits, hosts,
                    first_ts, last_ts, elapsed_ms, yaml)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """)
            let hit = try db.prepare("INSERT INTO det_hit(rule, n, ids) VALUES (?,?,?)")
            for (i, r) in rules.enumerated() {
                let id = Int64(i + 1)
                ins.bind(1, id).bind(2, r.ruleId).bind(3, r.source).bind(4, r.path).bind(5, r.title)
                    .bind(6, r.level).bind(7, r.status).bind(8, r.author).bind(9, r.description).bind(10, r.date)
                    .bind(11, r.modified).bind(12, DetectionSchema.json(r.tags)).bind(13, DetectionSchema.json(r.references))
                    .bind(14, DetectionSchema.json(r.falsePositives)).bind(15, r.logsource).bind(16, r.query)
                    .bind(17, DetectionSchema.json(r.variants)).bind(18, DetectionSchema.json(r.absentFields))
                    .bind(19, r.unsupported).bind(20, r.error).bind(21, DetectionSchema.json(r.warnings))
                    .bind(22, r.hits).bind(23, r.hosts).bind(24, r.firstTs).bind(25, r.lastTs).bind(26, r.elapsedMs)
                    .bind(27, yaml[i])
                try ins.run()
                if !hits[i].isEmpty {
                    try hit.bind(1, id).bind(2, hits[i].count).bind(3, blob: Varint.encodeDeltas(hits[i])).run()
                }
            }
            let m = try db.prepare("INSERT INTO det_meta(key, value) VALUES (?,?)")
            for (k, v) in meta { try m.bind(1, k).bind(2, v).run() }
        }
        try db.exec("PRAGMA wal_checkpoint(PASSIVE)")
    }
}

/// Last loaded detection rules (re-read when a new run has finished).
final class DetectionCache: @unchecked Sendable {
    let lock = NSLock()
    var run: String?
    var rules: [DetectionRule] = []
}

extension CaseStore {
    /// Rules of the last run, cached until another run finishes (the DQL `rule` field and the
    /// UI ask for them often).
    func cachedDetectionRules() throws -> [DetectionRule] {
        let run = (try? detectionMeta()["finished"]) ?? nil
        if let hit = detectionCache.lock.withLock({ detectionCache.run == run && run != nil ? detectionCache.rules : nil }) { return hit }
        let rules = try detectionRules()
        detectionCache.lock.withLock {
            detectionCache.run = run
            detectionCache.rules = rules
        }
        return rules
    }

    /// True when detections were run for this case.
    public func hasDetections() -> Bool {
        (try? queryLock.withLock {
            try queryDB.scalar("SELECT count(*) FROM sqlite_master WHERE name = 'det_meta'")
        }) == 1 && ((try? detectionMeta()["finished"]) ?? nil) != nil
    }

    public func detectionMeta() throws -> [String: String] {
        try queryLock.withLock {
            guard try queryDB.scalar("SELECT count(*) FROM sqlite_master WHERE name = 'det_meta'") == 1 else { return [:] }
            let st = try queryDB.prepare("SELECT key, value FROM det_meta")
            var out: [String: String] = [:]
            while try st.step() { out[st.string(0)] = st.string(1) }
            return out
        }
    }

    /// All rules of the last detection run (without their YAML text).
    public func detectionRules() throws -> [DetectionRule] {
        try queryLock.withLock {
            guard try queryDB.scalar("SELECT count(*) FROM sqlite_master WHERE name = 'det_rule'") == 1 else { return [] }
            let st = try queryDB.prepare("""
                SELECT id, rule_id, source, path, title, level, status, author, description, date, modified, tags, refs,
                    falsepositives, logsource, query, variants, absent, unsupported, error, hits, hosts, first_ts, last_ts,
                    elapsed_ms, warnings FROM det_rule ORDER BY id
                """)
            var out: [DetectionRule] = []
            while try st.step() {
                var r = DetectionRule(ruleId: st.string(1), source: st.string(2), path: st.string(3), title: st.string(4),
                                      level: st.optionalString(5), status: st.optionalString(6), author: st.optionalString(7),
                                      description: st.optionalString(8), date: st.optionalString(9),
                                      modified: st.optionalString(10), tags: DetectionSchema.list(st.string(11)),
                                      references: DetectionSchema.list(st.string(12)),
                                      falsePositives: DetectionSchema.list(st.string(13)), logsource: st.string(14),
                                      query: st.string(15), variants: DetectionSchema.list(st.string(16)),
                                      absentFields: DetectionSchema.list(st.string(17)),
                                      unsupported: st.optionalString(18), error: st.optionalString(19))
                r.id = st.int64(0)
                r.hits = Int(st.int64(20))
                r.hosts = Int(st.int64(21))
                r.firstTs = st.optionalInt64(22)
                r.lastTs = st.optionalInt64(23)
                r.elapsedMs = st.double(24)
                r.warnings = DetectionSchema.list(st.string(25))
                out.append(r)
            }
            return out
        }
    }

    public func detectionYAML(_ id: Int64) throws -> String {
        try queryLock.withLock {
            let st = try queryDB.prepare("SELECT yaml FROM det_rule WHERE id = ?")
            st.bind(1, id)
            return try st.step() ? st.string(0) : ""
        }
    }

    /// Hit event ids (time-ordered) of the given stored rules, unioned.
    public func detectionHits(_ ids: [Int64]) throws -> [UInt32] {
        guard !ids.isEmpty else { return [] }
        let lists: [[UInt32]] = try queryLock.withLock {
            guard try queryDB.scalar("SELECT count(*) FROM sqlite_master WHERE name = 'det_hit'") == 1 else { return [] }
            let st = try queryDB.prepare("SELECT n, ids FROM det_hit WHERE rule = ?")
            var out: [[UInt32]] = []
            for id in ids {
                st.bind(1, id)
                if try st.step() {
                    let n = Int(st.int64(0))
                    out.append(st.withBlob(1) { Varint.decodeDeltas($0, count: n) })
                }
                st.reset()
            }
            return out
        }
        return IdSet.union(lists, universe: eventCount)
    }

    /// Stored rules whose id, title (case-insensitive; `*` / `?` wildcards) or level matches.
    func detectionRuleIds(matching value: String) throws -> [Int64] {
        let rules = try cachedDetectionRules()
        let v = value.lowercased()
        if value.contains("*") || value.contains("?") {
            var p = "^"
            for ch in v {
                switch ch {
                case "*": p += ".*"
                case "?": p += "."
                default: p += NSRegularExpression.escapedPattern(for: String(ch))
                }
            }
            let re = try NSRegularExpression(pattern: p + "$", options: [.caseInsensitive])
            return rules.filter { r in
                re.firstMatch(in: r.title, range: NSRange(location: 0, length: (r.title as NSString).length)) != nil
                    || r.ruleId.lowercased() == v
            }.map(\.id)
        }
        return rules.filter { $0.ruleId.lowercased() == v || $0.title.lowercased() == v || String($0.id) == v }.map(\.id)
    }

    func detectionRuleIds(level op: String, _ value: String) throws -> [Int64] {
        let want = DetectionRule.rank(value)
        guard want > 0 else {
            throw DQLError(message: String(localized: "Уровень правила: informational, low, medium, high, critical"), position: -1)
        }
        return try cachedDetectionRules().filter { r in
            let x = r.levelRank
            switch op {
            case "<": return x > 0 && x < want
            case "<=": return x > 0 && x <= want
            case ">": return x > want
            case ">=": return x >= want
            default: return x == want
            }
        }.map(\.id)
    }

    /// Stored rules that matched one event.
    public func detections(forEvent id: UInt32) throws -> [DetectionRule] {
        let rules = try cachedDetectionRules().filter { $0.hits > 0 }
        var out: [DetectionRule] = []
        for r in rules {
            let hits = try detectionHits([r.id])
            let p = IdSet.lowerBound(hits, id)
            if p < hits.count, hits[p] == id { out.append(r) }
        }
        return out.sorted { ($0.levelRank, $1.title) > ($1.levelRank, $0.title) }
    }
}

/// Matched rules as CSV for reports: one row per rule, with the rule author (required by the
/// Detection Rule License 1.1 for messages based on matches) and the exact DQL that was evaluated.
public enum DetectionExport {
    public static func csv(_ rules: [DetectionRule], excel: Bool, zoneLabel: String,
                           formatLocal: (Int64) -> String) -> String {
        let sep = excel ? ";" : ","
        func cell(_ s: String) -> String { CaseExporter.csv(excel ? CaseExporter.excelSafe(s) : s, sep) }
        var out = excel ? "\u{FEFF}" : ""
        let header = ["Level", "Rule", "Events", "Hosts", "First (\(zoneLabel))", "Last (\(zoneLabel))", "FirstUTC", "LastUTC",
                      "Author", "RuleSet", "RulePath", "RuleID", "Status", "Tags", "References", "License", "DQL"]
        out += header.map(cell).joined(separator: sep) + "\r\n"
        for r in rules {
            let license = r.source == "SigmaHQ" || r.source == "Hayabusa" ? "Detection Rule License (DRL) 1.1" : ""
            let row = [r.level ?? "", r.title, String(r.hits), String(r.hosts),
                       r.firstTs.map(formatLocal) ?? "", r.lastTs.map(formatLocal) ?? "",
                       r.firstTs.map(FileTime.iso8601) ?? "", r.lastTs.map(FileTime.iso8601) ?? "",
                       r.author ?? "", r.source, r.path, r.ruleId, r.status ?? "",
                       r.tags.joined(separator: " "), r.references.joined(separator: " "), license, r.query]
            out += row.map(cell).joined(separator: sep) + "\r\n"
        }
        return out
    }
}
