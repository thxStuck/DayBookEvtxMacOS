import Foundation

public struct EventTag: Sendable, Hashable, Identifiable {
    public let id: Int64
    public let event: UInt32
    public var color: String
    public var note: String
    public let created: Double
}

/// Analyst annotations (bookmarks with colour and note). Stored with a stable key
/// (source SHA-256 + chunk + record offset) so they survive a case rebuild; the event id
/// is kept as a cache. Writes use their own read-write connection (the database is WAL).
public final class CaseAnnotations: @unchecked Sendable {
    public static let colors = ["red", "orange", "yellow", "green", "blue", "purple"]

    private let db: SQLiteDB
    private let lock = NSLock()
    private let store: CaseStore

    public init(store: CaseStore) throws {
        self.store = store
        db = try SQLiteDB(path: store.url.appendingPathComponent(CaseSchema.databaseName).path)
        try db.exec("PRAGMA busy_timeout = 5000")
    }

    public func all() throws -> [EventTag] {
        try lock.withLock {
            let st = try db.prepare("SELECT id, ev, color, note, created FROM tag ORDER BY ev")
            var out: [EventTag] = []
            while try st.step() {
                out.append(EventTag(id: st.int64(0), event: UInt32(st.int64(1)), color: st.string(2),
                                    note: st.string(3), created: Double(st.int64(4))))
            }
            return out
        }
    }

    /// Sets (or replaces) the bookmark of an event.
    @discardableResult
    public func set(event: UInt32, color: String, note: String) throws -> EventTag {
        let location = try store.location(of: event)
        let now = Date().timeIntervalSince1970
        return try lock.withLock {
            try db.transaction {
                let del = try db.prepare("DELETE FROM tag WHERE ev = ?")
                try del.bind(1, Int64(event)).run()
                let ins = try db.prepare("INSERT INTO tag(src_sha, chunk, off, ev, tag, note, color, created) VALUES (?,?,?,?,?,?,?,?)")
                try ins.bind(1, location.sha256).bind(2, location.chunk).bind(3, location.offset).bind(4, Int64(event))
                    .bind(5, "bookmark").bind(6, note).bind(7, color).bind(8, Int64(now)).run()
                return EventTag(id: db.lastInsertRowID, event: event, color: color, note: note, created: now)
            }
        }
    }

    public func remove(event: UInt32) throws {
        try lock.withLock {
            let st = try db.prepare("DELETE FROM tag WHERE ev = ?")
            try st.bind(1, Int64(event)).run()
        }
    }
}

extension CaseStore {
    public struct EventLocation: Sendable {
        public let sha256: String
        public let chunk: Int
        public let offset: Int
    }

    func location(of event: UInt32) throws -> EventLocation {
        try rowsLock.withLock {
            let st = try rowsDB.prepare("SELECT src, chunk, off FROM ev WHERE id = ?")
            st.bind(1, Int64(event))
            guard try st.step() else { throw SQLiteError(code: 0, message: "event \(event) not found") }
            let src = Int(st.int64(0))
            return EventLocation(sha256: src < sources.count ? sources[src].sha256 : "", chunk: Int(st.int64(1)), offset: Int(st.int64(2)))
        }
    }

    /// Ids of bookmarked events (optionally of one colour), sorted.
    public func taggedEvents(color: String? = nil) throws -> [UInt32] {
        try queryLock.withLock {
            let st = try queryDB.prepare(color == nil ? "SELECT ev FROM tag ORDER BY ev" : "SELECT ev FROM tag WHERE color = ? ORDER BY ev")
            if let color { st.bind(1, color) }
            var out: [UInt32] = []
            while try st.step() { out.append(UInt32(st.int64(0))) }
            return Array(Set(out)).sorted()
        }
    }
}
