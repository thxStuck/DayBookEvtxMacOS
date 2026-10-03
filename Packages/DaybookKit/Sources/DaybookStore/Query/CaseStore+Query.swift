import Foundation

/// Value-dictionary and posting-list primitives used by the DQL engine. All SQL here is
/// fixed text with bound parameters; user input only ever arrives as bound values.
extension CaseStore {
    /// Ids of dictionary strings matching a SQL LIKE pattern (case-insensitive). Uses the
    /// trigram index when available; the caller re-checks candidates precisely, because
    /// LIKE treats `_` and `%` in user text as wildcards.
    func likeCandidates(_ pattern: String, literalLength: Int) throws -> [UInt32] {
        try queryLock.withLock {
            let sql = fullTextReady && literalLength >= 3
                ? "SELECT rowid FROM sfts WHERE s LIKE ?"
                : "SELECT id FROM str WHERE s LIKE ?"
            let st = try queryDB.prepare(sql)
            st.bind(1, pattern)
            var out: [UInt32] = []
            while try st.step() { out.append(UInt32(st.int64(0))) }
            return out
        }
    }

    /// Distinct value ids of a field (from its posting lists).
    func values(ofKey key: UInt32) throws -> [(value: UInt32, count: Int)] {
        try queryLock.withLock {
            let st = try queryDB.prepare("SELECT v, n FROM post WHERE k = ?")
            st.bind(1, Int64(key))
            var out: [(UInt32, Int)] = []
            while try st.step() { out.append((UInt32(st.int64(0)), Int(st.int64(1)))) }
            return out.map { (value: $0.0, count: $0.1) }
        }
    }

    /// Value ids of `key` whose numeric value satisfies `op`.
    func numericValues(key: UInt32, op: String, _ a: Int64, _ b: Int64 = 0) throws -> [UInt32] {
        let cond: String
        switch op {
        case "<": cond = "s.num < ?1"
        case "<=": cond = "s.num <= ?1"
        case ">": cond = "s.num > ?1"
        case ">=": cond = "s.num >= ?1"
        default: cond = "s.num BETWEEN ?1 AND ?2"
        }
        return try queryLock.withLock {
            let st = try queryDB.prepare("SELECT p.v FROM post p JOIN str s ON s.id = p.v WHERE p.k = ?3 AND s.num IS NOT NULL AND \(cond)")
            st.bind(1, a).bind(2, b).bind(3, Int64(key))
            var out: [UInt32] = []
            while try st.step() { out.append(UInt32(st.int64(0))) }
            return out
        }
    }

    /// Posting lists of `key` restricted to the given value ids (or of every field when
    /// `key` is nil), decoded.
    func postings(key: UInt32?, values: [UInt32]) throws -> [[UInt32]] {
        guard !values.isEmpty else { return [] }
        return try queryLock.withLock {
            var lists: [[UInt32]] = []
            func collect(_ st: Statement) throws {
                while try st.step() {
                    let n = Int(st.int64(0))
                    lists.append(st.withBlob(1) { Varint.decodeDeltas($0, count: n) })
                }
            }
            if let key, values.count > 20_000 {
                // Huge candidate sets: scan the field's postings and filter in memory.
                let wanted = Set(values)
                let st = try queryDB.prepare("SELECT n, ids, v FROM post WHERE k = ?")
                st.bind(1, Int64(key))
                while try st.step() {
                    guard wanted.contains(UInt32(st.int64(2))) else { continue }
                    let n = Int(st.int64(0))
                    lists.append(st.withBlob(1) { Varint.decodeDeltas($0, count: n) })
                }
                return lists
            }
            for start in stride(from: 0, to: values.count, by: 20_000) {
                let chunk = values[start..<min(start + 20_000, values.count)]
                let json = "[" + chunk.map(String.init).joined(separator: ",") + "]"
                let st: Statement
                if let key {
                    st = try queryDB.prepare("SELECT n, ids FROM post WHERE k = ? AND v IN (SELECT value FROM json_each(?))")
                    st.bind(1, Int64(key)).bind(2, json)
                } else {
                    st = try queryDB.prepare("SELECT n, ids FROM post WHERE v IN (SELECT value FROM json_each(?))")
                    st.bind(1, json)
                }
                try collect(st)
            }
            return lists
        }
    }

    /// Every posting list of a field (for `exists`, group by and sort).
    public func allPostings(key: UInt32) throws -> [(value: UInt32, ids: [UInt32])] {
        try queryLock.withLock {
            let st = try queryDB.prepare("SELECT v, n, ids FROM post WHERE k = ?")
            st.bind(1, Int64(key))
            var out: [(UInt32, [UInt32])] = []
            while try st.step() {
                let n = Int(st.int64(1))
                out.append((UInt32(st.int64(0)), st.withBlob(2) { Varint.decodeDeltas($0, count: n) }))
            }
            return out.map { (value: $0.0, ids: $0.1) }
        }
    }

    /// Number of distinct values of a field.
    public func distinctValues(_ key: String) throws -> Int {
        guard let k = keyId(key) else { return 0 }
        return try queryLock.withLock {
            let st = try queryDB.prepare("SELECT count(*) FROM post WHERE k = ?")
            st.bind(1, Int64(k))
            return try st.step() ? Int(st.int64(0)) : 0
        }
    }
}
