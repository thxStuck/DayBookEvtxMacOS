import Foundation

/// Time-ordered set of event ids: either a contiguous id range (no allocation, used for
/// "everything in a time window") or an explicit sorted list.
public struct ResultSet: Sendable {
    public enum Storage: Sendable {
        case range(Range<UInt32>)
        case list([UInt32])
    }

    public let storage: Storage

    public init(range: Range<UInt32>) { storage = .range(range) }
    public init(list: [UInt32]) { storage = .list(list) }

    public static let empty = ResultSet(list: [])

    public var count: Int {
        switch storage {
        case let .range(r): r.count
        case let .list(l): l.count
        }
    }

    public var isEmpty: Bool { count == 0 }

    @inline(__always)
    public func id(at index: Int) -> UInt32 {
        switch storage {
        case let .range(r): r.lowerBound + UInt32(index)
        case let .list(l): l[index]
        }
    }

    public func ids(_ indices: Range<Int>) -> [UInt32] {
        switch storage {
        case let .range(r): (indices.lowerBound..<indices.upperBound).map { r.lowerBound + UInt32($0) }
        case let .list(l): Array(l[indices])
        }
    }

    public var list: [UInt32] {
        switch storage {
        case let .range(r): Array(r)
        case let .list(l): l
        }
    }

    /// Index of the first element >= id (for "jump to time").
    public func lowerBound(_ id: UInt32) -> Int {
        switch storage {
        case let .range(r): Int(min(max(id, r.lowerBound), r.upperBound) - r.lowerBound)
        case let .list(l): IdSet.lowerBound(l, id)
        }
    }

    public func intersect(_ ids: [UInt32]) -> ResultSet {
        switch storage {
        case let .range(r): ResultSet(list: Array(IdSet.range(ids, r.lowerBound, r.upperBound)))
        case let .list(l): ResultSet(list: IdSet.intersect(l, ids))
        }
    }

    public func subtract(_ ids: [UInt32]) -> ResultSet {
        switch storage {
        case let .range(r):
            let inside = IdSet.range(ids, r.lowerBound, r.upperBound)
            if inside.isEmpty { return self }
            var out = [UInt32]()
            out.reserveCapacity(r.count - inside.count)
            var j = inside.startIndex
            for id in r {
                if j < inside.endIndex, inside[j] == id { j += 1; continue }
                out.append(id)
            }
            return ResultSet(list: out)
        case let .list(l):
            return ResultSet(list: IdSet.subtract(l, ids))
        }
    }

    public func clamp(_ window: Range<UInt32>) -> ResultSet {
        switch storage {
        case let .range(r):
            let lo = max(r.lowerBound, window.lowerBound), hi = min(r.upperBound, window.upperBound)
            return ResultSet(range: lo..<max(lo, hi))
        case let .list(l):
            return ResultSet(list: Array(IdSet.range(l, window.lowerBound, window.upperBound)))
        }
    }

    /// Number of elements of `ids` (sorted) that belong to this set.
    public func countCommon(_ ids: [UInt32]) -> Int {
        switch storage {
        case let .range(r): IdSet.range(ids, r.lowerBound, r.upperBound).count
        case let .list(l): IdSet.intersect(l, ids).count
        }
    }
}

/// A click-to-filter chip: `key = value` or `key != value`. `key` is a field name or a
/// System key (`@Channel`, `@EventID`, …).
public struct FieldFilter: Hashable, Sendable, Identifiable {
    public var id = UUID()
    public var key: String
    public var value: String
    public var negated: Bool
    public var enabled = true

    public init(key: String, value: String, negated: Bool = false) {
        self.key = key
        self.value = value
        self.negated = negated
    }
}

extension CaseStore {
    /// Ids whose `key` equals `value` (case-insensitive unless `exact`).
    public func matching(key: String, value: String, exact: Bool = false) throws -> [UInt32] {
        if let kind = CaseSchema.SystemKey.entityKind(key) { return try entityMatching(kind, value) }
        if key == CaseSchema.SystemKey.tag { return try taggedEvents(color: value == "*" ? nil : value.lowercased()) }
        guard let k = keyId(key) else { return [] }
        let lists = try valueIds(value, exact: exact).map { try posting(key: k, value: $0) }
        return IdSet.union(lists, universe: eventCount)
    }

    /// Ids of events that have field `key` at all.
    public func eventsWithField(_ key: String) throws -> [UInt32] {
        guard let k = keyId(key) else { return [] }
        return IdSet.union(try allPostings(key: k).map(\.ids), universe: eventCount)
    }

    /// Applies chip filters and a time window (FILETIME bounds, inclusive) to all events.
    public func evaluate(_ filters: [FieldFilter], from: Int64? = nil, to: Int64? = nil) throws -> ResultSet {
        var lo: UInt32 = 0, hi = UInt32(eventCount)
        if let from { lo = lowerBound(time: from) }
        if let to { hi = lowerBound(time: to == .max ? to : to + 1) }
        var result = ResultSet(range: lo..<max(lo, hi))
        let active = filters.filter(\.enabled)
        // Positive chips on the same field are alternatives (Channel = A or Channel = B);
        // different fields narrow each other. Positives first: they shrink the set the
        // negative ones have to scan.
        var byKey: [String: [[UInt32]]] = [:]
        var order: [String] = []
        for f in active where !f.negated {
            if byKey[f.key] == nil { order.append(f.key) }
            byKey[f.key, default: []].append(try matching(key: f.key, value: f.value))
        }
        for key in order {
            result = result.intersect(IdSet.union(byKey[key] ?? [], universe: eventCount))
            if result.isEmpty { return result }
        }
        for f in active where f.negated {
            result = result.subtract(try matching(key: f.key, value: f.value))
        }
        return result
    }
}

extension CaseStore {
    /// Number of events per (source file, record flag) — for the case information screen.
    public func flagCountsBySource() throws -> [Int: [String: Int]] {
        guard let fk = keyId(CaseSchema.SystemKey.flag), let sk = keyId(CaseSchema.SystemKey.source) else { return [:] }
        let flags = try allPostings(key: fk)
        let flagNames = try strings(flags.map(\.value))
        var out: [Int: [String: Int]] = [:]
        for (sv, ids) in try allPostings(key: sk) {
            let name = string(sv)
            guard let src = sources.firstIndex(where: { $0.name == name }) else { continue }
            for (i, f) in flags.enumerated() {
                let n = IdSet.intersect(ids, f.ids).count
                if n > 0 { out[src, default: [:]][flagNames[i]] = n }
            }
        }
        return out
    }
}
