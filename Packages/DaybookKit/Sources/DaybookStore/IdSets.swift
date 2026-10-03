import Foundation

/// Event ids are positions in time order (0-based), so every sorted id list is also a
/// time-ordered list. Posting lists are stored delta + LEB128-varint encoded.
public enum Varint {
    public static func encodeDeltas(_ ids: [UInt32]) -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(ids.count + ids.count / 2)
        var prev: UInt32 = 0
        for (i, id) in ids.enumerated() {
            var d = i == 0 ? id : id &- prev
            prev = id
            while d >= 0x80 {
                out.append(UInt8(truncatingIfNeeded: d) | 0x80)
                d >>= 7
            }
            out.append(UInt8(d))
        }
        return out
    }

    public static func decodeDeltas(_ buf: UnsafeRawBufferPointer, count hint: Int = 0) -> [UInt32] {
        var out = [UInt32]()
        out.reserveCapacity(hint)
        var acc: UInt32 = 0
        var shift: UInt32 = 0
        var prev: UInt32 = 0
        var first = true
        for byte in buf {
            acc |= UInt32(byte & 0x7F) << shift
            if byte & 0x80 != 0 {
                shift += 7
                continue
            }
            prev = first ? acc : prev &+ acc
            first = false
            out.append(prev)
            acc = 0
            shift = 0
        }
        return out
    }

    /// Unsigned varint helpers for compact (key, value) pair blobs.
    static func append(_ v: UInt32, to out: inout [UInt8]) {
        var x = v
        while x >= 0x80 {
            out.append(UInt8(truncatingIfNeeded: x) | 0x80)
            x >>= 7
        }
        out.append(UInt8(x))
    }

    static func decodeAll(_ buf: UnsafeRawBufferPointer) -> [UInt32] {
        var out = [UInt32]()
        var acc: UInt32 = 0
        var shift: UInt32 = 0
        for byte in buf {
            acc |= UInt32(byte & 0x7F) << shift
            if byte & 0x80 != 0 { shift += 7; continue }
            out.append(acc)
            acc = 0
            shift = 0
        }
        return out
    }
}

/// Set algebra over sorted, duplicate-free `[UInt32]`.
public enum IdSet {
    public static func intersect(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        if a.isEmpty || b.isEmpty { return [] }
        let (small, large) = a.count <= b.count ? (a, b) : (b, a)
        var out = [UInt32]()
        out.reserveCapacity(small.count)
        if large.count / small.count >= 16 {
            // Galloping: binary-search each element of the small list in the remaining large list.
            var lo = 0
            for x in small {
                var step = 1
                var hi = lo
                while hi < large.count && large[hi] < x { lo = hi; hi += step; step <<= 1 }
                hi = min(hi, large.count)
                var l = lo, h = hi
                while l < h {
                    let m = (l + h) >> 1
                    if large[m] < x { l = m + 1 } else { h = m }
                }
                lo = l
                if lo < large.count && large[lo] == x { out.append(x); lo += 1 }
                if lo >= large.count { break }
            }
            return out
        }
        var i = 0, j = 0
        while i < small.count && j < large.count {
            let x = small[i], y = large[j]
            if x < y { i += 1 } else if y < x { j += 1 } else { out.append(x); i += 1; j += 1 }
        }
        return out
    }

    public static func subtract(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        if a.isEmpty || b.isEmpty { return a }
        var out = [UInt32]()
        out.reserveCapacity(a.count)
        var j = 0
        for x in a {
            while j < b.count && b[j] < x { j += 1 }
            if j < b.count && b[j] == x { continue }
            out.append(x)
        }
        return out
    }

    /// Union of many lists. Uses a bitmap over the id universe when the input is large.
    public static func union(_ lists: [[UInt32]], universe: Int) -> [UInt32] {
        let nonEmpty = lists.filter { !$0.isEmpty }
        if nonEmpty.isEmpty { return [] }
        if nonEmpty.count == 1 { return nonEmpty[0] }
        let total = nonEmpty.reduce(0) { $0 + $1.count }
        if nonEmpty.count == 2 && total < universe / 8 {
            return merge(nonEmpty[0], nonEmpty[1])
        }
        var bits = Bitmap(count: universe)
        for l in nonEmpty { for id in l where Int(id) < universe { bits.insert(id) } }
        return bits.ids()
    }

    static func merge(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        var out = [UInt32]()
        out.reserveCapacity(a.count + b.count)
        var i = 0, j = 0
        while i < a.count && j < b.count {
            if a[i] < b[j] { out.append(a[i]); i += 1 } else if b[j] < a[i] { out.append(b[j]); j += 1 } else {
                out.append(a[i]); i += 1; j += 1
            }
        }
        out.append(contentsOf: a[i...])
        out.append(contentsOf: b[j...])
        return out
    }

    /// 0..<universe minus `a`.
    public static func complement(_ a: [UInt32], universe: Int) -> [UInt32] {
        var out = [UInt32]()
        out.reserveCapacity(max(0, universe - a.count))
        var j = 0
        for id in 0..<UInt32(universe) {
            if j < a.count && a[j] == id { j += 1; continue }
            out.append(id)
        }
        return out
    }

    /// Ids within [lo, hi) — ids are time-ordered, so a time range is an id range.
    public static func range(_ a: [UInt32], _ lo: UInt32, _ hi: UInt32) -> ArraySlice<UInt32> {
        let l = lowerBound(a, lo), h = lowerBound(a, hi)
        return a[l..<max(l, h)]
    }

    public static func lowerBound(_ a: [UInt32], _ x: UInt32) -> Int {
        var l = 0, h = a.count
        while l < h {
            let m = (l + h) >> 1
            if a[m] < x { l = m + 1 } else { h = m }
        }
        return l
    }
}

public struct Bitmap {
    var words: [UInt64]
    public init(count: Int) { words = [UInt64](repeating: 0, count: (count + 63) / 64) }
    @inline(__always) public mutating func insert(_ id: UInt32) { words[Int(id >> 6)] |= 1 << UInt64(id & 63) }
    @inline(__always) public func contains(_ id: UInt32) -> Bool { words[Int(id >> 6)] & (1 << UInt64(id & 63)) != 0 }
    public func ids() -> [UInt32] {
        var out = [UInt32]()
        for (wi, w) in words.enumerated() where w != 0 {
            var x = w
            while x != 0 {
                let b = x.trailingZeroBitCount
                out.append(UInt32(wi * 64 + b))
                x &= x - 1
            }
        }
        return out
    }
}
