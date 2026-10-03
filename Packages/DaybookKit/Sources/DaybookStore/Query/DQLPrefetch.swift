import Foundation

/// Multi-pattern substring search (Aho–Corasick) over lowercased UTF-8 bytes, as a dense
/// DFA over byte classes (bytes that occur in no needle share class 0).
struct AhoCorasick {
    let classOf: [UInt8]
    let classCount: Int
    private(set) var delta: [Int32] = []
    private(set) var terminal: [Int32] = []
    private(set) var dictLink: [Int32] = []
    let lengths: [Int]

    init(_ needles: [[UInt8]]) {
        var cls = [UInt8](repeating: 0, count: 256)
        var n = 1
        for needle in needles {
            for b in needle where cls[Int(b)] == 0 {
                cls[Int(b)] = UInt8(n)
                n += 1
            }
        }
        classOf = cls
        classCount = n
        lengths = needles.map(\.count)

        // Trie (goto) as sparse edges, then BFS for failure links and the full DFA.
        var edges: [Int: Int32] = [:]
        var term: [Int32] = [-1]
        for (i, needle) in needles.enumerated() {
            var node = 0
            for b in needle {
                let k = node * n + Int(cls[Int(b)])
                if let next = edges[k] {
                    node = Int(next)
                } else {
                    term.append(-1)
                    let next = term.count - 1
                    edges[k] = Int32(next)
                    node = next
                }
            }
            term[node] = Int32(i)
        }
        let count = term.count
        var d = [Int32](repeating: 0, count: count * n)
        var fail = [Int32](repeating: 0, count: count)
        var dict = [Int32](repeating: -1, count: count)
        var queue: [Int] = []
        queue.reserveCapacity(count)
        for c in 1..<n {
            if let child = edges[c] {
                d[c] = child
                fail[Int(child)] = 0
                queue.append(Int(child))
            }
        }
        var head = 0
        while head < queue.count {
            let u = queue[head]
            head += 1
            let f = Int(fail[u])
            dict[u] = term[f] >= 0 ? Int32(f) : dict[f]
            for c in 0..<n {
                if c > 0, let child = edges[u * n + c] {
                    d[u * n + c] = child
                    fail[Int(child)] = d[f * n + c]
                    queue.append(Int(child))
                } else {
                    d[u * n + c] = d[f * n + c]
                }
            }
        }
        delta = d
        terminal = term
        dictLink = dict
    }

    /// Calls `match(needle, endIndex)` for every occurrence of every needle.
    @inline(__always)
    func scan(_ text: UnsafeBufferPointer<UInt8>, _ match: (Int, Int) -> Void) {
        var node = 0
        let n = classCount
        delta.withUnsafeBufferPointer { d in
            terminal.withUnsafeBufferPointer { t in
                dictLink.withUnsafeBufferPointer { dl in
                    for i in 0..<text.count {
                        node = Int(d[node * n + Int(classOf[Int(text[i])])])
                        var o = t[node] >= 0 ? node : Int(dl[node])
                        while o >= 0 {
                            match(Int(t[o]), i)
                            o = Int(dl[o])
                        }
                    }
                }
            }
        }
    }
}

/// `*` / `?` glob over lowercased UTF-8 (`?` = one Unicode scalar), anchored at both ends.
struct ByteGlob {
    let pattern: [UInt8]

    func matches(_ s: UnsafeBufferPointer<UInt8>) -> Bool {
        var i = 0, p = 0
        var star = -1, mark = 0
        @inline(__always) func scalarEnd(_ at: Int) -> Int {
            var j = at + 1
            while j < s.count, s[j] & 0xC0 == 0x80 { j += 1 }
            return j
        }
        while i < s.count {
            if p < pattern.count, pattern[p] == UInt8(ascii: "?") {
                i = scalarEnd(i)
                p += 1
            } else if p < pattern.count, pattern[p] == UInt8(ascii: "*") {
                star = p
                mark = i
                p += 1
            } else if p < pattern.count, pattern[p] == s[i] {
                i += 1
                p += 1
            } else if star >= 0 {
                p = star + 1
                mark = scalarEnd(mark)
                i = mark
            } else {
                return false
            }
        }
        while p < pattern.count, pattern[p] == UInt8(ascii: "*") { p += 1 }
        return p == pattern.count
    }
}

extension DQLEngine {
    /// Evaluates many contains / startswith / endswith / like predicates at once and puts
    /// the results in the pattern cache. Every distinct value of a field is lowercased and
    /// scanned once for all needles of that field (Aho–Corasick) instead of one dictionary
    /// search per predicate — this is what makes running thousands of detection rules fast.
    public func prefetch(_ requests: [(field: String, op: DQLOp, value: String)]) throws {
        struct Group {
            var needles: [String: Int] = [:]      // lowercased needle → index
            var needleList: [[UInt8]] = []
            var uses: [(original: String, needle: Int, mode: PatternMode)] = []
            var globs: [String: Int] = [:]
            var globList: [ByteGlob] = []
            var globUses: [(original: String, glob: Int)] = []
        }
        // Bucket requests per field first (in-place appends), then build each group once.
        var buckets: [UInt32: [(original: String, mode: PatternMode)]] = [:]
        for r in requests {
            guard case let .key(k, _) = try? resolve(r.field), !r.value.isEmpty else { continue }
            let mode: PatternMode
            switch r.op {
            case .contains, .notContains: mode = .contains
            case .startswith: mode = .prefix
            case .endswith: mode = .suffix
            case .like: mode = .wildcard
            default: continue
            }
            buckets[k, default: []].append((r.value, mode))
        }
        var groups: [UInt32: Group] = [:]
        for (k, list) in buckets {
            var g = Group()
            var seen = Set<String>()
            let cached = cacheLock.withLock { Set(list.map { Self.patternKey(k, $0.original, $0.mode) }.filter { patternCache[$0] != nil }) }
            for (original, mode) in list {
                let key = Self.patternKey(k, original, mode)
                guard !cached.contains(key), seen.insert(key).inserted else { continue }
                let lower = original.lowercased()
                if mode == .wildcard {
                    let idx: Int
                    if let i = g.globs[lower] { idx = i } else {
                        g.globList.append(ByteGlob(pattern: Array(lower.utf8)))
                        idx = g.globList.count - 1
                        g.globs[lower] = idx
                    }
                    g.globUses.append((original, idx))
                } else {
                    let idx: Int
                    if let i = g.needles[lower] { idx = i } else {
                        g.needleList.append(Array(lower.utf8))
                        idx = g.needleList.count - 1
                        g.needles[lower] = idx
                    }
                    g.uses.append((original, idx, mode))
                }
            }
            if !g.uses.isEmpty || !g.globUses.isEmpty { groups[k] = g }
        }

        for (k, g) in groups {
            try checkCancel()
            // Automata over at most ~64k needle bytes each (bounded DFA size).
            var automata: [(ac: AhoCorasick, offset: Int)] = []
            var start = 0
            while start < g.needleList.count {
                var end = start, bytes = 0
                while end < g.needleList.count, bytes < 65_536 || end == start {
                    bytes += g.needleList[end].count
                    end += 1
                }
                automata.append((AhoCorasick(Array(g.needleList[start..<end])), start))
                start = end
            }
            var contains = [[UInt32]](repeating: [], count: g.needleList.count)
            var prefix = [[UInt32]](repeating: [], count: g.needleList.count)
            var suffix = [[UInt32]](repeating: [], count: g.needleList.count)
            var globHits = [[UInt32]](repeating: [], count: g.globList.count)
            var stamp = [Int](repeating: -1, count: g.needleList.count)

            let values = try store.values(ofKey: k).map(\.value)
            var serial = 0
            for batchStart in stride(from: 0, to: values.count, by: 4096) {
                try checkCancel()
                let batch = Array(values[batchStart..<min(batchStart + 4096, values.count)])
                for (id, s) in zip(batch, try store.strings(batch)) {
                    serial += 1
                    var lower = s.lowercased()
                    lower.withUTF8 { text in
                        let last = text.count - 1
                        for (ac, offset) in automata {
                            ac.scan(text) { local, end in
                                let n = offset + local
                                if stamp[n] != serial {
                                    stamp[n] = serial
                                    contains[n].append(id)
                                }
                                if end + 1 == ac.lengths[local], prefix[n].last != id { prefix[n].append(id) }
                                if end == last, suffix[n].last != id { suffix[n].append(id) }
                            }
                        }
                        for (gi, glob) in g.globList.enumerated() where glob.matches(text) { globHits[gi].append(id) }
                    }
                }
            }

            var results: [(String, ResultSet)] = []
            for u in g.uses {
                let ids: [UInt32]
                switch u.mode {
                case .contains: ids = contains[u.needle]
                case .prefix: ids = prefix[u.needle]
                default: ids = suffix[u.needle]
                }
                results.append((Self.patternKey(k, u.original, u.mode), postingUnion(k, ids)))
            }
            for u in g.globUses {
                results.append((Self.patternKey(k, u.original, .wildcard), postingUnion(k, globHits[u.glob])))
            }
            cacheLock.withLock { for (key, r) in results { patternCache[key] = r } }
        }
    }
}
