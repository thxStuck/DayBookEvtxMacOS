import Foundation

/// An event with selected fields resolved to strings (for session / process analysis).
public struct FieldEvent: Sendable {
    public let id: UInt32
    public let ts: Int64
    public let computer: String
    public let eventId: UInt16
    public let fields: [String: String]

    public func f(_ name: String) -> String? {
        guard let v = fields[name]?.trimmingCharacters(in: .whitespaces), !v.isEmpty, v != "-" else { return nil }
        return v
    }
}

extension CaseStore {
    /// Loads events with the given field names resolved (first value per field).
    public func fieldEvents(_ ids: [UInt32], names: Set<String>) throws -> [FieldEvent] {
        let wanted = Set(names.compactMap { exactKeyId($0) })
        var out: [FieldEvent] = []
        out.reserveCapacity(ids.count)
        for start in stride(from: 0, to: ids.count, by: 4096) {
            let rows = try rows(Array(ids[start..<min(start + 4096, ids.count)]))
            var need = Set<UInt32>()
            for r in rows { for p in r.pairs where wanted.contains(p.key) { need.insert(p.value) } }
            let list = Array(need)
            let str = Dictionary(uniqueKeysWithValues: zip(list, try strings(list)))
            for r in rows {
                var f: [String: String] = [:]
                for p in r.pairs where wanted.contains(p.key) {
                    let name = keyName(p.key)
                    if f[name] == nil { f[name] = str[p.value] }
                }
                out.append(FieldEvent(id: r.id, ts: r.ts, computer: r.computer, eventId: r.eventId, fields: f))
            }
        }
        return out
    }

    /// Ids of events with `key = value` for each value (union), intersected with `channel` when given.
    func events(_ key: String, in values: [String], channel: String? = nil) throws -> [UInt32] {
        var ids = IdSet.union(try values.map { try matching(key: key, value: $0) }, universe: eventCount)
        if let channel { ids = IdSet.intersect(ids, try matching(key: CaseSchema.SystemKey.channel, value: channel)) }
        return ids
    }

    /// Boot times per host (Kernel-General 12, EventLog 6005, Security 4608), used to split
    /// logon ids and process ids, which are only unique within one boot.
    func bootTimes() throws -> [String: [Int64]] {
        let ids = IdSet.union([
            IdSet.intersect(try matching(key: CaseSchema.SystemKey.eventId, value: "12"),
                            try matching(key: CaseSchema.SystemKey.provider, value: "Microsoft-Windows-Kernel-General")),
            IdSet.intersect(try matching(key: CaseSchema.SystemKey.eventId, value: "6005"),
                            try matching(key: CaseSchema.SystemKey.provider, value: "EventLog")),
            IdSet.intersect(try matching(key: CaseSchema.SystemKey.eventId, value: "4608"),
                            try matching(key: CaseSchema.SystemKey.channel, value: "Security")),
        ], universe: eventCount)
        var out: [String: [Int64]] = [:]
        for r in try rows(ids) {
            guard let h = EntityNames.hostKey(r.computer) else { continue }
            out[h, default: []].append(r.ts)
        }
        // Events of one boot (12, 6005, 4608) arrive within seconds: collapse them.
        for (h, list) in out {
            var merged: [Int64] = []
            for t in list.sorted() where merged.last.map({ t - $0 > 300 * 10_000_000 }) ?? true { merged.append(t) }
            out[h] = merged
        }
        return out
    }
}

/// Boot segment of a time on a host: number of boots at or before it.
func bootSegment(_ boots: [Int64]?, _ ts: Int64) -> Int {
    guard let boots else { return 0 }
    var lo = 0, hi = boots.count
    while lo < hi {
        let m = (lo + hi) >> 1
        if boots[m] <= ts { lo = m + 1 } else { hi = m }
    }
    return lo
}

public struct LogonSession: Sendable, Identifiable, Hashable {
    public let id: Int
    public let host: String
    public let logonId: String
    public let user: String
    public let userSid: String?
    public let logonType: Int?
    public let workstation: String?
    public let ip: String?
    public let authPackage: String?
    public let logonProcess: String?
    public let elevated: String?
    public let linkedLogonId: String?
    public let start: Int64
    public let end: Int64?
    public let startEvent: UInt32
    public let endEvent: UInt32?
    public let privileged: Bool
    public let bootSegment: Int
    public var duration: Int64? { end.map { $0 - start } }
}

public struct SessionAnalysis: Sendable {
    public let sessions: [LogonSession]
    public let unmatchedEnds: Int
    public let hostsWithoutBootInfo: [String]
}

/// Reconstructs logon sessions: 4624 start → 4634/4647 end with the same TargetLogonId
/// on the same host within the same boot; 4672 (SubjectLogonId) marks privileged ones.
public enum SessionBuilder {
    public static func build(_ store: CaseStore) throws -> SessionAnalysis {
        let channel = "Security"
        let starts = try store.events(CaseSchema.SystemKey.eventId, in: ["4624"], channel: channel)
        let ends = try store.events(CaseSchema.SystemKey.eventId, in: ["4634", "4647"], channel: channel)
        let privs = try store.events(CaseSchema.SystemKey.eventId, in: ["4672"], channel: channel)
        let boots = try store.bootTimes()

        let names: Set<String> = ["TargetLogonId", "TargetUserName", "TargetDomainName", "TargetUserSid", "LogonType",
                                  "WorkstationName", "IpAddress", "AuthenticationPackageName", "LogonProcessName",
                                  "ElevatedToken", "TargetLinkedLogonId", "SubjectLogonId"]
        func key(_ e: FieldEvent, _ field: String) -> String? {
            guard let host = EntityNames.hostKey(e.computer), let id = e.f(field)?.lowercased() else { return nil }
            return "\(host)|\(bootSegment(boots[host], e.ts))|\(id)"
        }
        var endTimes: [String: [(Int64, UInt32)]] = [:]
        for e in try store.fieldEvents(ends, names: names) {
            if let k = key(e, "TargetLogonId") { endTimes[k, default: []].append((e.ts, e.id)) }
        }
        var privileged = Set<String>()
        for e in try store.fieldEvents(privs, names: names) {
            if let k = key(e, "SubjectLogonId") { privileged.insert(k) }
        }
        var used = Set<UInt32>()
        var sessions: [LogonSession] = []
        for e in try store.fieldEvents(starts, names: names) {
            guard let k = key(e, "TargetLogonId") else { continue }
            let endMatch = endTimes[k]?.filter { $0.0 >= e.ts && !used.contains($0.1) }.min { $0.0 < $1.0 }
            if let m = endMatch { used.insert(m.1) }
            let host = EntityNames.hostKey(e.computer) ?? e.computer
            let user = [e.f("TargetDomainName"), e.f("TargetUserName")].compactMap { $0 }.joined(separator: "\\")
            sessions.append(LogonSession(
                id: sessions.count, host: e.computer, logonId: e.f("TargetLogonId") ?? "?", user: user,
                userSid: e.f("TargetUserSid"), logonType: e.f("LogonType").flatMap { Int($0) },
                workstation: e.f("WorkstationName"),
                ip: e.f("IpAddress").map { $0.hasPrefix("::ffff:") ? String($0.dropFirst(7)) : $0 },
                authPackage: e.f("AuthenticationPackageName"), logonProcess: e.f("LogonProcessName"),
                elevated: e.f("ElevatedToken").map(EventDescriber.param), linkedLogonId: e.f("TargetLinkedLogonId"),
                start: e.ts, end: endMatch?.0, startEvent: e.id, endEvent: endMatch?.1,
                privileged: privileged.contains(k), bootSegment: bootSegment(boots[host], e.ts)))
        }
        let totalEnds = endTimes.values.reduce(0) { $0 + $1.count }
        let hostsNoBoot = Set(sessions.map { EntityNames.hostKey($0.host) ?? $0.host }).filter { boots[$0] == nil }.sorted()
        return SessionAnalysis(sessions: sessions, unmatchedEnds: totalEnds - used.count, hostsWithoutBootInfo: hostsNoBoot)
    }
}

/// One RDP session chain from TerminalServices-LocalSessionManager (21 logon, 22 shell,
/// 24 disconnect, 25 reconnect, 23 logoff) per host and session id.
public struct RDPSession: Sendable, Identifiable, Hashable {
    public let id: Int
    public let host: String
    public let sessionId: String
    public let user: String
    public let address: String
    public let start: Int64
    public let end: Int64?
    public let events: [UInt32]
    public let steps: String
}

public enum RDPSessionBuilder {
    public static let channel = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"

    public static func build(_ store: CaseStore) throws -> [RDPSession] {
        let ids = try store.events(CaseSchema.SystemKey.eventId, in: ["21", "22", "23", "24", "25", "39", "40"], channel: channel)
        let events = try store.fieldEvents(ids, names: ["User", "Address", "SessionID", "Session", "Reason"])
        var open: [String: (start: Int64, user: String, address: String, ids: [UInt32], steps: [String])] = [:]
        var out: [RDPSession] = []
        func close(_ key: String, end: Int64?) {
            guard let s = open.removeValue(forKey: key) else { return }
            let parts = key.split(separator: "|", maxSplits: 1).map(String.init)
            out.append(RDPSession(id: out.count, host: parts[0], sessionId: parts.count > 1 ? parts[1] : "?", user: s.user,
                                  address: s.address, start: s.start, end: end, events: s.ids, steps: s.steps.joined(separator: " → ")))
        }
        for e in events.sorted(by: { $0.ts < $1.ts }) {
            let sid = e.f("SessionID") ?? e.f("Session") ?? "?"
            let key = e.computer + "|" + sid
            let step: String
            switch e.eventId {
            case 21: step = "21 вход"
            case 22: step = "22 оболочка"
            case 23: step = "23 выход"
            case 24: step = "24 отключение"
            case 25: step = "25 переподключение"
            case 39: step = "39 отключён другим сеансом"
            case 40: step = "40 отключение (код \(e.f("Reason") ?? "?"))"
            default: step = String(e.eventId)
            }
            if e.eventId == 21 { close(key, end: nil) }
            var s = open[key] ?? (e.ts, e.f("User") ?? "?", e.f("Address") ?? "?", [], [])
            if s.user == "?", let u = e.f("User") { s.user = u }
            if s.address == "?", let a = e.f("Address") { s.address = a }
            s.ids.append(e.id)
            s.steps.append(step)
            open[key] = s
            if e.eventId == 23 { close(key, end: e.ts) }
        }
        for key in Array(open.keys) { close(key, end: nil) }
        return out.sorted { $0.start < $1.start }
    }
}
