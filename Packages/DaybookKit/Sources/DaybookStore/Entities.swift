import Foundation

public enum EntityKind: Int, Sendable, CaseIterable {
    case host = 1, user = 2, ip = 3
}

public enum EntityRole: Int, Sendable, CaseIterable {
    case logging = 1      // the Computer that wrote the event
    case source = 2       // where an action came from (WorkstationName, IpAddress, …)
    case target = 3       // who/what the action was about (TargetUserName, …)
    case subject = 4      // who performed it (SubjectUserName, Sysmon User, …)
    case account = 5      // machine account (NAME$) seen in a user field
    case destination = 6  // network destination
    case system = 7       // System/Security/UserID
}

public struct EntityInfo: Sendable, Identifiable, Hashable {
    public let id: Int
    public let kind: EntityKind
    public let key: String
    public let display: String
    public let domain: String?
    public let sid: String?
    public let aliases: [String]
    public let firstTs: Int64?
    public let lastTs: Int64?
    public let events: Int
    public let builtin: Bool
    public let roles: [Int: Int]   // EntityRole.rawValue → event count
}

public struct EntityLink: Sendable, Hashable {
    public let other: Int
    public let count: Int
    public let firstTs: Int64
    public let lastTs: Int64
}

/// Normalisation rules shared by the builder and lookups.
public enum EntityNames {
    static let builtinDomains: Set<String> = ["NT AUTHORITY", "NT-AUTORITÄT", "AUTORITE NT", "NT AUTHORITY",
                                              "WINDOW MANAGER", "FONT DRIVER HOST", "NT SERVICE", "IIS APPPOOL",
                                              "NT VIRTUAL MACHINE", "BUILTIN", "NT-AUTORITAET"]
    static let builtinNames: Set<String> = ["system", "local service", "network service", "anonymous logon",
                                            "lokaler dienst", "netzwerkdienst", "-"]

    public static func isIP(_ s: String) -> Bool {
        var v4 = in_addr(), v6 = in6_addr()
        return inet_pton(AF_INET, s, &v4) == 1 || inet_pton(AF_INET6, s, &v6) == 1
    }

    /// Canonical IP (inet_ntop form, IPv4-mapped IPv6 unwrapped); nil for
    /// loopback/unspecified/garbage. "0:0:0:0:0:0:0:1" and "::1" are the same address.
    public static func ipKey(_ raw: String) -> String? {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.hasPrefix("["), let close = s.firstIndex(of: "]") { s = String(s[s.index(after: s.startIndex)..<close]) }
        var v4 = in_addr(), v6 = in6_addr()
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        var canonical: String
        if inet_pton(AF_INET, s, &v4) == 1 {
            canonical = inet_ntop(AF_INET, &v4, &buf, socklen_t(buf.count)).map { String(cString: $0) } ?? s
        } else if inet_pton(AF_INET6, s, &v6) == 1 {
            canonical = inet_ntop(AF_INET6, &v6, &buf, socklen_t(buf.count)).map { String(cString: $0) } ?? s
            if canonical.lowercased().hasPrefix("::ffff:"), isIP(String(canonical.dropFirst(7))) {
                canonical = String(canonical.dropFirst(7))
            }
        } else {
            return nil
        }
        canonical = canonical.lowercased()
        if ["127.0.0.1", "::1", "0.0.0.0", "::"].contains(canonical) || canonical.hasPrefix("127.") { return nil }
        return canonical
    }

    /// Host key: upper-case short name without domain suffix or trailing `$`.
    public static func hostKey(_ raw: String) -> String? {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        while s.hasPrefix("\\") { s.removeFirst() }
        guard !s.isEmpty, s != "-" else { return nil }
        if isIP(s) || s.lowercased().hasPrefix("::ffff:") { return nil }
        var name = s.uppercased()
        if ["LOCALHOST", "LOCAL", "UNKNOWN", "N/A", "-"].contains(name) { return nil }
        if name.hasSuffix("$") { name.removeLast() }
        let short = name.split(separator: ".").first.map(String.init) ?? name
        return short.isEmpty ? nil : short
    }

    public static func normalizeDomain(_ d: String?) -> String? {
        guard let d = d?.trimmingCharacters(in: .whitespaces), !d.isEmpty, d != "-" else { return nil }
        let u = d.uppercased()
        return builtinDomains.contains(u) ? u : String(u.split(separator: ".").first ?? Substring(u))
    }

    /// Splits `DOMAIN\user` and `user@domain` forms.
    public static func splitUser(_ raw: String, domain: String?) -> (name: String, domain: String?)? {
        var name = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        var dom = domain
        guard !name.isEmpty, name != "-" else { return nil }
        if let i = name.firstIndex(of: "\\") {
            dom = String(name[..<i])
            name = String(name[name.index(after: i)...])
        } else if let i = name.lastIndex(of: "@"), i != name.startIndex {
            dom = String(name[name.index(after: i)...])
            name = String(name[..<i])
        }
        guard !name.isEmpty else { return nil }
        return (name, normalizeDomain(dom))
    }

    public static func isValidSID(_ s: String?) -> Bool {
        guard let s, s.hasPrefix("S-1-"), s != "S-1-0-0" else { return false }
        return true
    }

    public static func isBuiltin(name: String?, domain: String?, sid: String?) -> Bool {
        if let sid {
            if ["S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-7", "S-1-0-0", "S-1-5-6", "S-1-5-4", "S-1-5-11"].contains(sid) { return true }
            if ["S-1-5-90-", "S-1-5-96-", "S-1-5-80-", "S-1-5-83-", "S-1-5-82-"].contains(where: { sid.hasPrefix($0) }) { return true }
        }
        if let domain, builtinDomains.contains(domain) { return true }
        if let name, builtinNames.contains(name.lowercased()) || name.uppercased().hasPrefix("DWM-") || name.uppercased().hasPrefix("UMFD-") { return true }
        return false
    }
}
