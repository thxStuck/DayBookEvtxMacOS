import EvtxCore
import Foundation

/// Display time zone. Times are stored as UTC FILETIME; only rendering is shifted.
nonisolated enum TimeZoneChoice: Hashable, Codable, Sendable {
    case utc
    case offset(Int)        // seconds east of UTC, no DST
    case named(String)      // IANA identifier, with DST
    case local

    static let fixedOffsets: [Int] = [
        -12, -11, -10, -9.5, -9, -8, -7, -6, -5, -4, -3.5, -3, -2, -1,
        1, 2, 3, 3.5, 4, 4.5, 5, 5.5, 5.75, 6, 6.5, 7, 8, 8.75, 9, 9.5, 10, 10.5, 11, 12, 12.75, 13, 14,
    ].map { Int(($0 as Double) * 3600) }

    static let namedZones = [
        "Europe/Moscow", "Europe/Kaliningrad", "Europe/Samara", "Asia/Yekaterinburg", "Asia/Omsk",
        "Asia/Novosibirsk", "Asia/Krasnoyarsk", "Asia/Irkutsk", "Asia/Yakutsk", "Asia/Vladivostok",
        "Asia/Magadan", "Asia/Kamchatka", "Europe/Minsk", "Europe/Kyiv", "Asia/Almaty", "Asia/Tashkent",
        "Asia/Dubai", "Europe/London", "Europe/Berlin", "America/New_York", "America/Chicago",
        "America/Los_Angeles", "Asia/Shanghai", "Asia/Tokyo",
    ]

    static func offsetLabel(_ seconds: Int) -> String {
        let sign = seconds < 0 ? "−" : "+"
        let a = abs(seconds)
        return String(format: "UTC%@%02d:%02d", sign, a / 3600, a / 60 % 60)
    }

    var label: String {
        switch self {
        case .utc: "UTC"
        case let .offset(s): Self.offsetLabel(s)
        case let .named(id): id
        case .local: String(localized: "Локальное время Mac")
        }
    }

    /// Short label for column headers, e.g. "UTC+03:00".
    func headerLabel(at ft: Int64?) -> String {
        switch self {
        case .utc: return "UTC"
        case let .offset(s): return Self.offsetLabel(s)
        case .named, .local:
            let off = ft.map { offset(at: $0) } ?? zone.secondsFromGMT()
            return "\(label), \(Self.offsetLabel(off))"
        }
    }

    var zone: TimeZone {
        switch self {
        case .utc: TimeZone(identifier: "UTC")!
        case let .offset(s): TimeZone(secondsFromGMT: s) ?? TimeZone(identifier: "UTC")!
        case let .named(id): TimeZone(identifier: id) ?? TimeZone(identifier: "UTC")!
        case .local: TimeZone.current
        }
    }

    func offset(at ft: Int64) -> Int {
        switch self {
        case .utc: 0
        case let .offset(s): s
        case .named, .local: zone.secondsFromGMT(for: FileTime.date(ft))
        }
    }

    // Persistence in UserDefaults as a compact string.
    var storageValue: String {
        switch self {
        case .utc: "utc"
        case let .offset(s): "offset:\(s)"
        case let .named(id): "named:\(id)"
        case .local: "local"
        }
    }

    init(storageValue: String) {
        if storageValue.hasPrefix("offset:"), let s = Int(storageValue.dropFirst(7)) { self = .offset(s) }
        else if storageValue.hasPrefix("named:") { self = .named(String(storageValue.dropFirst(6))) }
        else if storageValue == "local" { self = .local }
        else { self = .utc }
    }
}

/// Fast FILETIME → text in the chosen zone. DST-aware zones cache the offset per hour.
/// One instance per thread (the cache is not locked).
nonisolated final class TimeFormatter: @unchecked Sendable {
    let zone: TimeZoneChoice
    let fractionDigits: Int
    private var hourCache: [Int64: Int] = [:]

    init(zone: TimeZoneChoice, fractionDigits: Int = 3) {
        self.zone = zone
        self.fractionDigits = fractionDigits
    }

    func offset(_ ft: Int64) -> Int {
        switch zone {
        case .utc: return 0
        case let .offset(s): return s
        case .named, .local:
            let hour = ft / (3600 * FileTime.ticksPerSecond)
            if let o = hourCache[hour] { return o }
            let o = zone.offset(at: ft)
            if hourCache.count > 100_000 { hourCache.removeAll() }
            hourCache[hour] = o
            return o
        }
    }

    func string(_ ft: Int64) -> String {
        FileTime.format(ft, offsetSeconds: offset(ft), fractionDigits: fractionDigits,
                        separator: UInt8(ascii: " "), zulu: false)
    }

    /// Parses "YYYY-MM-DD[ HH:MM[:SS[.fff]]]" in this zone (or with an explicit `Z`/±HH:MM).
    func parse(_ text: String) -> Int64? {
        var s = text.trimmingCharacters(in: .whitespaces)
        var explicit: Int?
        if s.hasSuffix("Z") || s.hasSuffix("z") { explicit = 0; s.removeLast() }
        else if let m = s.range(of: #"[+-]\d\d:\d\d$"#, options: .regularExpression), s.distance(from: s.startIndex, to: m.lowerBound) >= 10 {
            let tz = s[m]
            let sign = tz.first == "-" ? -1 : 1
            let h = Int(tz.dropFirst().prefix(2)) ?? 0, mi = Int(tz.suffix(2)) ?? 0
            explicit = sign * (h * 3600 + mi * 60)
            s = String(s[..<m.lowerBound])
        }
        let parts = s.split(whereSeparator: { $0 == " " || $0 == "T" })
        guard let datePart = parts.first else { return nil }
        let d = datePart.split(separator: "-").compactMap { Int64($0) }
        guard d.count == 3 else { return nil }
        var secs: Int64 = 0, frac: Int64 = 0
        if parts.count > 1 {
            let t = parts[1].split(separator: ":")
            guard t.count >= 2, let h = Int64(t[0]), let mi = Int64(t[1]) else { return nil }
            secs = h * 3600 + mi * 60
            if t.count > 2 {
                let sp = t[2].split(separator: ".")
                secs += Int64(sp[0]) ?? 0
                if sp.count > 1 { frac = Int64(String(sp[1].prefix(7)).padding(toLength: 7, withPad: "0", startingAt: 0)) ?? 0 }
            }
        }
        let local = FileTime.fromUnixSeconds(FileTime.days(fromCivil: d[0], Int(d[1]), Int(d[2])) * 86_400 + secs) + frac
        let off = explicit ?? offset(local - Int64(offset(local)) * FileTime.ticksPerSecond)
        return local - Int64(off) * FileTime.ticksPerSecond
    }
}
