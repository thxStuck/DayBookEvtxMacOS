import Foundation

/// Windows FILETIME helpers: 100-ns ticks since 1601-01-01 UTC, kept as `Int64` so that
/// full precision survives storage and sorting.
public enum FileTime {
    public static let ticksPerSecond: Int64 = 10_000_000
    /// Ticks between 1601-01-01 and 1970-01-01.
    public static let unixEpochTicks: Int64 = 116_444_736_000_000_000

    public static func fromUnixSeconds(_ s: Int64) -> Int64 { s * ticksPerSecond + unixEpochTicks }

    public static func date(_ ft: Int64) -> Date {
        Date(timeIntervalSince1970: Double(ft - unixEpochTicks) / Double(ticksPerSecond))
    }

    /// Days since 1970-01-01 → proleptic Gregorian civil date (H. Hinnant, `civil_from_days`).
    public static func civil(fromDays z0: Int64) -> (year: Int64, month: Int, day: Int) {
        let z = z0 + 719_468
        let era = (z >= 0 ? z : z - 146_096) / 146_097
        let doe = z - era * 146_097
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        let mp = (5 * doy + 2) / 153
        let d = doy - (153 * mp + 2) / 5 + 1
        let m = mp < 10 ? mp + 3 : mp - 9
        return (yoe + era * 400 + (m <= 2 ? 1 : 0), Int(m), Int(d))
    }

    /// Civil date → days since 1970-01-01 (`days_from_civil`).
    public static func days(fromCivil year: Int64, _ month: Int, _ day: Int) -> Int64 {
        let y = month <= 2 ? year - 1 : year
        let era = (y >= 0 ? y : y - 399) / 400
        let yoe = y - era * 400
        let m = Int64(month)
        let doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + Int64(day) - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146_097 + doe - 719_468
    }

    /// Formats `ft` shifted by `offsetSeconds` as `YYYY-MM-DD HH:MM:SS[.fffffff]`.
    /// `separator` is `"T"` for ISO output; `zulu` appends `Z`.
    public static func format(_ ft: Int64, offsetSeconds: Int = 0, fractionDigits: Int = 7,
                              separator: UInt8 = UInt8(ascii: "T"), zulu: Bool = true) -> String {
        let ticks = ft - unixEpochTicks + Int64(offsetSeconds) * ticksPerSecond
        var secs = ticks / ticksPerSecond
        var frac = ticks - secs * ticksPerSecond
        if frac < 0 { frac += ticksPerSecond; secs -= 1 }
        var days = secs / 86_400
        var sod = secs - days * 86_400
        if sod < 0 { sod += 86_400; days -= 1 }
        let (y, mo, d) = civil(fromDays: days)

        var out = [UInt8]()
        out.reserveCapacity(32)
        func put(_ v: Int64, _ width: Int) {
            let start = out.count
            out.append(contentsOf: repeatElement(UInt8(ascii: "0"), count: width))
            var x = v
            var i = start + width - 1
            while i >= start { out[i] = UInt8(ascii: "0") + UInt8(x % 10); x /= 10; i -= 1 }
        }
        if y < 0 || y > 9999 { out.append(contentsOf: Array(String(y).utf8)) } else { put(y, 4) }
        out.append(UInt8(ascii: "-")); put(Int64(mo), 2)
        out.append(UInt8(ascii: "-")); put(Int64(d), 2)
        out.append(separator)
        put(sod / 3600, 2); out.append(UInt8(ascii: ":"))
        put(sod / 60 % 60, 2); out.append(UInt8(ascii: ":"))
        put(sod % 60, 2)
        let digits = min(max(fractionDigits, 0), 7)
        if digits > 0 {
            var f = frac
            for _ in 0..<(7 - digits) { f /= 10 }
            out.append(UInt8(ascii: ".")); put(f, digits)
        }
        if zulu { out.append(UInt8(ascii: "Z")) }
        return String(decoding: out, as: UTF8.self)
    }

    /// ISO-8601 UTC with 100-ns precision, as Event Viewer prints `SystemTime`.
    public static func iso8601(_ ft: Int64) -> String { format(ft) }
}
