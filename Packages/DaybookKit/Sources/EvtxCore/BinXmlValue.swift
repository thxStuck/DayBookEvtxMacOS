import Foundation

/// BinXML value types (MS-EVEN6 2.2.13 / EVT_VARIANT_TYPE).
public enum ValueType {
    public static let null: UInt8 = 0x00
    public static let string: UInt8 = 0x01
    public static let ansiString: UInt8 = 0x02
    public static let int8: UInt8 = 0x03
    public static let uint8: UInt8 = 0x04
    public static let int16: UInt8 = 0x05
    public static let uint16: UInt8 = 0x06
    public static let int32: UInt8 = 0x07
    public static let uint32: UInt8 = 0x08
    public static let int64: UInt8 = 0x09
    public static let uint64: UInt8 = 0x0A
    public static let real32: UInt8 = 0x0B
    public static let real64: UInt8 = 0x0C
    public static let bool: UInt8 = 0x0D
    public static let binary: UInt8 = 0x0E
    public static let guid: UInt8 = 0x0F
    public static let sizeT: UInt8 = 0x10
    public static let fileTime: UInt8 = 0x11
    public static let systemTime: UInt8 = 0x12
    public static let sid: UInt8 = 0x13
    public static let hexInt32: UInt8 = 0x14
    public static let hexInt64: UInt8 = 0x15
    public static let evtHandle: UInt8 = 0x20
    public static let binXml: UInt8 = 0x21
    public static let evtXml: UInt8 = 0x23
    public static let arrayFlag: UInt8 = 0x80

    /// Fixed element size for array expansion; nil for variable-size types.
    static func fixedSize(_ t: UInt8) -> Int? {
        switch t {
        case int8, uint8: 1
        case int16, uint16: 2
        case int32, uint32, real32, bool, hexInt32: 4
        case int64, uint64, real64, fileTime, hexInt64: 8
        case guid, systemTime: 16
        default: nil
        }
    }
}

/// A substitution value inside a chunk. Only valid while the chunk mapping is alive and
/// during the walk that produced it; convert to `String` / integers to keep it.
public struct EvtxValue {
    public let type: UInt8
    let buf: UnsafeRawBufferPointer
    let offset: Int
    public let size: Int

    public var isNull: Bool { type == ValueType.null }
    public var isArray: Bool { type & ValueType.arrayFlag != 0 }

    /// Integer interpretation of integer-like types (incl. hex ints, bool, size_t, FILETIME).
    public var integer: UInt64? {
        guard !isArray else { return nil }
        switch (type, size) {
        case (ValueType.int8, 1): return UInt64(bitPattern: Int64(Int8(bitPattern: buf[offset])))
        case (ValueType.uint8, 1): return UInt64(buf[offset])
        case (ValueType.int16, 2): return UInt64(bitPattern: Int64(Int16(bitPattern: buf.u16u(offset))))
        case (ValueType.uint16, 2): return UInt64(buf.u16u(offset))
        case (ValueType.int32, 4): return UInt64(bitPattern: Int64(Int32(bitPattern: buf.u32u(offset))))
        case (ValueType.uint32, 4), (ValueType.hexInt32, 4), (ValueType.bool, 4), (ValueType.sizeT, 4):
            return UInt64(buf.u32u(offset))
        case (ValueType.int64, 8), (ValueType.uint64, 8), (ValueType.hexInt64, 8),
             (ValueType.sizeT, 8), (ValueType.fileTime, 8):
            return buf.u64u(offset)
        default: return nil
        }
    }

    public var fileTime: Int64? {
        type == ValueType.fileTime && size == 8 ? Int64(bitPattern: buf.u64u(offset)) : nil
    }

    public func render(invalidText: inout Bool) -> String {
        if isArray { return items(invalidText: &invalidText).joined(separator: ", ") }
        return ValueRender.scalar(type, buf, offset, size, invalidText: &invalidText)
    }

    /// Items of an array value (string arrays are NUL-separated; others are fixed-size).
    public func items(invalidText: inout Bool) -> [String] {
        let base = type & ~ValueType.arrayFlag
        guard isArray, size > 0 else { return size > 0 ? [render(invalidText: &invalidText)] : [] }
        switch base {
        case ValueType.string:
            // Every NUL terminates one item, so empty strings are real items
            // ("a\0\0b\0" → "a", "", "b"); only an unterminated tail adds one more.
            var out: [String] = []
            var start = offset
            var i = offset
            let end = offset + size - (size & 1)
            while i < end {
                if buf.u16u(i) == 0 {
                    out.append(i > start ? UTF16Text.decode(buf, start, i - start, invalid: &invalidText) : "")
                    start = i + 2
                }
                i += 2
            }
            if end > start { out.append(UTF16Text.decode(buf, start, end - start, invalid: &invalidText)) }
            return out
        case ValueType.ansiString:
            return buf[offset..<(offset + size)].split(separator: 0).map { String(decoding: $0, as: UTF8.self) }
        case ValueType.sid:
            var out: [String] = []
            var o = offset
            while o + 8 <= offset + size {
                let len = 8 + Int(buf[o + 1]) * 4
                guard o + len <= offset + size else { break }
                out.append(ValueRender.sid(buf, o, len))
                o += len
            }
            return out
        case ValueType.sizeT:
            let w = size % 8 == 0 ? 8 : 4
            return stride(from: offset, to: offset + size - w + 1, by: w).map {
                ValueRender.scalar(ValueType.sizeT, buf, $0, w, invalidText: &invalidText)
            }
        default:
            guard let w = ValueType.fixedSize(base) else {
                return [ValueRender.hex(buf, offset, size)]
            }
            return stride(from: offset, to: offset + size - w + 1, by: w).map {
                ValueRender.scalar(base, buf, $0, w, invalidText: &invalidText)
            }
        }
    }
}

enum ValueRender {
    static func scalar(_ type: UInt8, _ b: UnsafeRawBufferPointer, _ o: Int, _ size: Int,
                       invalidText: inout Bool) -> String {
        switch type {
        case ValueType.null:
            return ""
        case ValueType.string:
            return UTF16Text.decode(b, o, size, invalid: &invalidText)
        case ValueType.ansiString:
            var n = size
            while n > 0, b[o + n - 1] == 0 { n -= 1 }
            // Windows-1252 is a superset of Latin-1 for printable data; Latin-1 never fails.
            return String(b[o..<(o + n)].map { Character(Unicode.Scalar($0)) })
        case ValueType.int8 where size == 1: return String(Int8(bitPattern: b[o]))
        case ValueType.uint8 where size == 1: return String(b[o])
        case ValueType.int16 where size == 2: return String(Int16(bitPattern: b.u16u(o)))
        case ValueType.uint16 where size == 2: return String(b.u16u(o))
        case ValueType.int32 where size == 4: return String(Int32(bitPattern: b.u32u(o)))
        case ValueType.uint32 where size == 4: return String(b.u32u(o))
        case ValueType.int64 where size == 8: return String(Int64(bitPattern: b.u64u(o)))
        case ValueType.uint64 where size == 8: return String(b.u64u(o))
        case ValueType.real32 where size == 4: return String(Float(bitPattern: b.u32u(o)))
        case ValueType.real64 where size == 8: return String(Double(bitPattern: b.u64u(o)))
        case ValueType.bool where size == 4: return b.u32u(o) != 0 ? "true" : "false"
        case ValueType.bool where size == 1: return b[o] != 0 ? "true" : "false"
        case ValueType.guid where size == 16: return guid(b, o)
        case ValueType.sizeT where size == 4: return "0x" + String(b.u32u(o), radix: 16)
        case ValueType.sizeT where size == 8: return "0x" + String(b.u64u(o), radix: 16)
        case ValueType.fileTime where size == 8: return FileTime.iso8601(Int64(bitPattern: b.u64u(o)))
        case ValueType.systemTime where size == 16: return systemTime(b, o)
        case ValueType.sid where size >= 8: return sid(b, o, size)
        case ValueType.hexInt32 where size == 4: return "0x" + String(b.u32u(o), radix: 16)
        case ValueType.hexInt64 where size == 8: return "0x" + String(b.u64u(o), radix: 16)
        default:
            return hex(b, o, size)
        }
    }

    private static let hexDigits = Array("0123456789ABCDEF".utf8)

    static func hex(_ b: UnsafeRawBufferPointer, _ o: Int, _ size: Int) -> String {
        guard size > 0, o >= 0, o + size <= b.count else { return "" }
        return String(unsafeUninitializedCapacity: size * 2) { out in
            for i in 0..<size {
                let v = b[o + i]
                out[i * 2] = hexDigits[Int(v >> 4)]
                out[i * 2 + 1] = hexDigits[Int(v & 0xF)]
            }
            return size * 2
        }
    }

    /// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`: Data1..3 little-endian, Data4 as bytes.
    static func guid(_ b: UnsafeRawBufferPointer, _ o: Int) -> String {
        let d1 = b.u32u(o), d2 = b.u16u(o + 4), d3 = b.u16u(o + 6)
        func h(_ v: UInt64, _ w: Int) -> String {
            let s = String(v, radix: 16, uppercase: true)
            return String(repeating: "0", count: max(0, w - s.count)) + s
        }
        return "{" + h(UInt64(d1), 8) + "-" + h(UInt64(d2), 4) + "-" + h(UInt64(d3), 4) + "-"
            + hex(b, o + 8, 2) + "-" + hex(b, o + 10, 6) + "}"
    }

    /// `S-R-A-S1-S2…`; the 48-bit authority is big-endian, sub-authorities little-endian.
    static func sid(_ b: UnsafeRawBufferPointer, _ o: Int, _ size: Int) -> String {
        let rev = b[o]
        let count = Int(b[o + 1])
        guard size >= 8 + count * 4 else { return hex(b, o, size) }
        var auth: UInt64 = 0
        for i in 0..<6 { auth = auth << 8 | UInt64(b[o + 2 + i]) }
        var s = "S-\(rev)-" + (auth >= 1 << 32 ? "0x" + String(auth, radix: 16, uppercase: true) : String(auth))
        for i in 0..<count { s += "-" + String(b.u32u(o + 8 + i * 4)) }
        return s
    }

    /// SYSTEMTIME: year, month, day-of-week, day, hour, minute, second, milliseconds (UInt16 each).
    static func systemTime(_ b: UnsafeRawBufferPointer, _ o: Int) -> String {
        func p(_ v: UInt16, _ w: Int) -> String {
            let s = String(v)
            return String(repeating: "0", count: max(0, w - s.count)) + s
        }
        return p(b.u16u(o), 4) + "-" + p(b.u16u(o + 2), 2) + "-" + p(b.u16u(o + 6), 2) + "T"
            + p(b.u16u(o + 8), 2) + ":" + p(b.u16u(o + 10), 2) + ":" + p(b.u16u(o + 12), 2) + "."
            + p(b.u16u(o + 14), 3) + "Z"
    }
}
