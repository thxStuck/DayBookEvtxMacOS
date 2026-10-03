import Foundation

// Bounds-checked little-endian reads. All Apple platforms are little-endian, so the
// raw unaligned loads already have the on-disk byte order.
extension UnsafeRawBufferPointer {
    @inline(__always)
    func checkRange(_ offset: Int, _ length: Int) throws {
        guard offset >= 0, length >= 0, offset <= count - length else {
            throw EvtxError.truncated(offset: offset)
        }
    }

    @inline(__always) func u8(_ o: Int) throws -> UInt8 {
        try checkRange(o, 1); return load(fromByteOffset: o, as: UInt8.self)
    }
    @inline(__always) func u16(_ o: Int) throws -> UInt16 {
        try checkRange(o, 2); return loadUnaligned(fromByteOffset: o, as: UInt16.self)
    }
    @inline(__always) func u32(_ o: Int) throws -> UInt32 {
        try checkRange(o, 4); return loadUnaligned(fromByteOffset: o, as: UInt32.self)
    }
    @inline(__always) func u64(_ o: Int) throws -> UInt64 {
        try checkRange(o, 8); return loadUnaligned(fromByteOffset: o, as: UInt64.self)
    }

    /// Unchecked variants for callers that already validated the range.
    @inline(__always) func u16u(_ o: Int) -> UInt16 { loadUnaligned(fromByteOffset: o, as: UInt16.self) }
    @inline(__always) func u32u(_ o: Int) -> UInt32 { loadUnaligned(fromByteOffset: o, as: UInt32.self) }
    @inline(__always) func u64u(_ o: Int) -> UInt64 { loadUnaligned(fromByteOffset: o, as: UInt64.self) }
}

enum UTF16Text {
    /// Decodes `byteCount` bytes of UTF-16LE at `offset`, dropping trailing NULs.
    /// Sets `invalid` when the data contains unpaired surrogates (rendered as U+FFFD).
    static func decode(_ buf: UnsafeRawBufferPointer, _ offset: Int, _ byteCount: Int, invalid: inout Bool) -> String {
        var units = byteCount / 2
        guard units > 0, offset >= 0, offset + units * 2 <= buf.count else { return "" }
        while units > 0, buf.u16u(offset + (units - 1) * 2) == 0 { units -= 1 }
        if units == 0 { return "" }

        var ascii = true
        var surrogates = false
        for i in 0..<units {
            let u = buf.u16u(offset + i * 2)
            if u >= 0x80 {
                ascii = false
                if u & 0xF800 == 0xD800 { surrogates = true; break }
            }
        }
        if ascii {
            return String(unsafeUninitializedCapacity: units) { out in
                for i in 0..<units { out[i] = UInt8(truncatingIfNeeded: buf.u16u(offset + i * 2)) }
                return units
            }
        }
        if surrogates, !validSurrogates(buf, offset, units) { invalid = true }

        let base = buf.baseAddress! + offset
        if Int(bitPattern: base) & 1 == 0 {
            let p = base.assumingMemoryBound(to: UInt16.self)
            return String(decoding: UnsafeBufferPointer(start: p, count: units), as: UTF16.self)
        }
        var tmp = [UInt16](repeating: 0, count: units)
        for i in 0..<units { tmp[i] = buf.u16u(offset + i * 2) }
        return String(decoding: tmp, as: UTF16.self)
    }

    private static func validSurrogates(_ buf: UnsafeRawBufferPointer, _ offset: Int, _ units: Int) -> Bool {
        var i = 0
        while i < units {
            let u = buf.u16u(offset + i * 2)
            if u >= 0xD800 && u <= 0xDBFF {
                guard i + 1 < units else { return false }
                let lo = buf.u16u(offset + (i + 1) * 2)
                guard lo >= 0xDC00 && lo <= 0xDFFF else { return false }
                i += 2
                continue
            }
            if u >= 0xDC00 && u <= 0xDFFF { return false }
            i += 1
        }
        return true
    }
}
