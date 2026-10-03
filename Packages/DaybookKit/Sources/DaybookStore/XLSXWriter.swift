import Foundation
import zlib

/// Minimal ZIP writer: deflated entries streamed with a data descriptor (sizes and CRC after
/// the data), as used by .xlsx. No ZIP64 — callers keep entries below 4 GB.
final class ZipWriter {
    private let out: FileHandle
    private var offset: UInt64 = 0
    private var central = Data()
    private var count: UInt16 = 0

    init(url: URL) throws {
        FileManager.default.createFile(atPath: url.path, contents: nil)
        guard let h = FileHandle(forWritingAtPath: url.path) else {
            throw CocoaError(.fileWriteNoPermission, userInfo: [NSFilePathErrorKey: url.path])
        }
        out = h
    }

    private func write(_ d: Data) throws {
        try out.write(contentsOf: d)
        offset += UInt64(d.count)
    }

    private static func le16(_ v: UInt16) -> Data { withUnsafeBytes(of: v.littleEndian) { Data($0) } }
    private static func le32(_ v: UInt32) -> Data { withUnsafeBytes(of: v.littleEndian) { Data($0) } }

    /// Streams one entry: `body` receives a function that appends uncompressed bytes.
    func entry(_ name: String, _ body: (_ append: (Data) throws -> Void) throws -> Void) throws {
        let nameBytes = Data(name.utf8)
        let start = offset
        // Local header: version 20, flag 0x0808 (data descriptor + UTF-8 name), deflate.
        var local = Self.le32(0x0403_4b50) + Self.le16(20) + Self.le16(0x0808) + Self.le16(8)
        local += Self.le16(0) + Self.le16(0x21)            // time 00:00, date 1980-01-01
        local += Self.le32(0) + Self.le32(0) + Self.le32(0) // crc and sizes follow the data
        local += Self.le16(UInt16(nameBytes.count)) + Self.le16(0) + nameBytes
        try write(local)

        var stream = z_stream()
        guard deflateInit2_(&stream, 6, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY, ZLIB_VERSION,
                            Int32(MemoryLayout<z_stream>.size)) == Z_OK else {
            throw CocoaError(.fileWriteUnknown)
        }
        defer { deflateEnd(&stream) }
        var crc: uLong = crc32(0, nil, 0)
        var size: UInt64 = 0, compressed: UInt64 = 0
        var buffer = [UInt8](repeating: 0, count: 1 << 16)
        func pump(_ input: Data, finish: Bool) throws {
            try input.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
                stream.next_in = UnsafeMutablePointer(mutating: raw.bindMemory(to: Bytef.self).baseAddress)
                stream.avail_in = uInt(raw.count)
                repeat {
                    let produced: Int = buffer.withUnsafeMutableBytes { b in
                        stream.next_out = b.bindMemory(to: Bytef.self).baseAddress
                        stream.avail_out = uInt(b.count)
                        deflate(&stream, finish ? Z_FINISH : Z_NO_FLUSH)
                        return b.count - Int(stream.avail_out)
                    }
                    if produced > 0 {
                        try write(Data(buffer[0..<produced]))
                        compressed += UInt64(produced)
                    }
                } while stream.avail_out == 0 || (finish && stream.avail_in > 0)
            }
        }
        try body { chunk in
            guard !chunk.isEmpty else { return }
            crc = chunk.withUnsafeBytes { crc32(crc, $0.bindMemory(to: Bytef.self).baseAddress, uInt($0.count)) }
            size += UInt64(chunk.count)
            try pump(chunk, finish: false)
        }
        try pump(Data(), finish: true)
        guard size < UInt64(UInt32.max), compressed < UInt64(UInt32.max), offset < UInt64(UInt32.max) else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSLocalizedDescriptionKey: String(localized: "Слишком большой файл для XLSX (больше 4 ГБ)")])
        }
        try write(Self.le32(0x0807_4b50) + Self.le32(UInt32(crc)) + Self.le32(UInt32(compressed)) + Self.le32(UInt32(size)))

        var c = Self.le32(0x0201_4b50) + Self.le16(20) + Self.le16(20) + Self.le16(0x0808) + Self.le16(8)
        c += Self.le16(0) + Self.le16(0x21) + Self.le32(UInt32(crc)) + Self.le32(UInt32(compressed)) + Self.le32(UInt32(size))
        c += Self.le16(UInt16(nameBytes.count)) + Self.le16(0) + Self.le16(0) + Self.le16(0) + Self.le16(0)
        c += Self.le32(0) + Self.le32(UInt32(start)) + nameBytes
        central += c
        count += 1
    }

    func finish() throws {
        let start = offset
        try write(central)
        var end = Self.le32(0x0605_4b50) + Self.le16(0) + Self.le16(0) + Self.le16(count) + Self.le16(count)
        end += Self.le32(UInt32(central.count)) + Self.le32(UInt32(start)) + Self.le16(0)
        try write(end)
        try out.close()
    }
}

/// Writes .xlsx workbooks: text cells are inline strings (never formulas), numbers are numbers.
enum XLSX {
    static let maxRows = 1_048_575          // Excel: 1 048 576 rows including the header
    static let maxCell = 32_767             // Excel: characters per cell

    enum Cell {
        case text(String)
        case number(Int64)
    }

    /// XML text. Control characters become OOXML's `_xHHHH_`; an underscore that would start
    /// such a sequence in the original text is itself escaped as `_x005F_` (ECMA-376 §22.4.2.4).
    static func xml(_ s: String) -> String {
        let u = Array(s.unicodeScalars)
        func isHex(_ c: Unicode.Scalar) -> Bool { ("0"..."9").contains(c) || ("a"..."f").contains(c) || ("A"..."F").contains(c) }
        var out = ""
        out.reserveCapacity(s.utf8.count)
        var i = 0
        while i < u.count {
            let c = u[i]
            switch c {
            case "&": out += "&amp;"
            case "<": out += "&lt;"
            case ">": out += "&gt;"
            case "\"": out += "&quot;"
            case "\t", "\n", "\r": out.unicodeScalars.append(c)
            case "_":
                if i + 6 < u.count, u[i + 1] == "x", isHex(u[i + 2]), isHex(u[i + 3]), isHex(u[i + 4]), isHex(u[i + 5]), u[i + 6] == "_" {
                    out += "_x005F_"
                } else {
                    out += "_"
                }
            default:
                if c.value < 0x20 || c.value == 0xFFFE || c.value == 0xFFFF {
                    out += String(format: "_x%04X_", c.value)
                } else {
                    out.unicodeScalars.append(c)
                }
            }
            i += 1
        }
        return out
    }

    static func column(_ i: Int) -> String {
        var n = i + 1, s = ""
        while n > 0 {
            let r = (n - 1) % 26
            s = String(UnicodeScalar(UInt8(65 + r))) + s
            n = (n - 1) / 26
        }
        return s
    }

    static let contentTypes = """
    <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\
    <Default Extension="xml" ContentType="application/xml"/>\
    <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>\
    <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>\
    <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>\
    <Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>\
    </Types>
    """

    static let rootRels = """
    <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>\
    </Relationships>
    """

    static func workbook(_ sheets: [String]) -> String {
        """
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>\
        \(sheets.enumerated().map { "<sheet name=\"\(xml($0.element))\" sheetId=\"\($0.offset + 1)\" r:id=\"rId\($0.offset + 1)\"/>" }.joined())\
        </sheets></workbook>
        """
    }

    static func workbookRels(_ count: Int) -> String {
        """
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\
        \((0..<count).map { "<Relationship Id=\"rId\($0 + 1)\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet\($0 + 1).xml\"/>" }.joined())\
        <Relationship Id="rId\(count + 1)" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>\
        </Relationships>
        """
    }

    /// Style 0: normal; style 1: bold header.
    static let styles = """
    <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">\
    <fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>\
    <fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>\
    <borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>\
    <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>\
    <cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>\
    </styleSheet>
    """

    static func sheetStart(widths: [Double], frozenHeader: Bool) -> String {
        var s = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">"
        if frozenHeader {
            s += "<sheetViews><sheetView workbookViewId=\"0\"><pane ySplit=\"1\" topLeftCell=\"A2\" activePane=\"bottomLeft\" state=\"frozen\"/></sheetView></sheetViews>"
        }
        s += "<cols>" + widths.enumerated().map { "<col min=\"\($0.offset + 1)\" max=\"\($0.offset + 1)\" width=\"\($0.element)\" customWidth=\"1\"/>" }.joined() + "</cols><sheetData>"
        return s
    }

    /// One row; returns the number of cells that had to be shortened to Excel's limit.
    static func row(_ index: Int, _ cells: [Cell], bold: Bool = false, into out: inout String) -> Int {
        var truncated = 0
        out += "<row r=\"\(index)\">"
        for (i, c) in cells.enumerated() {
            let ref = column(i) + String(index)
            switch c {
            case let .number(n):
                out += "<c r=\"\(ref)\"\(bold ? " s=\"1\"" : "")><v>\(n)</v></c>"
            case var .text(s):
                if s.isEmpty { continue }
                if s.count > maxCell {
                    let note = String(localized: "…[обрезано: полная длина \(s.count) символов]")
                    s = String(s.prefix(maxCell - note.count)) + note
                    truncated += 1
                }
                out += "<c r=\"\(ref)\" t=\"inlineStr\"\(bold ? " s=\"1\"" : "")><is><t xml:space=\"preserve\">\(xml(s))</t></is></c>"
            }
        }
        out += "</row>"
        return truncated
    }
}
