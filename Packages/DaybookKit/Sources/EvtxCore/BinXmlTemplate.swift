import Foundation

/// 16-byte GUID in on-disk (mixed-endian) layout.
public struct EvtxGUID: Hashable, Sendable {
    public let lo: UInt64
    public let hi: UInt64

    init(_ b: UnsafeRawBufferPointer, _ o: Int) {
        lo = b.u64u(o)
        hi = b.u64u(o + 8)
    }

    /// First four bytes; equals the template identifier stored in a TemplateInstance.
    public var prefix: UInt32 { UInt32(truncatingIfNeeded: lo) }

    public var string: String {
        withUnsafeBytes(of: (lo, hi)) { ValueRender.guid(UnsafeRawBufferPointer($0), 0) }
    }
}

enum NodeKind: UInt8 {
    case element, text, substitution, charRef, entityRef, cdata, pi
}

/// A node of a compiled template, stored in document (pre-)order. An element's subtree
/// occupies the index range `(self, end)`.
struct TemplateNode {
    var kind: NodeKind
    var str: Int32 = -1          // element / entity / PI-target name, or text / CDATA
    var str2: Int32 = -1         // PI data
    var end: Int32 = 0
    var attrStart: Int32 = 0
    var attrCount: Int32 = 0
    var sub: UInt16 = 0
    var optional = false
    var declaredType: UInt8 = 0
    var charRef: UInt16 = 0
}

struct TemplateAttribute {
    var name: Int32
    var partStart: Int32
    var partCount: Int32
}

/// Chunk-independent compiled form of a BinXML template definition: every name is
/// resolved to a string, so the same object can render records from any chunk
/// (needed when a carved record's template lives in another chunk).
public final class CompiledTemplate: @unchecked Sendable {
    let nodes: [TemplateNode]
    let attributes: [TemplateAttribute]
    let parts: [TemplateNode]        // attribute value parts (text / substitution / refs)
    let strings: [String]
    public let guid: EvtxGUID?
    /// Highest substitution index referenced + 1.
    public let substitutionCount: Int
    /// Declared value type per substitution index (0 when not referenced).
    let declaredTypes: [UInt8]
    let fingerprint: Int

    init(nodes: [TemplateNode], attributes: [TemplateAttribute], parts: [TemplateNode],
         strings: [String], guid: EvtxGUID?) {
        self.nodes = nodes
        self.attributes = attributes
        self.parts = parts
        self.strings = strings
        self.guid = guid
        var types = [UInt8]()
        for n in nodes + parts where n.kind == .substitution {
            let i = Int(n.sub)
            if i >= types.count { types += Array(repeating: 0, count: i - types.count + 1) }
            types[i] = n.declaredType
        }
        declaredTypes = types
        substitutionCount = types.count

        var h = Hasher()
        h.combine(guid)
        for n in nodes { h.combine(n.kind); h.combine(n.str); h.combine(n.end); h.combine(n.sub); h.combine(n.attrCount) }
        for a in attributes { h.combine(a.name); h.combine(a.partCount) }
        for p in parts { h.combine(p.kind); h.combine(p.str); h.combine(p.sub) }
        for s in strings { h.combine(s) }
        fingerprint = h.finalize()
    }
}

/// Per-chunk cache of names (keyed by chunk offset).
final class NameTable {
    private var cache: [UInt32: String] = [:]
    let chunk: UnsafeRawBufferPointer
    var invalidText = false

    init(chunk: UnsafeRawBufferPointer) { self.chunk = chunk }

    /// Name structure: next offset (4) | hash (2) | character count (2) | UTF-16 | NUL (2).
    func name(at offset: Int) throws -> (String, Int) {
        let count = Int(try chunk.u16(offset + 6))
        let size = 8 + count * 2 + 2
        guard offset >= 0, offset + size <= chunk.count, count < 2048 else {
            throw EvtxError.invalidName(offset: offset)
        }
        if let s = cache[UInt32(offset)] { return (s, size) }
        let s = UTF16Text.decode(chunk, offset + 8, count * 2, invalid: &invalidText)
        cache[UInt32(offset)] = s
        return (s, size)
    }

    /// Reads a name referenced at `pos` (the 4-byte offset was just consumed). When the
    /// name is stored inline (offset == current position), `pos` advances past it.
    func resolve(_ nameOffset: Int, pos: inout Int) throws -> String {
        let (s, size) = try name(at: nameOffset)
        if nameOffset == pos { pos += size }
        return s
    }
}

/// Compiles BinXML token streams (template definitions or raw fragments) into `CompiledTemplate`.
struct TemplateCompiler {
    let chunk: UnsafeRawBufferPointer
    let names: NameTable

    private var nodes: [TemplateNode] = []
    private var attributes: [TemplateAttribute] = []
    private var parts: [TemplateNode] = []
    private var strings: [String] = []
    private var stringIndex: [String: Int32] = [:]

    init(chunk: UnsafeRawBufferPointer, names: NameTable) {
        self.chunk = chunk
        self.names = names
    }

    /// Template definition header at `offset`: next (4) | GUID (16) | data size (4) | data.
    static func compileDefinition(at offset: Int, chunk: UnsafeRawBufferPointer, names: NameTable) throws -> CompiledTemplate {
        guard offset >= 0, offset + 24 <= chunk.count else {
            throw EvtxError.invalidTemplate(offset: offset, reason: "header out of bounds")
        }
        let guid = EvtxGUID(chunk, offset + 4)
        let size = Int(chunk.u32u(offset + 20))
        let start = offset + 24
        guard size > 0, start + size <= chunk.count else {
            throw EvtxError.invalidTemplate(offset: offset, reason: "bad data size \(size)")
        }
        var c = TemplateCompiler(chunk: chunk, names: names)
        do {
            try c.compile(start, start + size, dependencyIds: true)
        } catch {
            // EVTX writes dependency ids in definitions; fall back for odd producers.
            c = TemplateCompiler(chunk: chunk, names: names)
            try c.compile(start, start + size, dependencyIds: false)
        }
        return c.finish(guid: guid)
    }

    /// Compiles a raw nested fragment (a BinXml substitution value that is not a template instance).
    static func compileFragment(_ start: Int, _ end: Int, chunk: UnsafeRawBufferPointer, names: NameTable) throws -> CompiledTemplate {
        var c = TemplateCompiler(chunk: chunk, names: names)
        do {
            try c.compile(start, end, dependencyIds: false)
        } catch {
            c = TemplateCompiler(chunk: chunk, names: names)
            try c.compile(start, end, dependencyIds: true)
        }
        return c.finish(guid: nil)
    }

    private mutating func intern(_ s: String) -> Int32 {
        if let i = stringIndex[s] { return i }
        let i = Int32(strings.count)
        strings.append(s)
        stringIndex[s] = i
        return i
    }

    private func finish(guid: EvtxGUID?) -> CompiledTemplate {
        CompiledTemplate(nodes: nodes, attributes: attributes, parts: parts, strings: strings, guid: guid)
    }

    private func text(_ offset: Int, _ chars: Int) throws -> String {
        try chunk.checkRange(offset, chars * 2)
        return UTF16Text.decode(chunk, offset, chars * 2, invalid: &names.invalidText)
    }

    private mutating func compile(_ start: Int, _ end: Int, dependencyIds: Bool) throws {
        var pos = start
        var open: [Int] = []
        loop: while pos < end {
            let tok = try chunk.u8(pos)
            switch tok & 0xBF {
            case 0x00:
                break loop
            case 0x0F:
                pos += 4
            case 0x01:
                pos = try openElement(pos, end: end, dependencyIds: dependencyIds, open: &open)
            case 0x04:
                pos += 1
                guard let idx = open.popLast() else { throw EvtxError.invalidToken(tok, offset: pos - 1) }
                nodes[idx].end = Int32(nodes.count)
            case 0x05, 0x07, 0x08, 0x09, 0x0A, 0x0D, 0x0E:
                var node = TemplateNode(kind: .text)
                pos = try valueToken(pos, into: &node)
                nodes.append(node)
            default:
                throw EvtxError.invalidToken(tok, offset: pos)
            }
        }
        while let idx = open.popLast() { nodes[idx].end = Int32(nodes.count) }
    }

    /// OpenStartElement: token | [dependency id (2)] | data size (4) | name offset (4) |
    /// [inline name] | [attribute list size (4) when token has 0x40] | attributes | close.
    private mutating func openElement(_ p: Int, end: Int, dependencyIds: Bool, open: inout [Int]) throws -> Int {
        let tok = try chunk.u8(p)
        var pos = p + 1 + (dependencyIds ? 2 : 0) + 4
        let nameOffset = Int(try chunk.u32(pos))
        pos += 4
        guard nameOffset >= 128, nameOffset <= pos, nameOffset + 10 <= chunk.count else {
            throw EvtxError.invalidName(offset: nameOffset)
        }
        let name = try names.resolve(nameOffset, pos: &pos)
        if tok & 0x40 != 0 { pos += 4 }

        let idx = nodes.count
        nodes.append(TemplateNode(kind: .element, str: intern(name)))
        let attrStart = attributes.count
        while pos < end, try chunk.u8(pos) & 0xBF == 0x06 {
            pos = try attribute(pos, end: end)
        }
        nodes[idx].attrStart = Int32(attrStart)
        nodes[idx].attrCount = Int32(attributes.count - attrStart)

        let close = try chunk.u8(pos)
        switch close {
        case 0x02:
            open.append(idx)
        case 0x03:
            nodes[idx].end = Int32(nodes.count)
        default:
            throw EvtxError.invalidToken(close, offset: pos)
        }
        return pos + 1
    }

    private mutating func attribute(_ p: Int, end: Int) throws -> Int {
        var pos = p + 1
        let nameOffset = Int(try chunk.u32(pos))
        pos += 4
        let name = try names.resolve(nameOffset, pos: &pos)
        let partStart = parts.count
        while pos < end {
            let t = try chunk.u8(pos) & 0xBF
            guard t == 0x05 || t == 0x08 || t == 0x09 || t == 0x0D || t == 0x0E else { break }
            var part = TemplateNode(kind: .text)
            pos = try valueToken(pos, into: &part)
            parts.append(part)
        }
        attributes.append(TemplateAttribute(name: intern(name), partStart: Int32(partStart),
                                            partCount: Int32(parts.count - partStart)))
        return pos
    }

    /// Parses one content token (value text, substitution, references, CDATA, PI).
    private mutating func valueToken(_ p: Int, into node: inout TemplateNode) throws -> Int {
        let tok = try chunk.u8(p)
        switch tok & 0xBF {
        case 0x05: // value text: token | value type (1) | char count (2) | UTF-16
            let count = Int(try chunk.u16(p + 2))
            node.kind = .text
            node.str = intern(try text(p + 4, count))
            return p + 4 + count * 2
        case 0x07: // CDATA: token | char count (2) | UTF-16
            let count = Int(try chunk.u16(p + 1))
            node.kind = .cdata
            node.str = intern(try text(p + 3, count))
            return p + 3 + count * 2
        case 0x08: // character reference: token | value (2)
            node.kind = .charRef
            node.charRef = try chunk.u16(p + 1)
            return p + 3
        case 0x09: // entity reference: token | name offset (4)
            var pos = p + 5
            let name = try names.resolve(Int(try chunk.u32(p + 1)), pos: &pos)
            node.kind = .entityRef
            node.str = intern(name)
            return pos
        case 0x0A: // PI target (name), followed by PI data: token | char count (2) | UTF-16
            var pos = p + 5
            let target = try names.resolve(Int(try chunk.u32(p + 1)), pos: &pos)
            node.kind = .pi
            node.str = intern(target)
            if try chunk.u8(pos) == 0x0B {
                let count = Int(try chunk.u16(pos + 1))
                node.str2 = intern(try text(pos + 3, count))
                pos += 3 + count * 2
            }
            return pos
        case 0x0D, 0x0E: // substitution: token | index (2) | value type (1)
            node.kind = .substitution
            node.sub = try chunk.u16(p + 1)
            node.declaredType = try chunk.u8(p + 3)
            node.optional = (tok & 0xBF) == 0x0E
            return p + 4
        default:
            throw EvtxError.invalidToken(tok, offset: p)
        }
    }
}
