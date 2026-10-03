import Foundation

public enum AttributeValue {
    case value(EvtxValue)
    case text(String)
}

/// Receives the rendered document of one record. Implementations: `EventExtractor`
/// (structured fields) and `XmlWriter` (XML text).
public protocol BinXmlVisitor {
    /// When false, nested BinXml values (EventData/UserData) are skipped.
    var wantsNestedContent: Bool { get }
    mutating func startElement(_ name: String)
    mutating func attribute(_ name: String, _ value: AttributeValue)
    mutating func text(_ s: String)
    mutating func value(_ v: EvtxValue)
    mutating func cdata(_ s: String)
    mutating func endElement(_ name: String)
}

extension BinXmlVisitor {
    public var wantsNestedContent: Bool { true }
    public mutating func cdata(_ s: String) { text(s) }
}

struct Substitution {
    var offset: Int
    var size: Int
    var type: UInt8
}

struct TemplateInstance {
    var template: CompiledTemplate?
    var templateId: UInt32
    var substitutions: [Substitution]
    var end: Int
    var foreign: Bool
}

/// Thread-safe collection of compiled templates from every chunk of a case, keyed by
/// template id (= first 4 bytes of the GUID). Used to decode carved records whose
/// definition is not present in their own chunk.
public final class TemplateLibrary: @unchecked Sendable {
    private var byId: [UInt32: [CompiledTemplate]] = [:]
    private var fingerprints: Set<Int> = []
    private let lock = NSLock()

    public init() {}

    public func add(_ t: CompiledTemplate) {
        guard let id = t.guid?.prefix else { return }
        lock.lock(); defer { lock.unlock() }
        guard fingerprints.insert(t.fingerprint).inserted else { return }
        byId[id, default: []].append(t)
    }

    public var count: Int { lock.lock(); defer { lock.unlock() }; return fingerprints.count }

    func best(for id: UInt32, substitutions: [Substitution]) -> CompiledTemplate? {
        lock.lock()
        let candidates = byId[id] ?? []
        lock.unlock()
        return candidates.first { t in
            guard t.substitutionCount <= substitutions.count else { return false }
            for (i, declared) in t.declaredTypes.enumerated() where declared != 0 {
                let actual = substitutions[i].type
                if actual != declared && actual != ValueType.null { return false }
            }
            return true
        } ?? candidates.first
    }
}

/// Per-chunk parsing state: name cache and template cache keyed by definition offset.
final class ChunkContext {
    let buf: UnsafeRawBufferPointer
    let names: NameTable
    let library: TemplateLibrary?
    private(set) var templates: [Int: CompiledTemplate] = [:]

    init(buf: UnsafeRawBufferPointer, library: TemplateLibrary?) {
        self.buf = buf
        self.names = NameTable(chunk: buf)
        self.library = library
    }

    func compile(_ offset: Int) -> CompiledTemplate? {
        if let t = templates[offset] { return t }
        guard let t = try? TemplateCompiler.compileDefinition(at: offset, chunk: buf, names: names) else { return nil }
        templates[offset] = t
        return t
    }

    /// TemplateInstance: 0x0C | unknown (1) | template id (4) | definition offset (4) |
    /// [inline definition] | value count (4) | descriptors (size u16, type u8, pad u8) | values.
    func readInstance(at p: Int, limit: Int) throws -> TemplateInstance {
        guard try buf.u8(p) == 0x0C else { throw EvtxError.invalidToken(buf[p], offset: p) }
        let templateId = try buf.u32(p + 2)
        let defOffset = Int(try buf.u32(p + 6))
        var pos = p + 10
        var template: CompiledTemplate?
        var foreign = false

        if defOffset == pos {
            try buf.checkRange(pos, 24)
            let size = Int(buf.u32u(pos + 20))
            template = compile(defOffset)
            pos += 24 + size
        } else if let t = templates[defOffset], t.guid?.prefix == templateId {
            // The id check matters for carved records: a reused chunk can hold a different
            // template at the offset an old record points to.
            template = t
        } else if defOffset >= 512, defOffset + 24 <= buf.count, buf.u32u(defOffset + 4) == templateId {
            template = compile(defOffset)
        }

        let count = Int(try buf.u32(pos))
        pos += 4
        guard count <= 8192, pos + count * 4 <= limit else {
            throw EvtxError.badRecord(offset: p, reason: "bad substitution count \(count)")
        }
        var subs = [Substitution]()
        subs.reserveCapacity(count)
        var v = pos + count * 4
        for i in 0..<count {
            let size = Int(buf.u16u(pos + i * 4))
            subs.append(Substitution(offset: v, size: size, type: buf[pos + i * 4 + 2]))
            v += size
        }
        guard v <= limit else { throw EvtxError.badRecord(offset: p, reason: "values exceed record") }

        if template == nil, let lib = library, let t = lib.best(for: templateId, substitutions: subs) {
            template = t
            foreign = true
        }
        return TemplateInstance(template: template, templateId: templateId, substitutions: subs, end: v, foreign: foreign)
    }
}

/// Instantiates templates with substitution values and feeds the visitor.
struct BinXmlWalker<V: BinXmlVisitor> {
    let ctx: ChunkContext
    var visitor: V
    var flags: RecordFlags = []
    var invalidText = false
    private var depth = 0

    init(ctx: ChunkContext, visitor: V) {
        self.ctx = ctx
        self.visitor = visitor
    }

    /// Walks a BinXML fragment: [fragment header] then a TemplateInstance or raw tokens.
    mutating func walkFragment(_ start: Int, _ end: Int) throws {
        depth += 1
        defer { depth -= 1 }
        guard depth <= 12 else { throw EvtxError.recursionLimit }
        var pos = start
        if try ctx.buf.u8(pos) == 0x0F { pos += 4 }
        guard pos < end else { return }
        if try ctx.buf.u8(pos) == 0x0C {
            let inst = try ctx.readInstance(at: pos, limit: end)
            if inst.foreign { flags.insert(.foreignTemplate) }
            if let t = inst.template {
                try walkTemplate(t, inst.substitutions)
            } else {
                flags.insert(.missingTemplate)
                try emitMissing(inst.substitutions, wrapInEvent: depth == 1)
            }
        } else {
            let t = try TemplateCompiler.compileFragment(pos, end, chunk: ctx.buf, names: ctx.names)
            try walkTemplate(t, [])
        }
    }

    private mutating func walkTemplate(_ t: CompiledTemplate, _ subs: [Substitution]) throws {
        var i = 0
        while i < t.nodes.count { i = try walkNode(t, i, subs) }
    }

    private func value(_ s: Substitution) -> EvtxValue {
        EvtxValue(type: s.type, buf: ctx.buf, offset: s.offset, size: s.size)
    }

    private mutating func walkNode(_ t: CompiledTemplate, _ i: Int, _ subs: [Substitution]) throws -> Int {
        let node = t.nodes[i]
        switch node.kind {
        case .element:
            let end = max(Int(node.end), i + 1)
            let name = t.strings[Int(node.str)]
            // An element whose only content is an array substitution is repeated per item.
            if end == i + 2, t.nodes[i + 1].kind == .substitution,
               let s = sub(subs, t.nodes[i + 1].sub), s.type & ValueType.arrayFlag != 0 {
                for item in value(s).items(invalidText: &invalidText) {
                    visitor.startElement(name)
                    emitAttributes(t, node, subs)
                    visitor.text(item)
                    visitor.endElement(name)
                }
                return end
            }
            visitor.startElement(name)
            emitAttributes(t, node, subs)
            var j = i + 1
            while j < end { j = try walkNode(t, j, subs) }
            visitor.endElement(name)
            return end
        case .text:
            visitor.text(t.strings[Int(node.str)])
        case .cdata:
            visitor.cdata(t.strings[Int(node.str)])
        case .charRef:
            visitor.text(String(Character(Unicode.Scalar(UInt32(node.charRef)) ?? "\u{FFFD}")))
        case .entityRef:
            visitor.text(Self.entity(t.strings[Int(node.str)]))
        case .pi:
            break
        case .substitution:
            guard let s = sub(subs, node.sub), s.type != ValueType.null else { break }
            if s.type == ValueType.binXml {
                if visitor.wantsNestedContent, s.size > 0 { try walkFragment(s.offset, s.offset + s.size) }
            } else {
                visitor.value(value(s))
            }
        }
        return i + 1
    }

    private func sub(_ subs: [Substitution], _ index: UInt16) -> Substitution? {
        Int(index) < subs.count ? subs[Int(index)] : nil
    }

    /// Attributes whose value is a NULL substitution are omitted, as Event Viewer does.
    private mutating func emitAttributes(_ t: CompiledTemplate, _ node: TemplateNode, _ subs: [Substitution]) {
        guard node.attrCount > 0 else { return }
        for a in t.attributes[Int(node.attrStart)..<Int(node.attrStart + node.attrCount)] {
            let name = t.strings[Int(a.name)]
            let parts = t.parts[Int(a.partStart)..<Int(a.partStart + a.partCount)]
            if parts.count == 1, let p = parts.first, p.kind == .substitution {
                guard let s = sub(subs, p.sub), s.type != ValueType.null, s.type != ValueType.binXml else { continue }
                visitor.attribute(name, .value(value(s)))
                continue
            }
            var text = ""
            for p in parts {
                switch p.kind {
                case .text: text += t.strings[Int(p.str)]
                case .charRef: text.append(Character(Unicode.Scalar(UInt32(p.charRef)) ?? "\u{FFFD}"))
                case .entityRef: text += Self.entity(t.strings[Int(p.str)])
                case .substitution:
                    if let s = sub(subs, p.sub), s.type != ValueType.null, s.type != ValueType.binXml {
                        text += value(s).render(invalidText: &invalidText)
                    }
                default: break
                }
            }
            visitor.attribute(name, .text(text))
        }
    }

    /// Without a template the substitution values are still meaningful: emit them as
    /// `Value[n]` data items (what EVTXtract does for orphaned records).
    private mutating func emitMissing(_ subs: [Substitution], wrapInEvent: Bool) throws {
        if wrapInEvent { visitor.startElement("Event") }
        visitor.startElement("EventData")
        for (i, s) in subs.enumerated() where s.type != ValueType.null {
            if s.type == ValueType.binXml {
                if visitor.wantsNestedContent, s.size > 0 { try? walkFragment(s.offset, s.offset + s.size) }
                continue
            }
            visitor.startElement("Data")
            visitor.attribute("Name", .text("Value[\(i)]"))
            visitor.value(value(s))
            visitor.endElement("Data")
        }
        visitor.endElement("EventData")
        if wrapInEvent { visitor.endElement("Event") }
    }

    static func entity(_ name: String) -> String {
        switch name {
        case "amp": "&"
        case "lt": "<"
        case "gt": ">"
        case "quot": "\""
        case "apos": "'"
        default: "&\(name);"
        }
    }
}
