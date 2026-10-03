import Foundation

/// Renders a record as indented XML, close to Event Viewer's "XML View".
struct XmlWriter: BinXmlVisitor {
    private(set) var out = ""
    var invalidText = false

    private enum State { case openTag, text, children }
    private var stack: [(name: String, state: State)] = []

    mutating func startElement(_ name: String) {
        if let top = stack.last {
            if top.state == .openTag { out += ">" }
            if top.state != .text {
                stack[stack.count - 1].state = .children
                newline(stack.count)
            }
        }
        out += "<" + name
        stack.append((name, .openTag))
    }

    mutating func attribute(_ name: String, _ value: AttributeValue) {
        let s: String
        switch value {
        case let .value(v): s = v.render(invalidText: &invalidText)
        case let .text(t): s = t
        }
        out += " " + name + "=\"" + Self.escape(s, attribute: true) + "\""
    }

    mutating func text(_ s: String) {
        guard !s.isEmpty else { return }
        if stack.last?.state == .openTag {
            out += ">"
            stack[stack.count - 1].state = .text
        }
        out += Self.escape(s, attribute: false)
    }

    mutating func value(_ v: EvtxValue) { text(v.render(invalidText: &invalidText)) }

    mutating func cdata(_ s: String) {
        if stack.last?.state == .openTag {
            out += ">"
            stack[stack.count - 1].state = .text
        }
        out += "<![CDATA[" + s + "]]>"
    }

    mutating func endElement(_ name: String) {
        guard let top = stack.popLast() else { return }
        switch top.state {
        case .openTag: out += " />"
        case .text: out += "</" + top.name + ">"
        case .children:
            newline(stack.count)
            out += "</" + top.name + ">"
        }
    }

    private mutating func newline(_ level: Int) {
        out += "\n" + String(repeating: "  ", count: level)
    }

    static func escape(_ s: String, attribute: Bool) -> String {
        var needs = false
        for u in s.utf8 where u == 38 || u == 60 || u == 62 || (attribute && u == 34) || (u < 32 && u != 9 && u != 10 && u != 13) {
            needs = true
            break
        }
        guard needs else { return s }
        var r = ""
        r.reserveCapacity(s.utf8.count + 16)
        for ch in s.unicodeScalars {
            switch ch {
            case "&": r += "&amp;"
            case "<": r += "&lt;"
            case ">": r += "&gt;"
            case "\"" where attribute: r += "&quot;"
            default:
                if ch.value < 32 && ch.value != 9 && ch.value != 10 && ch.value != 13 {
                    r += "&#x" + String(ch.value, radix: 16, uppercase: true) + ";"
                } else {
                    r.unicodeScalars.append(ch)
                }
            }
        }
        return r
    }
}
