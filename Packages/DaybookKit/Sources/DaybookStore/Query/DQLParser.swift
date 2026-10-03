import Foundation

// DQL — DayBook Query Language. A pipeline in the spirit of PDQL / KQL:
//
//   EventID = 4624 and LogonType in (3, 10) and not TargetUserName endswith "$"
//   | group by IpAddress, TargetUserName
//   | sort count desc
//   | limit 100
//
// The text is parsed into an AST and executed as set operations over posting lists.
// It is never turned into SQL, so there is nothing to inject into.

public struct DQLError: Error, Equatable, Sendable, CustomStringConvertible {
    public let message: String
    /// Character offset in the query text (for highlighting).
    public let position: Int
    public var description: String { message }
}

public enum DQLOp: String, Sendable, Hashable {
    case eq = "="                 // case-insensitive equality
    case eqExact = "=="           // case-sensitive equality
    case ne = "!="
    case lt = "<", le = "<=", gt = ">", ge = ">="
    case contains, notContains = "!contains", startswith, endswith, like, matches, cidr
}

public indirect enum DQLExpr: Hashable, Sendable {
    case and([DQLExpr])
    case or([DQLExpr])
    case not(DQLExpr)
    case compare(field: String, op: DQLOp, value: String)
    case inList(field: String, values: [String])
    case exists(field: String)
    case between(field: String, low: String, high: String)
    /// Bare string: substring search across every field value.
    case text(String)
    /// `true` / `false` (used by compiled detection rules for impossible / empty parts).
    case constant(Bool)
    /// Compares two fields of the same event: Image endswith `OriginalFileName`.
    case fieldCompare(field: String, op: DQLOp, other: String)
}

public struct DQLSort: Equatable, Sendable {
    public var field: String
    public var descending: Bool
}

public struct DQLQuery: Equatable, Sendable {
    public var filter: DQLExpr?
    public var select: [String]?
    public var groupBy: [String]?
    public var sort: [DQLSort] = []
    public var limit: Int?

    public init() {}
}

enum DQLToken: Equatable {
    case word(String)           // identifiers, bare values, keywords, numbers
    case string(String)         // "…" or '…'
    case field(String)          // `quoted field name`
    case op(String)             // = == != < <= > >= ~ !~
    case lparen, rparen, comma, pipe
    case end
}

struct DQLLexer {
    static let operatorChars: Set<Character> = ["=", "!", "<", ">", "~"]
    static let stopChars: Set<Character> = ["(", ")", ",", "|", "\"", "'", "`", "=", "!", "<", ">", "~"]

    static func tokenize(_ text: String) throws -> [(DQLToken, Int)] {
        var out: [(DQLToken, Int)] = []
        let chars = Array(text)
        var i = 0
        while i < chars.count {
            let c = chars[i]
            if c.isWhitespace { i += 1; continue }
            let start = i
            switch c {
            case "(": out.append((.lparen, i)); i += 1
            case ")": out.append((.rparen, i)); i += 1
            case ",": out.append((.comma, i)); i += 1
            case "|": out.append((.pipe, i)); i += 1
            case "\"", "'", "`":
                let quote = c
                var s = ""
                i += 1
                var closed = false
                while i < chars.count {
                    let d = chars[i]
                    if d == "\\", i + 1 < chars.count, quote != "`" {
                        let n = chars[i + 1]
                        // Only quotes and backslashes are escapes, so Windows paths
                        // like "C:\Windows\Temp" can be typed as-is.
                        if n == quote || n == "\\" { s.append(n); i += 2; continue }
                        s.append(d); i += 1; continue
                    }
                    if d == quote { closed = true; i += 1; break }
                    s.append(d)
                    i += 1
                }
                guard closed else {
                    throw DQLError(message: String(localized: "Незакрытая кавычка"), position: start)
                }
                out.append((quote == "`" ? .field(s) : .string(s), start))
            default:
                if operatorChars.contains(c) {
                    var op = String(c)
                    if i + 1 < chars.count, chars[i + 1] == "=" || (c == "!" && chars[i + 1] == "~") {
                        op.append(chars[i + 1])
                    }
                    guard ["=", "==", "!=", "<", "<=", ">", ">=", "~", "!~"].contains(op) else {
                        throw DQLError(message: String(localized: "Неизвестный оператор «\(op)»"), position: start)
                    }
                    out.append((.op(op), start))
                    i += op.count
                } else {
                    var w = ""
                    while i < chars.count, !chars[i].isWhitespace, !stopChars.contains(chars[i]) {
                        w.append(chars[i])
                        i += 1
                    }
                    out.append((.word(w), start))
                }
            }
            guard out.count < 200_000 else { throw DQLError(message: String(localized: "Слишком длинный запрос"), position: i) }
        }
        out.append((.end, chars.count))
        return out
    }
}

public enum DQLParser {
    public static let maxDepth = 64

    public static func parse(_ text: String) throws -> DQLQuery {
        var p = Parser(tokens: try DQLLexer.tokenize(text))
        return try p.query()
    }

    private struct Parser {
        let tokens: [(DQLToken, Int)]
        var i = 0
        var depth = 0

        init(tokens: [(DQLToken, Int)]) { self.tokens = tokens }

        var tok: DQLToken { tokens[i].0 }
        var pos: Int { tokens[i].1 }
        mutating func advance() { if i < tokens.count - 1 { i += 1 } }

        func isKeyword(_ k: String) -> Bool {
            if case let .word(w) = tok { return w.lowercased() == k }
            return false
        }

        mutating func accept(_ k: String) -> Bool {
            if isKeyword(k) { advance(); return true }
            return false
        }

        func error(_ msg: String) -> DQLError { DQLError(message: msg, position: pos) }

        mutating func query() throws -> DQLQuery {
            var q = DQLQuery()
            if tok != .pipe && tok != .end, !stageStart() {
                q.filter = try expression()
            }
            while tok != .end {
                if tok == .pipe { advance() } else if !stageStart() {
                    throw error(String(localized: "Ожидался «|» или конец запроса"))
                }
                try stage(&q)
            }
            return q
        }

        /// AND-combines pipeline stages into one flat conjunction.
        static func combine(_ a: DQLExpr?, _ b: DQLExpr) -> DQLExpr {
            guard let a else { return b }
            let left: [DQLExpr] = if case let .and(xs) = a { xs } else { [a] }
            let right: [DQLExpr] = if case let .and(ys) = b { ys } else { [b] }
            return .and(left + right)
        }

        func stageStart() -> Bool {
            ["where", "select", "project", "group", "sort", "order", "limit", "take", "search"].contains { isKeyword($0) }
        }

        mutating func stage(_ q: inout DQLQuery) throws {
            if accept("where") {
                q.filter = Self.combine(q.filter, try expression())
            } else if accept("search") {
                guard case let .string(s) = tok else { throw error(String(localized: "После search ожидается строка в кавычках")) }
                advance()
                q.filter = Self.combine(q.filter, .text(s))
            } else if accept("select") || accept("project") {
                q.select = try fieldList()
            } else if accept("group") {
                _ = accept("by")
                q.groupBy = try fieldList()
            } else if accept("sort") || accept("order") {
                _ = accept("by")
                repeat {
                    let f = try fieldName()
                    var desc = false
                    if accept("desc") { desc = true } else { _ = accept("asc") }
                    q.sort.append(DQLSort(field: f, descending: desc))
                } while acceptComma()
            } else if accept("limit") || accept("take") {
                guard case let .word(w) = tok, let n = Int(w), n >= 0 else {
                    throw error(String(localized: "После limit ожидается число"))
                }
                advance()
                q.limit = n
            } else {
                throw error(String(localized: "Неизвестная стадия: ожидалось where, select, group by, sort, limit или search"))
            }
        }

        mutating func acceptComma() -> Bool {
            if tok == .comma { advance(); return true }
            return false
        }

        mutating func fieldList() throws -> [String] {
            var out = [try fieldName()]
            while acceptComma() { out.append(try fieldName()) }
            return out
        }

        mutating func fieldName() throws -> String {
            switch tok {
            case let .word(w) where !w.isEmpty:
                advance()
                return w
            case let .field(f):
                advance()
                return f
            default:
                throw error(String(localized: "Ожидалось имя поля"))
            }
        }

        // expression := and ('or' and)*
        mutating func expression() throws -> DQLExpr {
            depth += 1
            defer { depth -= 1 }
            guard depth < maxDepth else { throw error(String(localized: "Слишком глубокая вложенность скобок")) }
            var parts = [try conjunction()]
            while accept("or") { parts.append(try conjunction()) }
            return parts.count == 1 ? parts[0] : .or(parts)
        }

        // conjunction := unary (('and')? unary)*  — juxtaposition means AND
        mutating func conjunction() throws -> DQLExpr {
            var parts = [try unary()]
            while true {
                if accept("and") { parts.append(try unary()); continue }
                if startsOperand() { parts.append(try unary()); continue }
                break
            }
            return parts.count == 1 ? parts[0] : .and(parts)
        }

        func startsOperand() -> Bool {
            switch tok {
            case .lparen, .string, .field: return true
            case let .word(w):
                let k = w.lowercased()
                return !["or", "and", "where", "select", "project", "group", "sort", "order", "limit", "take", "search"].contains(k)
            default: return false
            }
        }

        mutating func unary() throws -> DQLExpr {
            if accept("not") { return .not(try unary()) }
            if tok == .lparen {
                advance()
                let e = try expression()
                guard tok == .rparen else { throw error(String(localized: "Ожидалась «)»")) }
                advance()
                return e
            }
            if case let .string(s) = tok {
                advance()
                return .text(s)
            }
            if case let .word(w) = tok, ["true", "false"].contains(w.lowercased()) {
                // A bare true/false is a constant; "true = x" would be a field comparison.
                if i + 1 < tokens.count, case .op = tokens[i + 1].0 {} else {
                    advance()
                    return .constant(w.lowercased() == "true")
                }
            }
            return try comparison()
        }

        mutating func comparison() throws -> DQLExpr {
            let field = try fieldName()
            if accept("exists") { return .exists(field: field) }
            if accept("in") { return .inList(field: field, values: try valueList()) }
            if isKeyword("not") {
                // field not in (...) / field not contains "x"
                advance()
                if accept("in") { return .not(.inList(field: field, values: try valueList())) }
                if accept("contains") { return .compare(field: field, op: .notContains, value: try value()) }
                if accept("exists") { return .not(.exists(field: field)) }
                throw error(String(localized: "После not ожидается in, contains или exists"))
            }
            if accept("between") {
                let low = try value()
                guard accept("and") else { throw error(String(localized: "Ожидалось «and» в between")) }
                return .between(field: field, low: low, high: try value())
            }
            let op: DQLOp
            switch tok {
            case let .op(o):
                switch o {
                case "=": op = .eq
                case "==": op = .eqExact
                case "!=": op = .ne
                case "<": op = .lt
                case "<=": op = .le
                case ">": op = .gt
                case ">=": op = .ge
                case "~": op = .contains
                case "!~": op = .notContains
                default: throw error(String(localized: "Неизвестный оператор"))
                }
                advance()
            case let .word(w):
                switch w.lowercased() {
                case "contains": op = .contains
                case "startswith": op = .startswith
                case "endswith": op = .endswith
                case "like": op = .like
                case "matches", "regex": op = .matches
                case "cidr": op = .cidr
                default:
                    throw error(String(localized: "После «\(field)» ожидается оператор (=, !=, <, >, contains, in, …)"))
                }
                advance()
            default:
                throw error(String(localized: "После «\(field)» ожидается оператор (=, !=, <, >, contains, in, …)"))
            }
            if case let .field(other) = tok {
                // A backquoted right-hand side names a field of the same event.
                guard [.eq, .eqExact, .ne, .contains, .startswith, .endswith].contains(op) else {
                    throw error(String(localized: "Сравнение двух полей поддерживает =, ==, !=, contains, startswith, endswith"))
                }
                advance()
                return .fieldCompare(field: field, op: op, other: other)
            }
            return .compare(field: field, op: op, value: try value())
        }

        mutating func value() throws -> String {
            switch tok {
            case let .string(s): advance(); return s
            case let .word(w) where !w.isEmpty: advance(); return w
            default: throw error(String(localized: "Ожидалось значение"))
            }
        }

        mutating func valueList() throws -> [String] {
            guard tok == .lparen else { throw error(String(localized: "Ожидалась «(» со списком значений")) }
            advance()
            var out = [try value()]
            while acceptComma() { out.append(try value()) }
            guard tok == .rparen else { throw error(String(localized: "Ожидалась «)»")) }
            advance()
            guard out.count <= 10_000 else { throw error(String(localized: "Слишком длинный список значений")) }
            return out
        }
    }
}
