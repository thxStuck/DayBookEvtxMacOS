import Foundation

public enum EvtxError: Error, Equatable, Sendable, CustomStringConvertible {
    case io(path: String, errno: Int32)
    case notEvtx
    case legacyEvt
    case truncated(offset: Int)
    case badRecord(offset: Int, reason: String)
    case invalidToken(UInt8, offset: Int)
    case invalidName(offset: Int)
    case invalidTemplate(offset: Int, reason: String)
    case invalidSubstitution(index: Int, offset: Int)
    case recursionLimit

    public var description: String {
        switch self {
        case let .io(path, err): "I/O error \(err) (\(String(cString: strerror(err)))) on \(path)"
        case .notEvtx: "not an EVTX file"
        case .legacyEvt: "legacy Windows XP/2003 .evt file (not supported)"
        case let .truncated(o): "data truncated at offset \(o)"
        case let .badRecord(o, r): "bad record at offset \(o): \(r)"
        case let .invalidToken(t, o): String(format: "invalid BinXML token 0x%02X at offset %d", t, o)
        case let .invalidName(o): "invalid name structure at offset \(o)"
        case let .invalidTemplate(o, r): "invalid template at offset \(o): \(r)"
        case let .invalidSubstitution(i, o): "invalid substitution #\(i) at offset \(o)"
        case .recursionLimit: "BinXML nesting too deep"
        }
    }
}
