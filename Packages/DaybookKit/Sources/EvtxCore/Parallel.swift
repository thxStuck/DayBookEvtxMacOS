import Foundation

private struct SendablePointer<T>: @unchecked Sendable {
    let p: UnsafeMutablePointer<T?>
}

/// Runs `body` for 0..<n on all cores (Dispatch `concurrentPerform`), preserving order.
/// Intended for CPU-bound work such as per-chunk parsing.
public func parallelMap<T>(_ n: Int, _ body: @Sendable (Int) -> T) -> [T] {
    guard n > 0 else { return [] }
    let p = UnsafeMutablePointer<T?>.allocate(capacity: n)
    p.initialize(repeating: nil, count: n)
    defer {
        p.deinitialize(count: n)
        p.deallocate()
    }
    let box = SendablePointer(p: p)
    DispatchQueue.concurrentPerform(iterations: n) { i in box.p[i] = body(i) }
    return (0..<n).map { p[$0]! }
}

/// Recursively lists EVTX files under `urls` (files are taken as-is; directories are
/// scanned for `*.evtx` and for extension-less files carrying the EVTX signature). A source
/// that is a symbolic link is resolved; inside a tree, links to files are followed, links to
/// directories are not (no loops).
public func findEvtxFiles(_ urls: [URL]) -> [URL] {
    var out: [URL] = []
    let fm = FileManager.default
    for source in urls {
        let url = source.resolvingSymlinksInPath()
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: url.path, isDirectory: &isDir) else { continue }
        if !isDir.boolValue { out.append(source); continue }
        guard let e = fm.enumerator(at: url, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey],
                                    options: [.skipsHiddenFiles]) else { continue }
        for case let f as URL in e {
            let values = try? f.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            if values?.isRegularFile != true {
                // A link to a regular file counts; a link to a directory is not descended into.
                guard values?.isSymbolicLink == true,
                      (try? f.resolvingSymlinksInPath().resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true
                else { continue }
            }
            if f.pathExtension.lowercased() == "evtx" || (f.pathExtension.isEmpty && EvtxFile.looksLikeEvtx(f)) {
                out.append(f)
            }
        }
    }
    return out.sorted { $0.path < $1.path }
}
