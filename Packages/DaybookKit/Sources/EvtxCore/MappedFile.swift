import Foundation

/// Read-only memory mapping of an evidence file. The file is opened with `O_RDONLY`
/// and mapped `PROT_READ`, so the source can never be modified through it.
public final class MappedFile: @unchecked Sendable {
    public let url: URL
    public let size: Int
    private let base: UnsafeRawPointer?

    public init(url: URL) throws {
        self.url = url
        let fd = open(url.path, O_RDONLY)
        guard fd >= 0 else { throw EvtxError.io(path: url.path, errno: errno) }
        defer { close(fd) }

        var st = stat()
        guard fstat(fd, &st) == 0 else { throw EvtxError.io(path: url.path, errno: errno) }
        size = Int(st.st_size)

        if size > 0 {
            guard let p = mmap(nil, size, PROT_READ, MAP_PRIVATE, fd, 0), p != MAP_FAILED else {
                throw EvtxError.io(path: url.path, errno: errno)
            }
            base = UnsafeRawPointer(p)
        } else {
            base = nil
        }
    }

    deinit {
        if let base { munmap(UnsafeMutableRawPointer(mutating: base), size) }
    }

    /// The whole mapping. Valid for the lifetime of this object.
    public var bytes: UnsafeRawBufferPointer {
        UnsafeRawBufferPointer(start: base, count: size)
    }

    public func slice(_ offset: Int, _ count: Int) -> UnsafeRawBufferPointer {
        precondition(offset >= 0 && count >= 0 && offset + count <= size)
        return UnsafeRawBufferPointer(rebasing: bytes[offset..<(offset + count)])
    }
}
