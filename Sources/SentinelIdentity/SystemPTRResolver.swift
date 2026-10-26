import Darwin

/// Reverse DNS through the system resolver. Tests inject a stub instead.
public struct SystemPTRResolver: PTRResolving {
    public init() {}

    public func name(for address: String) -> String? {
        var v4 = in_addr()
        if inet_pton(AF_INET, address, &v4) == 1 {
            var sa = sockaddr_in(
                sin_len: UInt8(MemoryLayout<sockaddr_in>.size),
                sin_family: sa_family_t(AF_INET),
                sin_port: 0,
                sin_addr: v4,
                sin_zero: (0, 0, 0, 0, 0, 0, 0, 0)
            )
            return reverse(&sa, length: socklen_t(MemoryLayout<sockaddr_in>.size))
        }

        var v6 = in6_addr()
        if inet_pton(AF_INET6, address, &v6) == 1 {
            var sa = sockaddr_in6(
                sin6_len: UInt8(MemoryLayout<sockaddr_in6>.size),
                sin6_family: sa_family_t(AF_INET6),
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: v6,
                sin6_scope_id: 0
            )
            return reverse(&sa, length: socklen_t(MemoryLayout<sockaddr_in6>.size))
        }

        return nil
    }

    private func reverse<T>(_ address: inout T, length: socklen_t) -> String? {
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let status = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                getnameinfo(sockaddrPointer, length, &host, socklen_t(host.count), nil, 0, NI_NAMEREQD)
            }
        }
        guard status == 0 else { return nil }
        return host.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
    }
}
