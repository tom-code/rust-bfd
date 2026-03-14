//! Socket helpers for BFD: TTL=255 send, IP_RECVTTL/IPV6_RECVHOPLIMIT, recvmsg with cmsg.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::RawFd;

use socket2::{Domain, Protocol, Socket, Type};

/// Set outgoing TTL (IPv4) or hop-limit (IPv6) to 255 on a socket.
///
/// RFC 5881 §5 requires TTL=255 for single-hop BFD; RFC 5883 also sends at 255.
/// `socket2::set_ttl` only sets `IP_TTL` (IPv4); IPv6 requires `set_unicast_hops_v6`.
fn set_send_ttl(sock: &Socket, domain: Domain) -> io::Result<()> {
    if domain == Domain::IPV4 {
        sock.set_ttl(255)
    } else {
        sock.set_unicast_hops_v6(255)
    }
}

/// Set DSCP CS6 on a TX socket (RFC 5881 §4 SHOULD).
///
/// CS6 = 0b110000 (48 decimal), placed in the upper 6 bits of the TOS/TC byte → 0xC0.
fn set_tx_dscp(sock: &Socket, addr: &SocketAddr) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = sock.as_raw_fd();
    let tos: libc::c_int = 0xC0; // CS6
    let (level, opt) = if addr.is_ipv4() {
        (libc::IPPROTO_IP, libc::IP_TOS)
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_TCLASS)
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &tos as *const _ as *const libc::c_void,
            std::mem::size_of_val(&tos) as libc::socklen_t,
        )
    };
    if rc == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

/// Bind `sock` to a random port in the RFC 5881 §4 range 49152–65535 on `ip`.
///
/// Retries up to 64 times on `AddrInUse` before returning an error.
fn bind_in_ephemeral_range(sock: &Socket, ip: IpAddr) -> io::Result<()> {
    let mut buf = [0u8; 2];
    for _ in 0..64 {
        getrandom::fill(&mut buf)
            .map_err(|_| io::Error::other("getrandom unavailable"))?;
        let offset = u16::from_ne_bytes(buf) % (65535u16 - 49152 + 1);
        let port = 49152 + offset;
        let addr = SocketAddr::new(ip, port);
        match sock.bind(&socket2::SockAddr::from(addr)) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other("failed to bind TX socket to a port in 49152-65535 after 64 attempts"))
}

/// Create a BFD-compliant UDP socket:
/// - outgoing TTL/hop-limit = 255 (RFC 5881 §5)
/// - IP_RECVTTL / IPV6_RECVHOPLIMIT enabled so we can validate incoming TTL
/// - bound to `addr`, set non-blocking
pub fn create_bfd_socket(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    set_send_ttl(&sock, domain)?;
    set_recv_ttl(&sock, &addr)?;
    let bind_addr = socket2::SockAddr::from(addr);
    sock.bind(&bind_addr)?;
    sock.set_nonblocking(true)?;
    Ok(sock.into())
}

/// Create a send-only BFD UDP socket:
/// - outgoing TTL/hop-limit = 255 (RFC 5881 §5)
/// - DSCP CS6 (RFC 5881 §4 SHOULD)
/// - bound to a port in 49152–65535 (RFC 5881 §4 MUST)
/// - same address family as `listen_addr`
/// - set non-blocking
pub fn create_bfd_send_socket(listen_addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let domain = if listen_addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    set_send_ttl(&sock, domain)?;
    set_tx_dscp(&sock, &listen_addr)?;
    let any_ip: IpAddr = if listen_addr.is_ipv4() {
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    };
    bind_in_ephemeral_range(&sock, any_ip)?;
    sock.set_nonblocking(true)?;
    Ok(sock.into())
}

/// Create a BFD echo socket bound to `(addr.ip(), echo_port)`:
/// - outgoing TTL/hop-limit = 255
/// - IP_RECVTTL / IPV6_RECVHOPLIMIT enabled for TTL validation on received echo packets
/// - `reuse_address(true)` so the port can be shared between restarts
/// - non-blocking
pub fn create_echo_socket(addr: SocketAddr, echo_port: u16) -> io::Result<std::net::UdpSocket> {
    let echo_addr = SocketAddr::new(addr.ip(), echo_port);
    let domain = if echo_addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    set_send_ttl(&sock, domain)?;
    set_recv_ttl(&sock, &echo_addr)?;
    let bind_addr = socket2::SockAddr::from(echo_addr);
    sock.bind(&bind_addr)?;
    sock.set_nonblocking(true)?;
    Ok(sock.into())
}

/// Enable receiving TTL/hop-limit in ancillary data for subsequent recvmsg calls.
fn set_recv_ttl(sock: &Socket, addr: &SocketAddr) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = sock.as_raw_fd();
    let val: libc::c_int = 1;
    let (level, opt) = if addr.is_ipv4() {
        (libc::IPPROTO_IP, libc::IP_RECVTTL)
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT)
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        )
    };
    if rc == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

/// Receive a UDP datagram along with the IP TTL (IPv4) or hop-limit (IPv6) from ancillary data.
///
/// Uses `MSG_DONTWAIT` — returns `WouldBlock` immediately if no packet is available.
/// Call via `socket.try_io(Interest::READABLE, || recv_with_ttl(fd, buf))`.
pub fn recv_with_ttl(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, Option<u8>)> {
    let mut src: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // 256 bytes is plenty: IP_TTL cmsg is ~16 bytes, IPV6_HOPLIMIT ~20 bytes.
    let mut cmsg_buf = [0u8; 256];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut src as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1 as _;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len() as _;

    let len = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
    if len < 0 {
        return Err(io::Error::last_os_error());
    }

    let addr = unsafe { socket2::SockAddr::new(src, msg.msg_namelen) }
        .as_socket()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid source address"))?;

    let ttl = unsafe { parse_ttl(&msg) };

    Ok((len as usize, addr, ttl))
}

/// Walk the ancillary data from a recvmsg result and extract the TTL/hop-limit.
///
/// IPv4: cmsg level=IPPROTO_IP, type=IP_TTL
///   - macOS stores the value as `unsigned char` (1 byte)
///   - Linux stores the value as `int` (4 bytes)
/// IPv6: cmsg level=IPPROTO_IPV6, type=IPV6_HOPLIMIT, value as `int` (both platforms)
unsafe fn parse_ttl(msg: &libc::msghdr) -> Option<u8> {
    // SAFETY: msg is a valid msghdr from recvmsg; we traverse the cmsg chain per POSIX macros.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !cmsg.is_null() {
        let (level, ty, data) = unsafe {
            ((*cmsg).cmsg_level, (*cmsg).cmsg_type, libc::CMSG_DATA(cmsg))
        };

        // macOS kernel builds the cmsg with cmsg_type=IP_RECVTTL and 1-byte u_char value.
        // Linux kernel builds it with cmsg_type=IP_TTL and a 4-byte int value.
        #[cfg(target_os = "macos")]
        if level == libc::IPPROTO_IP && ty == libc::IP_RECVTTL {
            return Some(unsafe { *data });
        }
        #[cfg(not(target_os = "macos"))]
        if level == libc::IPPROTO_IP && ty == libc::IP_TTL {
            return Some(unsafe { std::ptr::read_unaligned(data as *const libc::c_int) } as u8);
        }

        if level == libc::IPPROTO_IPV6 && ty == libc::IPV6_HOPLIMIT {
            return Some(unsafe { std::ptr::read_unaligned(data as *const libc::c_int) } as u8);
        }

        cmsg = unsafe { libc::CMSG_NXTHDR(msg, cmsg) };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a cmsg buffer with a single entry carrying a `c_int` value.
    unsafe fn build_int_cmsg(level: libc::c_int, ty: libc::c_int, val: libc::c_int) -> Vec<u8> {
        unsafe {
            let space =
                libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as libc::c_uint) as usize;
            let mut buf = vec![0u8; space];
            let cmsg = buf.as_mut_ptr() as *mut libc::cmsghdr;
            (*cmsg).cmsg_level = level;
            (*cmsg).cmsg_type = ty;
            (*cmsg).cmsg_len =
                libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as libc::c_uint) as _;
            let data = libc::CMSG_DATA(cmsg) as *mut libc::c_int;
            std::ptr::write_unaligned(data, val);
            buf
        }
    }

    /// Build a cmsg buffer with a single entry carrying a single byte value.
    unsafe fn build_byte_cmsg(level: libc::c_int, ty: libc::c_int, val: u8) -> Vec<u8> {
        unsafe {
            let space = libc::CMSG_SPACE(1u32) as usize;
            let mut buf = vec![0u8; space];
            let cmsg = buf.as_mut_ptr() as *mut libc::cmsghdr;
            (*cmsg).cmsg_level = level;
            (*cmsg).cmsg_type = ty;
            (*cmsg).cmsg_len = libc::CMSG_LEN(1u32) as _;
            let data = libc::CMSG_DATA(cmsg);
            *data = val;
            buf
        }
    }

    fn msghdr_for(buf: &[u8]) -> libc::msghdr {
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        // SAFETY: CMSG_FIRSTHDR only reads msg_control; casting away const is acceptable here.
        msg.msg_control = buf.as_ptr() as *mut libc::c_void;
        msg.msg_controllen = buf.len() as _;
        msg
    }

    #[test]
    fn parse_ttl_empty_cmsg_returns_none() {
        let msg: libc::msghdr = unsafe { std::mem::zeroed() };
        assert!(unsafe { parse_ttl(&msg) }.is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_ttl_ipv4_macos() {
        let buf = unsafe { build_byte_cmsg(libc::IPPROTO_IP, libc::IP_RECVTTL, 200) };
        let msg = msghdr_for(&buf);
        assert_eq!(unsafe { parse_ttl(&msg) }, Some(200u8));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn parse_ttl_ipv4_linux() {
        let buf = unsafe { build_int_cmsg(libc::IPPROTO_IP, libc::IP_TTL, 200) };
        let msg = msghdr_for(&buf);
        assert_eq!(unsafe { parse_ttl(&msg) }, Some(200u8));
    }

    #[test]
    fn parse_ttl_ipv6_hoplimit() {
        let buf = unsafe { build_int_cmsg(libc::IPPROTO_IPV6, libc::IPV6_HOPLIMIT, 128) };
        let msg = msghdr_for(&buf);
        assert_eq!(unsafe { parse_ttl(&msg) }, Some(128u8));
    }

    #[test]
    fn parse_ttl_ipv6_hoplimit_max() {
        let buf = unsafe { build_int_cmsg(libc::IPPROTO_IPV6, libc::IPV6_HOPLIMIT, 255) };
        let msg = msghdr_for(&buf);
        assert_eq!(unsafe { parse_ttl(&msg) }, Some(255u8));
    }

    #[test]
    fn parse_ttl_wrong_level_returns_none() {
        // IPPROTO_TCP is not a BFD TTL cmsg level
        let buf = unsafe { build_int_cmsg(libc::IPPROTO_TCP, libc::IP_TTL, 200) };
        let msg = msghdr_for(&buf);
        assert!(unsafe { parse_ttl(&msg) }.is_none());
    }
}
