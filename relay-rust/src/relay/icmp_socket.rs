use std::borrow::BorrowMut;
use std::intrinsics::transmute;
/**
 * The ICMP socket
 *
 * only impl ICMP_ECHO and ICMP_ECHO_REPLY methods .
 *
 */
use std::io;
use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

use mio::Evented;
use socket2::Domain;
use socket2::Protocol;
use socket2::Socket;
use socket2::Type;

pub struct IcmpSocket(Socket, SelectorId);

impl IcmpSocket {
    pub fn bind(ip: IpAddr) -> io::Result<IcmpSocket> {
        let protocol = match ip {
            IpAddr::V4(_) => Some(Protocol::ICMPV4),
            IpAddr::V6(_) => Some(Protocol::ICMPV6),
        };
        Socket::new(
            Domain::for_address(SocketAddr::new(ip, 0)),
            Type::RAW,
            protocol,
        )
        .map(|socket| {
            socket
                .set_nonblocking(true)
                .expect("socket set non blocking failed");
            IcmpSocket(socket, SelectorId::new())
        })
    }

    pub fn connect(&self, addr: &SocketAddr) -> io::Result<()> {
        self.0.connect(&(*addr).into())
    }
}

impl Write for IcmpSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Read for IcmpSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut bytes = vec![0u8; 512];
        let mut size = self.0.read(&mut bytes)?;
        // Drop IPV4 Header
        size = buf.borrow_mut().write(&bytes[20..size])?;
        Ok(size)
    }
}

#[cfg(unix)]
use mio::unix::EventedFd;
use mio::Poll;
#[cfg(windows)]
use miow::iocp::{CompletionPort, CompletionStatus};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, FromRawSocket, IntoRawSocket, RawSocket};
#[cfg(windows)]
use std::sync::{Arc, Mutex};

#[cfg(unix)]
impl Evented for IcmpSocket {
    fn register(
        &self,
        poll: &Poll,
        token: mio::Token,
        interest: mio::Ready,
        opts: mio::PollOpt,
    ) -> io::Result<()> {
        self.1.associate_selector(poll)?;
        EventedFd(&self.0.as_raw_fd()).register(poll, token, interest, opts)
    }
    fn reregister(
        &self,
        poll: &Poll,
        token: mio::Token,
        interest: mio::Ready,
        opts: mio::PollOpt,
    ) -> io::Result<()> {
        EventedFd(&self.0.as_raw_fd()).reregister(poll, token, interest, opts)
    }
    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        EventedFd(&self.0.as_raw_fd()).deregister(poll)
    }
}

#[cfg(any(
    target_os = "bitrig",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "ios",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd"
))]

#[allow(dead_code)]
struct Selector {
    id: usize,
    kq: RawFd,
}

#[cfg(any(
    target_os = "android",
    target_os = "illumos",
    target_os = "linux",
    target_os = "solaris"
))]
#[allow(dead_code)]
struct Selector {
    id: usize,
    epfd: RawFd,
}

#[cfg(unix)]
impl Selector {
    pub fn id(&self) -> usize {
        self.id
    }
}

#[cfg(windows)]
struct BufferPool {
    pool: Vec<Vec<u8>>,
}

#[cfg(windows)]
struct SelectorInner {
    id: usize,
    port: CompletionPort,
    buffers: Mutex<BufferPool>,
}
#[cfg(windows)]
struct Selector {
    inner: Arc<SelectorInner>,
}

#[cfg(windows)]
impl Selector {
    pub fn id(&self) -> usize {
        self.inner.id
    }
}

struct ExPoll {
    pub selector: Selector,
}

#[derive(Debug)]
struct SelectorId {
    id: AtomicUsize,
}

impl SelectorId {
    pub fn new() -> SelectorId {
        SelectorId {
            id: AtomicUsize::new(0),
        }
    }

    pub fn associate_selector(&self, poll: &Poll) -> io::Result<()> {
        let selector_id = self.id.load(Ordering::SeqCst);
        let poll_exposed: &ExPoll = unsafe { transmute(poll) };
        if selector_id != 0 && selector_id != poll_exposed.selector.id() {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "socket already registered",
            ))
        } else {
            self.id.store(poll_exposed.selector.id(), Ordering::SeqCst);
            Ok(())
        }
    }
}

impl Clone for SelectorId {
    fn clone(&self) -> SelectorId {
        SelectorId {
            id: AtomicUsize::new(self.id.load(Ordering::SeqCst)),
        }
    }
}
