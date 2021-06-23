use io::{Read, Write};
use log::*;
use mio::{Evented, Poll, PollOpt, Ready, Token};
use std::{io, mem::MaybeUninit};

use super::binary;
use super::datagram::DatagramReceiver;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

#[derive(Debug)]
pub struct IcmpSocket {
    socket: Socket,
}

const TAG: &'static str = "ICMP_SOCKET";

impl IcmpSocket {
    pub fn new(domain: Domain, ty: Type, protocol: Protocol) -> io::Result<Self> {
        debug!(target: TAG, "info: {:?}, {:?}, {:?}", domain, ty, protocol);
        let socket = Socket::new(domain, ty, Some(protocol)).map_err(|err| {
            debug!(target: TAG, "create icmp socket error: {:?}", err);
            err
        })?;

        socket.set_nonblocking(true)?;

        Ok(Self { socket })
    }

    pub fn recv(&self, buf: &mut [MaybeUninit<u8>]) -> io::Result<usize> {
        self.socket.recv(buf)
    }

    pub fn bind(&self, addr: &SockAddr) -> io::Result<()> {
        self.socket.bind(addr)
    }

    pub fn connect(&self, addr: &SockAddr) -> io::Result<()> {
        self.socket.connect(addr)
    }

    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.socket.send(buf)
    }
}

impl DatagramReceiver for IcmpSocket {
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let buf = unsafe { &mut *(buf as *mut [u8] as *mut [MaybeUninit<u8>]) };
        self.socket.recv(buf)
    }
}

impl Read for IcmpSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.read(buf)
    }
}

impl<'a> Read for &'a IcmpSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.socket).read(buf)
    }
}

impl Write for IcmpSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        debug!(
            target: TAG,
            "send payload {}",
            binary::build_packet_string(buf)
        );
        self.send(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

impl<'a> Write for &'a IcmpSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        debug!(
            target: TAG,
            "send payload {}",
            binary::build_packet_string(buf)
        );
        (&self).send(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&self.socket).flush()
    }
}

#[cfg(unix)]
use mio::unix::EventedFd;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

#[cfg(all(unix, not(target_os = "fuchsia")))]
impl Evented for IcmpSocket {
    fn register(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        EventedFd(&self.as_raw_fd()).register(poll, token, interest, opts)
    }
    fn reregister(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        EventedFd(&self.as_raw_fd()).reregister(poll, token, interest, opts)
    }
    fn deregister(&self, poll: &mio::Poll) -> io::Result<()> {
        EventedFd(&self.as_raw_fd()).deregister(poll)
    }
}

#[cfg(all(unix, not(target_os = "fuchsia")))]
impl FromRawFd for IcmpSocket {
    unsafe fn from_raw_fd(fd: RawFd) -> IcmpSocket {
        IcmpSocket {
            socket: Socket::from_raw_fd(fd),
        }
    }
}

#[cfg(all(unix, not(target_os = "fuchsia")))]
impl IntoRawFd for IcmpSocket {
    fn into_raw_fd(self) -> RawFd {
        self.socket.into_raw_fd()
    }
}

#[cfg(all(unix, not(target_os = "fuchsia")))]
impl AsRawFd for IcmpSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

#[cfg(windows)]
use std::os::windows::io::{FromRawSocket, IntoRawSocket};

#[cfg(windows)]
impl IcmpSocket {
    fn post_register(&self, interest: Ready, me: &mut Inner) {
        if interest.is_readable() {
            //We use recv_from here since it is well specified for both
            //connected and non-connected sockets and we can discard the address
            //when calling recv().
            self.imp.schedule_read_from(me);
        }
        // See comments in TcpSocket::post_register for what's going on here
        if interest.is_writable() {
            if let State::Empty = me.write {
                self.imp.add_readiness(me, Ready::writable());
            }
        }
    }
}

#[cfg(windows)]
impl Evented for IcmpSocket {
    fn register(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        let mut me = self.socket.inner;
        me.iocp.register_socket(
            &self.imp.inner.socket,
            poll,
            token,
            interest,
            opts,
            &self.registration,
        )?;
        self.post_register(interest, &mut me);
        Ok(())
    }

    fn reregister(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        let mut me = self.socket.inner;
        me.iocp.reregister_socket(
            &self.imp.inner.socket,
            poll,
            token,
            interest,
            opts,
            &self.registration,
        )?;
        self.post_register(interest, &mut me);
        Ok(())
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        self.socket
            .inner
            .iocp
            .deregister(&self.imp.inner.socket, poll, &self.registration)
    }
}
