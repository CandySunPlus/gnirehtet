use log::*;
use mio::{Event, PollOpt};
use mio::{Ready, Token};
use std::cell::RefCell;
use std::io;
use std::net::IpAddr;
use std::rc::Rc;
use std::rc::Weak;
use std::time::Instant;

use super::{
    binary,
    client::{Client, ClientChannel},
    connection::Connection,
    connection::ConnectionId,
    icmp_socket::IcmpSocket,
    ipv4_header::Ipv4Header,
    ipv4_packet::Ipv4Packet,
    ipv4_packet::MAX_PACKET_LENGTH,
    packetizer::Packetizer,
    selector::Selector,
    stream_buffer::StreamBuffer,
    transport_header::TransportHeader,
};

const TAG: &'static str = "IcmpConnection";
const IDLE_TIMEOUT_SECONDS: u64 = 2;

pub struct IcmpConnection {
    id: ConnectionId,
    client: Weak<RefCell<Client>>,
    interests: Ready,
    socket: IcmpSocket,
    token: Token,
    client_to_network: StreamBuffer,
    network_to_client: Packetizer,
    closed: bool,
    idle_since: Instant,
}

impl IcmpConnection {
    pub fn create(
        selector: &mut Selector,
        id: ConnectionId,
        client: Weak<RefCell<Client>>,
        ipv4_header: Ipv4Header,
        transport_header: TransportHeader,
    ) -> io::Result<Rc<RefCell<Self>>> {
        cx_info!(target: TAG, id, "Open");

        let interests = Ready::readable();
        let packetizer = Packetizer::new(&ipv4_header, &transport_header);
        let socket = Self::create_socket(&id)?;

        let rc = Rc::new(RefCell::new(Self {
            id,
            client,
            interests,
            socket,
            token: Token(0),
            client_to_network: StreamBuffer::new(MAX_PACKET_LENGTH),
            network_to_client: packetizer,
            closed: false,
            idle_since: Instant::now(),
        }));

        {
            let mut self_ref = rc.borrow_mut();

            let rc2 = rc.clone();
            // must annotate selector type: https://stackoverflow.com/a/44004103/1987178
            let handler =
                move |selector: &mut Selector, event| rc2.borrow_mut().on_ready(selector, event);
            let token =
                selector.register(&self_ref.socket, handler, interests, PollOpt::level())?;
            self_ref.token = token;
        }
        Ok(rc)
    }

    fn create_socket(id: &ConnectionId) -> io::Result<IcmpSocket> {
        let socket = IcmpSocket::bind(
            "0.0.0.0"
                .parse::<IpAddr>()
                .expect("IP address parse failed"),
        )?;
        socket.connect(&id.rewritten_destination().into())?;
        Ok(socket)
    }

    fn remove_from_router(&self) {
        let client_rc = self.client.upgrade().expect("Expected client not found");
        let mut client = client_rc.borrow_mut();
        client.router().remove(self);
    }

    fn on_ready(&mut self, selector: &mut Selector, event: Event) {
        match self.process(selector, event) {
            Ok(_) => (),
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                cx_debug!(target: TAG, self.id, "Spurious event, ignoring")
            }
            Err(_) => panic!("Unexpected unhandled error"),
        }
    }

    fn process(&mut self, selector: &mut Selector, event: Event) -> io::Result<()> {
        if !self.closed {
            self.touch();
            let ready = event.readiness();
            cx_debug!(
                target: TAG,
                self.id,
                "connection in process R:{}::W:{}::C:{}",
                ready.is_readable(),
                ready.is_writable(),
                self.closed
            );
            if ready.is_readable() || ready.is_writable() {
                if ready.is_writable() {
                    self.process_send(selector)?;
                }
                if !self.closed && ready.is_readable() {
                    self.process_receive(selector)?;
                }
                if !self.closed {
                    self.update_interests(selector);
                }
            } else {
                self.close(selector);
            }
            if self.closed {
                self.remove_from_router();
            }
        }
        Ok(())
    }

    fn process_send(&mut self, selector: &mut Selector) -> io::Result<()> {
        match self.write() {
            Ok(_) => (),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                cx_debug!(target: TAG, self.id, "Spurious event, ignoring");
                return Err(err);
            }
            Err(ref err) => {
                cx_error!(
                    target: TAG,
                    self.id,
                    "Cannot write: [{:?}] {}",
                    err.kind(),
                    err
                );
                self.close(selector);
            }
        }
        Ok(())
    }

    fn process_receive(&mut self, selector: &mut Selector) -> io::Result<()> {
        match self.read(selector) {
            Ok(_) => (),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                return Err(err);
            }
            Err(ref err) => {
                cx_error!(
                    target: TAG,
                    self.id,
                    "Cannot read: [{:?}] {}",
                    err.kind(),
                    err
                );
                self.close(selector);
            }
        }
        Ok(())
    }

    fn read(&mut self, selector: &mut Selector) -> io::Result<()> {
        let ipv4_packet = self
            .network_to_client
            .packetize_read(&mut self.socket, None)?
            .expect("Packetzer reader failed");
        let client_rc = self.client.upgrade().expect("Expected client not found");

        match client_rc
            .borrow_mut()
            .send_to_client(selector, &ipv4_packet)
        {
            Ok(_) => {
                cx_debug!(
                    target: TAG,
                    self.id,
                    "Packet ({} bytes) send to client",
                    ipv4_packet.length()
                );
                if log_enabled!(target: TAG, Level::Trace) {
                    cx_trace!(
                        target: TAG,
                        self.id,
                        "send to client: {}",
                        binary::build_packet_string(ipv4_packet.raw())
                    );
                }
            }
            Err(_) => cx_warn!(target: TAG, self.id, "Cannot send to client, drop packet"),
        }
        Ok(())
    }

    fn write(&mut self) -> io::Result<()> {
        self.client_to_network.write_to(&mut self.socket)?;
        Ok(())
    }

    fn update_interests(&mut self, selector: &mut Selector) {
        let ready = if self.client_to_network.is_empty() {
            Ready::readable()
        } else {
            Ready::readable() | Ready::writable()
        };
        if self.interests != ready {
            cx_debug!(
                target: TAG,
                self.id,
                "set interests from {:?} to {:?}",
                self.interests,
                ready
            );
            self.interests = ready;
            selector
                .reregister(&self.socket, self.token, ready, PollOpt::level())
                .expect("Cannot register on poll");
        }
    }

    fn touch(&mut self) {
        self.idle_since = Instant::now();
    }
}

impl Connection for IcmpConnection {
    fn id(&self) -> &ConnectionId {
        &self.id
    }

    fn send_to_network(
        &mut self,
        selector: &mut Selector,
        _: &mut ClientChannel,
        ipv4_packet: &Ipv4Packet,
    ) {
        if ipv4_packet.length() as usize <= self.client_to_network.remaining() {
            let payload = ipv4_packet.payload().expect("No Payload");
            cx_trace!(
                target: TAG,
                self.id,
                "send to network {}",
                binary::build_packet_string(payload)
            );
            self.client_to_network.read_from(payload);
            self.update_interests(selector);
        } else {
            cx_warn!(target: TAG, self.id, "Cannot send to network, drop packet")
        }
    }

    fn close(&mut self, selector: &mut Selector) {
        cx_info!(target: TAG, self.id, "Close");
        self.closed = true;
        if let Err(err) = selector.deregister(&self.socket, self.token) {
            cx_warn!(
                target: TAG,
                self.id,
                "Fail to deregister ICMP stream: {}",
                err
            );
        }
    }

    fn is_expired(&self) -> bool {
        self.idle_since.elapsed().as_secs() > IDLE_TIMEOUT_SECONDS
    }

    fn is_closed(&self) -> bool {
        self.closed
    }
}
