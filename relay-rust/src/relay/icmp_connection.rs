use log::*;
use mio::{Event, PollOpt};
use mio::{Ready, Token};
use socket2::Protocol;
use socket2::{Domain, Type};
use std::cell::RefCell;
use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::rc::Rc;
use std::rc::Weak;
use std::time::Instant;

use super::{
    connection::Connection,
    socket::Socket,
    client::{Client, ClientChannel},
    connection::ConnectionId,
    datagram_buffer::DatagramBuffer,
    ipv4_header::Ipv4Header,
    ipv4_packet::Ipv4Packet,
    packetizer::Packetizer,
    selector::Selector,
    transport_header::TransportHeader,
};


const TAG: &'static str = "IcmpConnection";
const IDLE_TIMEOUT_SECONDS: u64 = 2;

pub struct IcmpConnection {
    id: ConnectionId,
    client: Weak<RefCell<Client>>,
    interests: Ready,
    socket: Socket,
    token: Token,
    client_to_network: DatagramBuffer,
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
            client_to_network: DatagramBuffer::new(4),
            network_to_client: packetizer,
            closed: false,
            idle_since: Instant::now(),
        }));

        {
            let mut self_ref = rc.borrow_mut();

            let rc2 = rc.clone();
            // must anotate selector type: https://stackoverflow.com/a/44004103/1987178
            let handler =
                move |selector: &mut Selector, event| rc2.borrow_mut().on_ready(selector, event);
            let token =
                selector.register(&self_ref.socket, handler, interests, PollOpt::level())?;
            self_ref.token = token;
        }
        Ok(rc)
    }

    fn create_socket(id: &ConnectionId) -> io::Result<Socket> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        let socket = Socket::new(Domain::IPV4, Type::RAW, Protocol::ICMPV4)?;
        socket.bind(&addr.into())?;
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
            if ready.is_readable() || ready.is_writable() {
            } else {
                self.close(selector);
            }
            if self.closed {
                self.remove_from_router();
            }
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
        cx_debug!(target: TAG, self.id, "interests: {:?}", ready);
        if self.interests != ready {
            self.interests = ready;
            selector
                .register(&self.socket, self.token, ready, PollOpt::level())
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
        match self
            .client_to_network
            .read_from(ipv4_packet.payload().expect("No payload"))
        {
            Ok(_) => {
                todo!();
            }
            Err(err) => cx_warn!(
                target: TAG,
                self.id,
                "Cannot send to network, drop packet: {}",
                err
            ),
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
