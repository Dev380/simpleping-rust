use nix::{
    libc::{self, sockaddr_ll, sockaddr_storage},
    sys::socket::{
        self, sockaddr, AddressFamily, LinkAddr, MsgFlags, SockFlag, SockProtocolInt, SockType,
        SockaddrLike,
    },
    unistd,
};

const ECHO_REQUEST: u8 = 8;
const BLANK_IP_HEADER: [u8; 20] = [69, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

struct Icmp {
    identifier: u16,
    sequence: u16,
    payload: Vec<u8>,
}

impl Icmp {
    fn as_bytes(&self) -> Vec<u8> {
        // Header
        let mut bytes = [0; 8];
        bytes[0] = ECHO_REQUEST;
        bytes[4..6].copy_from_slice(&self.identifier.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.sequence.to_be_bytes());

        let mut bytes = bytes.to_vec();
        bytes.extend(self.payload.clone());

        // Setting the checksum
        let checksum = internet_checksum::checksum(&bytes);
        bytes[2..4].copy_from_slice(&checksum);
        bytes
    }
}

struct Ipv4 {
    source_ip: [u8; 4],
    dest_ip: [u8; 4],
    payload: Vec<u8>,
}

impl Ipv4 {
    fn as_bytes(&self) -> Vec<u8> {
        // Header
        let mut bytes = BLANK_IP_HEADER;
        bytes[12..16].copy_from_slice(&self.source_ip);
        bytes[16..20].copy_from_slice(&self.dest_ip);
        // Total length
        let header_len = bytes.len();
        bytes[2..4].copy_from_slice(&((header_len + self.payload.len()) as u16).to_be_bytes());
        // Setting the checksum
        let checksum = internet_checksum::checksum(&bytes);
        bytes[10..12].copy_from_slice(&checksum);

        let mut bytes = bytes.to_vec();
        bytes.extend(self.payload.clone());
        bytes
    }
}

struct Ethernet {
    dest_mac: [u8; 6],
    source_mac: [u8; 6],
    payload: Vec<u8>,
}

impl Ethernet {
    fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = [0; 14];
        // Set IPv4 ethertype
        bytes[12..14].copy_from_slice(&[8, 0]);
        // Copy MAC addresses
        bytes[0..6].copy_from_slice(&self.dest_mac);
        bytes[6..12].copy_from_slice(&self.source_mac);
        // Payload
        let mut bytes = bytes.to_vec();
        bytes.extend(self.payload.clone());
        bytes
    }
}

fn main() {
    let iface = default_net::get_default_interface().unwrap();
    let source_ip = iface.ipv4[0].addr.octets();
    let source_mac = iface.mac_addr.unwrap().octets();
    let dest_mac = iface.gateway.unwrap().mac_addr.octets();

    let icmp = Icmp {
        identifier: 69,
        sequence: 420,
        payload: vec![1, 2, 3, 4],
    };
    let ip = Ipv4 {
        source_ip,
        dest_ip: [1, 1, 1, 1],
        payload: icmp.as_bytes(),
    };
    let ethernet = Ethernet {
        dest_mac,
        source_mac,
        payload: ip.as_bytes(),
    };

    let mac_address = unsafe {
        let mut mac_array = [0; 8];
        mac_array[0..6].copy_from_slice(&dest_mac);

        let mut storage: sockaddr_storage = std::mem::zeroed();
        let addr: *mut sockaddr_ll = &mut storage as *mut sockaddr_storage as *mut sockaddr_ll;
        (*addr).sll_family = libc::AF_PACKET as u16;
        (*addr).sll_protocol = (libc::ETH_P_IP as u16).to_be();
        (*addr).sll_addr = mac_array;
        (*addr).sll_halen = 6;
        (*addr).sll_ifindex = 3;
        let saddr = &storage as *const sockaddr_storage as *const libc::sockaddr;
        LinkAddr::from_raw(saddr as *const sockaddr, None).unwrap()
    };

    let socket = socket::socket(
        AddressFamily::Packet,
        SockType::Raw,
        SockFlag::empty(),
        SockProtocolInt(libc::ETH_P_IP),
    )
    .unwrap();
    socket::sendto(
        socket,
        &ethernet.as_bytes(),
        &mac_address,
        MsgFlags::empty(),
    )
    .unwrap();
    println!("Sending {:?}", ethernet.as_bytes());

    unistd::close(socket).unwrap();
}
