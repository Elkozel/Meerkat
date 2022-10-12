use std::{collections::HashSet, fmt, net::IpAddr};

#[derive(Debug, Hash)]
pub struct Rule {
    pub action: String,
    pub header: Header,
    pub options: Vec<Option>,
}
impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} ({})",
            self.action,
            self.header,
            self.options
                .iter()
                .map(|option| option.to_string())
                .collect::<Vec<String>>()
                .join(";")
        )
    }
}
impl PartialEq for Rule {
    fn eq(&self, other: &Self) -> bool {
        self.action == other.action && self.header == other.header && {
            let a: HashSet<_> = self.options.iter().collect();
            let b: HashSet<_> = other.options.iter().collect();
            a == b
        }
    }
}
impl Eq for Rule {}

#[derive(Debug, Hash)]
pub struct Header {
    pub protocol: String,
    pub source: NetworkAddress,
    pub source_port: NetworkPort,
    pub direction: NetworkDirection,
    pub destination: NetworkAddress,
    pub destination_port: NetworkPort,
}
impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {}",
            self.protocol,
            self.source,
            self.source_port,
            self.direction,
            self.destination,
            self.destination_port
        )
    }
}
impl PartialEq for Header {
    fn eq(&self, other: &Self) -> bool {
        self.protocol == other.protocol
            && self.source == other.source
            && self.source_port == other.source_port
            && self.direction == other.direction
            && self.destination == other.destination
            && self.destination_port == other.destination_port
    }
}
impl Eq for Header {}

#[derive(Debug, Hash)]
pub enum NetworkAddress {
    Any,
    IPAddr(IpAddr),
    CIDR(IpAddr, u16),
    IPGroup(Vec<NetworkAddress>),
    NegIP(Box<NetworkAddress>),
    IPVariable(String),
}

impl fmt::Display for NetworkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkAddress::Any => write!(f, "any"),
            NetworkAddress::IPAddr(ip) => write!(f, "{}", ip.to_string()),
            NetworkAddress::CIDR(ip, mask) => write!(f, "{}/{}", ip, mask),
            NetworkAddress::IPGroup(ips) => write!(
                f,
                "[{}]",
                ips.iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<String>>()
                    .join(", ")
            ),
            NetworkAddress::NegIP(ip) => write!(f, "!{}", *ip),
            NetworkAddress::IPVariable(name) => write!(f, "${}", name),
        }
    }
}
impl PartialEq for NetworkAddress {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (NetworkAddress::Any, NetworkAddress::Any) => true,
            (NetworkAddress::IPAddr(ip1), NetworkAddress::IPAddr(ip2)) => ip1 == ip2,
            (NetworkAddress::CIDR(ip1, mask1), NetworkAddress::CIDR(ip2, mask2)) => {
                ip1 == ip2 && mask1 == mask2
            }
            (NetworkAddress::IPGroup(group1), NetworkAddress::IPGroup(group2)) => {
                let a: HashSet<_> = group1.iter().collect();
                let b: HashSet<_> = group2.iter().collect();
                a == b
            }
            (NetworkAddress::NegIP(ip1), NetworkAddress::NegIP(ip2)) => ip1 == ip2,
            (NetworkAddress::IPVariable(var_name1), NetworkAddress::IPVariable(var_name2)) => {
                var_name1 == var_name2
            }
            _ => false,
        }
    }
}
impl Eq for NetworkAddress {}

#[derive(Debug, Hash)]
pub enum NetworkPort {
    Any,
    Port(u16),
    PortGroup(Vec<NetworkPort>),
    PortRange(u16, u16),
    PortOpenRange(u16, bool),
    NegPort(Box<NetworkPort>),
}

impl fmt::Display for NetworkPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkPort::Any => write!(f, "any"),
            NetworkPort::Port(port) => write!(f, "{}", port),
            NetworkPort::PortGroup(port_group) => write!(
                f,
                "[{}]",
                port_group
                    .iter()
                    .map(|port| port.to_string())
                    .collect::<Vec<String>>()
                    .join(",")
            ),
            NetworkPort::PortRange(from, to) => write!(f, "{}:{}", from, to),
            NetworkPort::PortOpenRange(port, up) => {
                if *up {
                    write!(f, "{}:", port)
                } else {
                    write!(f, ":{}", port)
                }
            }
            NetworkPort::NegPort(port) => write!(f, "!{}", port),
        }
    }
}

impl PartialEq for NetworkPort {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (NetworkPort::Any, NetworkPort::Any) => true,
            (NetworkPort::Port(port1), NetworkPort::Port(port2)) => port1 == port2,
            (NetworkPort::PortGroup(group1), NetworkPort::PortGroup(group2)) => {
                let a: HashSet<_> = group1.iter().collect();
                let b: HashSet<_> = group2.iter().collect();
                a == b
            }
            (NetworkPort::PortRange(from1, to1), NetworkPort::PortRange(from2, to2)) => {
                from1 == from2 && to1 == to2
            }
            (NetworkPort::PortOpenRange(port1, up1), Self::PortOpenRange(port2, up2)) => {
                port1 == port2 && up1 == up2
            }
            (NetworkPort::NegPort(port1), NetworkPort::NegPort(port2)) => port1 == port2,
            _ => false,
        }
    }
}
impl Eq for NetworkPort {}

#[derive(Debug, Hash)]
pub enum NetworkDirection {
    SrcToDst,
    Both,
    DstToSrc,
    Unrecognized(String),
}

impl fmt::Display for NetworkDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkDirection::SrcToDst => write!(f, "->"),
            NetworkDirection::Both => write!(f, "<>"),
            NetworkDirection::DstToSrc => write!(f, "<-"),
            NetworkDirection::Unrecognized(dir) => write!(f, "{}", dir),
        }
    }
}
impl PartialEq for NetworkDirection {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (NetworkDirection::SrcToDst, NetworkDirection::SrcToDst) => true,
            (NetworkDirection::Both, NetworkDirection::Both) => true,
            (NetworkDirection::DstToSrc, NetworkDirection::DstToSrc) => true,
            (NetworkDirection::Unrecognized(dir1), NetworkDirection::Unrecognized(dir2)) => {
                dir1 == dir2
            }
            _ => false,
        }
    }
}
impl Eq for NetworkDirection {}

#[derive(Debug, Hash)]
pub enum Option {
    KeywordPair(String, Vec<String>),
    Buffer(String),
}

impl fmt::Display for Option {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Option::KeywordPair(key, op) => write!(f, "{}: {}", key, op.join(", ")),
            Option::Buffer(keyword) => write!(f, "{}", keyword),
        }
    }
}

impl PartialEq for Option {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Option::KeywordPair(keyword1, options1), Option::KeywordPair(keyword2, options2)) => {
                keyword1 == keyword2 && {
                    let a: HashSet<_> = options1.iter().collect();
                    let b: HashSet<_> = options2.iter().collect();
                    a == b
                }
            }
            (Option::Buffer(s1), Option::Buffer(s2)) => s1 == s2,
            _ => false,
        }
    }
}
impl Eq for Option {}
