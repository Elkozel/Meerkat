use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::IpAddr,
    ops::Deref,
};

pub type Span = std::ops::Range<usize>;
pub type Spanned<T> = (T, Span);

#[derive(Debug, PartialEq, Eq)]
pub struct AST {
    pub rules: HashMap<u32, (Rule, Span)>,
}

#[derive(Debug, Hash, Clone)]
pub struct Rule {
    pub action: Spanned<String>,
    pub header: Spanned<Header>,
    pub options: Vec<Spanned<RuleOption>>,
}
impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} ({})",
            self.action.0,
            self.header.0,
            self.options
                .iter()
                .map(|(option, _)| option.to_string())
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
impl Rule {
    pub fn source(&self) -> &Spanned<NetworkAddress> {
        let (header, span) = &self.header;
        &header.source
    }
    pub fn source_port(&self) -> &Spanned<NetworkPort> {
        let (header, span) = &self.header;
        &header.source_port
    }
    pub fn destination(&self) -> &Spanned<NetworkAddress> {
        let (header, span) = &self.header;
        &header.destination
    }
    pub fn destination_port(&self) -> &Spanned<NetworkPort> {
        let (header, span) = &self.header;
        &header.destination_port
    }
    pub fn addresses(&self) -> Vec<&Spanned<NetworkAddress>> {
        vec![self.source(), self.destination()]
    }
    pub fn ports(&self) -> Vec<&Spanned<NetworkPort>> {
        vec![self.source_port(), self.destination_port()]
    }
}

#[derive(Debug, Hash, Clone)]
pub struct Header {
    pub protocol: Spanned<String>,
    pub source: Spanned<NetworkAddress>,
    pub source_port: Spanned<NetworkPort>,
    pub direction: Spanned<NetworkDirection>,
    pub destination: Spanned<NetworkAddress>,
    pub destination_port: Spanned<NetworkPort>,
}
impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {}",
            self.protocol.0,
            self.source.0,
            self.source_port.0,
            self.direction.0,
            self.destination.0,
            self.destination_port.0
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
impl Header {
    pub fn find_variables(&self, name: &Option<String>, variables: &mut Vec<Spanned<String>>) {
        let (source, source_span) = &self.source;
        source.find_variables_with_array(name, &mut variables);
        let (destination, destination_span) = &self.destination;
        destination.find_variables_with_array(name, &mut variables);
    }
}

#[derive(Debug, Hash, Clone)]
pub enum NetworkAddress {
    Any,
    IPAddr(Spanned<IpAddr>),
    CIDR(Spanned<IpAddr>, Spanned<u8>),
    IPGroup(Vec<Spanned<NetworkAddress>>),
    NegIP(Box<Spanned<NetworkAddress>>),
    IPVariable(Spanned<String>),
}

impl fmt::Display for NetworkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkAddress::Any => write!(f, "any"),
            NetworkAddress::IPAddr(ip) => write!(f, "{}", ip.0.to_string()),
            NetworkAddress::CIDR(ip, mask) => write!(f, "{}/{}", ip.0, mask.0),
            NetworkAddress::IPGroup(ips) => write!(
                f,
                "[{}]",
                ips.iter()
                    .map(|(ip, _)| ip.to_string())
                    .collect::<Vec<String>>()
                    .join(", ")
            ),
            NetworkAddress::NegIP(ip) => {
                let (ip, _) = ip.as_ref();
                write!(f, "!{}", ip)
            }
            NetworkAddress::IPVariable(name) => write!(f, "${}", name.0),
        }
    }
}
impl PartialEq for NetworkAddress {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (NetworkAddress::Any, NetworkAddress::Any) => true,
            (NetworkAddress::IPAddr(ip1), NetworkAddress::IPAddr(ip2)) => ip1.0 == ip2.0,
            (NetworkAddress::CIDR(ip1, mask1), NetworkAddress::CIDR(ip2, mask2)) => {
                ip1.0 == ip2.0 && mask1.0 == mask2.0
            }
            (NetworkAddress::IPGroup(ip_group1), NetworkAddress::IPGroup(ip_group2)) => {
                let a: HashSet<_> = ip_group1.iter().map(|ip| &ip.0).collect();
                let b: HashSet<_> = ip_group2.iter().map(|ip| &ip.0).collect();
                a == b
            }
            (NetworkAddress::NegIP(ip1), NetworkAddress::NegIP(ip2)) => {
                ip1.as_ref().0 == ip2.as_ref().0
            }
            (NetworkAddress::IPVariable(var1), NetworkAddress::IPVariable(var2)) => {
                var1.0 == var2.0
            }
            _ => false,
        }
    }
}
impl Eq for NetworkAddress {}
impl NetworkAddress {
    pub fn find_variables(&self, name: &Option<String>) -> Option<Vec<Spanned<String>>> {
        let mut ret: Vec<Spanned<String>> = vec![];
        match &self {
            NetworkAddress::Any => (),
            NetworkAddress::IPAddr(_) => (),
            NetworkAddress::CIDR(_, _) => (),
            NetworkAddress::IPGroup(group) => group.iter().for_each(|(ip, ip_span)| {
                ip.find_variables_with_array(name, &mut ret);
            }),
            NetworkAddress::NegIP(ip) => ip.deref().0.find_variables_with_array(name, &mut ret),
            NetworkAddress::IPVariable(var) => {
                match name {
                    Some(name) => {if *name == var.0 {
                        ret.push(var.clone());
                    }},
                    None => {ret.push(var.clone());},
                };
                
            }
            _ => ()
        }

        if ret.len() == 0 {
            return None;
        } else {
            Some(ret)
        }
    }
    fn find_variables_with_array(&self, name: &Option<String>, vector: &mut Vec<Spanned<String>>) -> () {
        match &self {
            NetworkAddress::Any => (),
            NetworkAddress::IPAddr(_) => (),
            NetworkAddress::CIDR(_, _) => (),
            NetworkAddress::IPGroup(group) => group.iter().for_each(|(ip, ip_span)| {
                ip.find_variables_with_array(name, vector);
            }),
            NetworkAddress::NegIP(ip) => ip.deref().0.find_variables_with_array(name, vector),
            NetworkAddress::IPVariable(var) => {
                match name {
                    Some(name) => {if *name == var.0 {
                        vector.push(var.clone());
                    }},
                    None => {vector.push(var.clone());},
                };
            }
            _ => ()
        }
    }
}

#[derive(Debug, Hash, Clone)]
pub enum NetworkPort {
    Any,
    Port(u16),
    PortGroup(Vec<Spanned<NetworkPort>>),
    PortRange(Spanned<u16>, Spanned<u16>),
    PortOpenRange(Spanned<u16>, bool),
    NegPort(Box<Spanned<NetworkPort>>),
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
                    .map(|(port, _)| port.to_string())
                    .collect::<Vec<String>>()
                    .join(",")
            ),
            NetworkPort::PortRange(from, to) => write!(f, "{}:{}", from.0, to.0),
            NetworkPort::PortOpenRange(port, up) => {
                if *up {
                    write!(f, "{}:", port.0)
                } else {
                    write!(f, ":{}", port.0)
                }
            }
            NetworkPort::NegPort(port) => {
                let (port, _) = port.as_ref();
                write!(f, "!{}", port)
            }
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
            (NetworkPort::PortOpenRange((port1, _), up1), Self::PortOpenRange((port2, _), up2)) => {
                port1 == port2 && up1 == up2
            }
            (NetworkPort::NegPort(port1), NetworkPort::NegPort(port2)) => {
                port1.as_ref().0 == port2.as_ref().0
            }
            _ => false,
        }
    }
}
impl Eq for NetworkPort {}

#[derive(Debug, Hash, Clone, PartialEq, Eq)]
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

#[derive(Debug, Hash, Clone)]
pub enum RuleOption {
    KeywordPair(Spanned<String>, Vec<Spanned<OptionsVariable>>),
    Buffer(Spanned<String>),
}

impl fmt::Display for RuleOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleOption::KeywordPair((key, _), op) => {
                let options = op
                    .iter()
                    .map(|(option, _)| option.to_string())
                    .collect::<Vec<String>>();
                write!(f, "{}: {}", key, options.join(", "))
            }
            RuleOption::Buffer((keyword, _)) => write!(f, "{}", keyword),
        }
    }
}

impl PartialEq for RuleOption {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                RuleOption::KeywordPair(keyword1, options1),
                RuleOption::KeywordPair(keyword2, options2),
            ) => {
                keyword1.0 == keyword2.0 && {
                    let a: HashSet<_> = options1.iter().map(|op| &op.0).collect();
                    let b: HashSet<_> = options2.iter().map(|op| &op.0).collect();
                    a == b
                }
            }
            (RuleOption::Buffer(buf1), RuleOption::Buffer(buf2)) => buf1.0 == buf2.0,
            _ => false,
        }
    }
}
impl Eq for RuleOption {}

#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub enum OptionsVariable {
    String(Spanned<String>),
    Other(Spanned<String>),
}

impl fmt::Display for OptionsVariable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OptionsVariable::String((string, span)) => write!(f, "\"{}\"", string),
            OptionsVariable::Other((string, span)) => write!(f, "{}", string),
        }
    }
}
