use chumsky::prelude::*;
use std::net::IpAddr::V4;
use std::net::Ipv4Addr;

use crate::rule::{Header, NetworkAddress, NetworkDirection, NetworkPort, Option, Rule};

impl Rule {
    pub fn parser() -> impl Parser<char, Rule, Error = Simple<char>> {
        let action = text::ident().padded();
        let options = Option::parser()
            .separated_by(just(";"))
            .allow_trailing()
            .delimited_by(just("("), just(")"))
            .padded();

        action
            .then(Header::parser().padded())
            .then(options)
            .map(|((action, header), options)| Rule {
                action: action,
                header: header,
                options: options,
            })
    }
}

impl Header {
    fn parser() -> impl Parser<char, Header, Error = Simple<char>> {
        let protocol = text::ident();

        protocol
            .then(NetworkAddress::parser().padded())
            .then(NetworkPort::parser().padded())
            .then(NetworkDirection::parser().padded())
            .then(NetworkAddress::parser().padded())
            .then(NetworkPort::parser().padded())
            .map(
                |(
                    ((((protocol, source), source_port), direction), destination),
                    destination_port,
                )| Header {
                    protocol,
                    source,
                    source_port,
                    direction,
                    destination,
                    destination_port,
                },
            )
    }
}

impl NetworkAddress {
    fn parser() -> impl Parser<char, NetworkAddress, Error = Simple<char>> {
        recursive(|ipaddress| {
            let digit = text::int(10).map(|int: String| {
                if (int.parse::<u128>().unwrap()) < 255 {
                    int.parse::<u8>().unwrap()
                } else {
                    0 as u8
                }
            });

            let any = just("any").map(|_| NetworkAddress::Any);
            // Simple IP address
            let ipv4 = digit
                .separated_by(just("."))
                .exactly(4)
                .map(|a| NetworkAddress::IPAddr(V4(Ipv4Addr::new(a[0], a[1], a[2], a[3]))));
            // CIDR IP Address
            let cidr = ipv4
                .then_ignore(just("/"))
                .then(digit)
                .map(|(ip, mask)| match ip {
                    NetworkAddress::IPAddr(ip) => NetworkAddress::CIDR(ip, mask.into()),
                    _ => NetworkAddress::Any, // This should never happen
                });
            // IP Group
            let ip_group = ipaddress
                .separated_by(just(","))
                .delimited_by(just("["), just("]"))
                .map(|ips| NetworkAddress::IPGroup(ips));
            // Negated port: !5
            let negated_ip = just("!")
                .then(ipv4.or(ip_group.clone()))
                .map(|(_, ip)| NetworkAddress::NegIP(Box::new(ip)));

            let ip_variable = just("$")
                .then(text::ident())
                .map(|(_, name)| NetworkAddress::IPVariable(name));

            ip_variable
                .or(negated_ip)
                .or(ip_group)
                .or(cidr)
                .or(ipv4)
                .or(any)
                .padded()
        })
    }
}

impl NetworkPort {
    fn parser() -> impl Parser<char, NetworkPort, Error = Simple<char>> {
        recursive(|port| {
            let any = just("any").map(|_| NetworkPort::Any);
            // Just a number
            let port_number = text::int(10)
                .map(|s: String| NetworkPort::Port(s.parse().unwrap()))
                .padded();
            // Port range: 1:32
            let port_range = text::int(10).or_not()
                .then_ignore(just(":"))
                .then(text::int(10).or_not())
                .try_map(|a:(std::option::Option<String>, std::option::Option<String>), span|match a {
                    (None, None) => Err(Simple::custom(span, "Port range cannot be \":\"")),
                    (None, Some(port)) => Ok(NetworkPort::PortOpenRange(port.parse().unwrap(), false)),
                    (Some(port), None) => Ok(NetworkPort::PortOpenRange(port.parse().unwrap(), false)),
                    (Some(port_from), Some(port_to)) => Ok(NetworkPort::PortRange(port_from.parse().unwrap(), port_to.parse().unwrap())),
                });
            // Port group: [1,2,3]
            let port_group = port
                .separated_by(just(","))
                .delimited_by(just("["), just("]"))
                .map(|ports| NetworkPort::PortGroup(ports));
            // Negated port: !5
            let negated_port = just("!")
                .then(port_number.or(port_range).or(port_group.clone()))
                .map(|(_, ports)| NetworkPort::NegPort(Box::new(ports)));

            negated_port
                .or(port_group)
                .or(port_range)
                .or(port_number)
                .or(any)
                .padded()
        })
    }
}

impl NetworkDirection {
    fn parser() -> impl Parser<char, NetworkDirection, Error = Simple<char>> {
        just("->")
            .or(just("<>"))
            .or(just("<-"))
            .map(|dir| match dir {
                "->" => NetworkDirection::SrcToDst,
                "<>" => NetworkDirection::Both,
                "<-" => NetworkDirection::DstToSrc,
                el => NetworkDirection::Unrecognized(el.to_string()),
            })
    }
}

impl Option {
    fn parser() -> impl Parser<char, Option, Error = Simple<char>> {
        let escaped_chars = one_of("\";").delimited_by(just("\\"), empty());
        let unescaped_value = escaped_chars.or(none_of(";,")).repeated()
            .collect::<String>();

        let keyword_pair = text::ident()
            .padded()
            .then_ignore(just(":"))
            .then(unescaped_value.padded().separated_by(just(",")))
            .map(|(keyword, options)| Option::KeywordPair(keyword, options));

        let buffer = text::ident()
            .padded()
            .map(|keyword| Option::Buffer(keyword));

        keyword_pair
            .or(buffer)
            .padded()
    }
}
