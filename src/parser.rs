use chumsky::prelude::*;
use std::net::Ipv4Addr;
use std::{net::IpAddr::V4, ops::Range};

use crate::rule::{
    Header, NetworkAddress, NetworkDirection, NetworkPort, OptionsVariable, Rule, RuleOption, Span,
    Spanned, AST,
};

pub fn parse_ast() {
    
}

impl Rule {
    pub fn parser() -> impl Parser<char, (Rule, Span), Error = Simple<char>> {
        let action = text::ident()
            .padded()
            .map_with_span(|action, span| (action, span));
        let options = RuleOption::parser()
            .separated_by(just(";"))
            .allow_trailing()
            .delimited_by(just("("), just(")"))
            .padded();

        action
            .then(Header::parser().padded())
            .then(options)
            .map_with_span(|((action, header), options), span| {
                (
                    Rule {
                        action: action,
                        header: header,
                        options: options,
                    },
                    span,
                )
            })
    }
}

impl Header {
    fn parser() -> impl Parser<char, (Header, Span), Error = Simple<char>> {
        let protocol = text::ident().map_with_span(|protocol, span| (protocol, span));
        let address_port_combined = NetworkAddress::parser()
            .padded()
            .then(NetworkPort::parser().padded());

        let address_port_combined2 = NetworkAddress::parser()
            .padded()
            .then(NetworkPort::parser().padded());

        protocol
            .then(address_port_combined)
            .then(NetworkDirection::parser().padded())
            .then(address_port_combined2)
            .map_with_span(|(((protocol, source), direction), destination), span| {
                (
                    Header {
                        protocol: protocol,
                        source: source.0,
                        source_port: source.1,
                        direction: direction,
                        destination: destination.0,
                        destination_port: destination.1,
                    },
                    span,
                )
            })
    }
}

impl NetworkAddress {
    fn parser() -> impl Parser<char, (NetworkAddress, Span), Error = Simple<char>> {
        recursive(|ipaddress| {
            let digit = text::int(10).try_map(|int: String, span: Span| {
                int.parse::<u8>().map_err(|e| {
                    Simple::custom(
                        span,
                        format!(
                            "Every digit of the IP address should be less than 255 (Err: {})",
                            e
                        ),
                    )
                })
            });

            let any = just("any").map_with_span(|_, span| (NetworkAddress::Any, span));
            // Simple IP address
            let ipv4 = digit
                .separated_by(just("."))
                .exactly(4)
                .map_with_span(|ip, span| {
                    (
                        NetworkAddress::IPAddr((
                            V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
                            span.clone(),
                        )),
                        span,
                    )
                });
            // CIDR IP Address
            let cidr = ipv4
                .then_ignore(just("/"))
                .then(
                    text::int(10)
                        .map_with_span(|mask: String, span| (mask.parse::<u8>().unwrap(), span)),
                )
                .try_map(|(ip, mask), span| match ip.0 {
                    NetworkAddress::IPAddr(ip) => Ok((NetworkAddress::CIDR(ip, mask), span)),
                    _ => Err(Simple::custom(
                        span,
                        "CIDR needs a valid IP, if you see this error, please report it :)",
                    )),
                });
            // IP Group
            let ip_group = ipaddress
                .separated_by(just(","))
                .delimited_by(just("["), just("]"))
                .map_with_span(|ips, span| (NetworkAddress::IPGroup(ips), span));
            // Negated port: !5
            let negated_ip = just("!")
                .then(ipv4.or(ip_group.clone()))
                .map_with_span(|(_, ip), span| (NetworkAddress::NegIP(Box::new(ip)), span));

            let ip_variable =
                just("$")
                    .then(text::ident())
                    .map_with_span(|(_, name), span: Range<usize>| {
                        (NetworkAddress::IPVariable((name, span.clone())), span)
                    });

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
    fn parser() -> impl Parser<char, (NetworkPort, Span), Error = Simple<char>> {
        recursive(|port| {
            let number = text::int(10).try_map(|num: String, span: Span| {
                Ok((
                    num.parse::<u16>()
                        .map_err(|e| Simple::<char>::custom(span.clone(), format!("{}", e)))
                        .unwrap(),
                    span,
                ))
            });
            let any = just("any").map_with_span(|_, span| (NetworkPort::Any, span));
            // Just a number
            let port_number = number
                .map(|(port, span)| (NetworkPort::Port(port), span))
                .padded();
            // Port range: 1:32
            let port_range = number
                .or_not()
                .then_ignore(just(":"))
                .then(number.or_not())
                .try_map(
                    |a: (
                        std::option::Option<(u16, Span)>,
                        std::option::Option<(u16, Span)>,
                    ),
                     span| match a {
                        (None, None) => Err(Simple::custom(span, "Port range cannot be \":\"")),
                        (None, Some((port, span))) => Ok((
                            NetworkPort::PortOpenRange((port, span.clone()), false),
                            span,
                        )),
                        (Some((port, span)), None) => Ok((
                            NetworkPort::PortOpenRange((port, span.clone()), false),
                            span,
                        )),
                        (Some((port_from, span_from)), Some((port_to, span_to))) => Ok((
                            NetworkPort::PortRange((port_from, span_from), (port_to, span_to)),
                            span,
                        )),
                    },
                );
            // Port group: [1,2,3]
            let port_group = port
                .separated_by(just(","))
                .delimited_by(just("["), just("]"))
                .map_with_span(|ports, span| (NetworkPort::PortGroup(ports), span));
            // Negated port: !5
            let negated_port = just("!")
                .then(port_number.or(port_range).or(port_group.clone()))
                .map_with_span(|(_, ports), span| (NetworkPort::NegPort(Box::new(ports)), span));

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
    fn parser() -> impl Parser<char, (NetworkDirection, Span), Error = Simple<char>> {
        just("->")
            .or(just("<>"))
            .or(just("<-"))
            .map_with_span(|dir, span| match dir {
                "->" => (NetworkDirection::SrcToDst, span),
                "<>" => (NetworkDirection::Both, span),
                "<-" => (NetworkDirection::DstToSrc, span),
                el => (NetworkDirection::Unrecognized(el.to_string()), span),
            })
    }
}

impl RuleOption {
    fn parser() -> impl Parser<char, (RuleOption, Span), Error = Simple<char>> {
        let escaped_chars = one_of("\";").delimited_by(just("\\"), empty());
        let unescaped_value = escaped_chars
            .clone()
            .or(none_of(";,"))
            .repeated()
            .collect::<String>()
            .map_with_span(|options, span: Span| {
                (OptionsVariable::Other((options, span.clone())), span)
            });

        let string_value = escaped_chars
            .or(none_of("\""))
            .repeated()
            .delimited_by(just("\""), just("\""))
            .collect::<String>()
            .padded()
            .map_with_span(|value, span: Span| {
                (OptionsVariable::String((value, span.clone())), span)
            });

        let keyword = text::ident()
            .padded()
            .map_with_span(|keyword, span| (keyword, span));

        let keyword_pair = keyword
            .padded()
            .then_ignore(just(":"))
            .then(
                string_value
                    .or(unescaped_value)
                    .padded()
                    .separated_by(just(",")),
            )
            .padded()
            .map_with_span(|(keyword, options), span| {
                (RuleOption::KeywordPair(keyword, options), span)
            });

        let buffer = keyword
            .padded()
            .map_with_span(|buffer, span| (RuleOption::Buffer(buffer), span));

        keyword_pair.or(buffer)
    }
}
