//! Provides the parsing for the signatures
//!
//! Powered by [chumsky], this parser guarantees an extremely fast and reliable
//! signature parsing.
//!
//! [chumsky]: https://docs.rs/chumsky/latest/chumsky/
use chumsky::prelude::*;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::{net::IpAddr::V4, net::IpAddr::V6, ops::Range};

use crate::rule::header::Header;
use crate::rule::header::NetworkAddress;
use crate::rule::header::NetworkDirection;
use crate::rule::header::NetworkPort;
use crate::rule::options::OptionsVariable;
use crate::rule::options::RuleOption;
use crate::rule::{
    Rule, Span,
};

impl Rule {
    /// Provides a parser for a signature
    pub fn parser() -> impl Parser<char, (Rule, Span), Error = Simple<char>> {
        let action = text::ident()
            .padded()
            .map_with_span(|action, span| (action, span));
        let options = RuleOption::parser()
            .separated_by(just(";"))
            .allow_trailing()
            .delimited_by(just("("), just(")"))
            .padded();

        action.or_not()
            .then(Header::parser().padded())
            .then(options.or_not())
            .then_ignore(end())
            .map_with_span(|((action, header), options), span| {
                (
                    Rule {
                        action: action.and_then(|(str, span)| Some((str.parse().unwrap(), span))),
                        header: header,
                        options: options,
                    },
                    span,
                )
            })
    }
}

impl Header {
    /// Provides a parser for a header
    fn parser() -> impl Parser<char, (Header, Span), Error = Simple<char>> {
        let protocol = text::ident().map_with_span(|protocol, span| (protocol, span));
        let address_port_combined = NetworkAddress::parser()
            .or_not()
            .padded()
            .then(NetworkPort::parser().or_not().padded());

        let address_port_combined2 = NetworkAddress::parser()
            .or_not() // I was too lasy cloning it TODO
            .padded()
            .then(NetworkPort::parser().or_not().padded());

        protocol.or_not()
            .then(address_port_combined)
            .then(NetworkDirection::parser().or_not().padded())
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
    /// Provides a parser for a network address
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

            let any = text::keyword::<_, _, Simple<char>>("any")
                .map_with_span(|_, span: Span| (NetworkAddress::Any(span.clone()), span));
            // Simple IPv4 address
            let ipv4 = digit
                .separated_by(just("."))
                .exactly(4)
                .map_with_span(|ipv4, span| {
                    (
                        NetworkAddress::IPAddr((
                            V4(Ipv4Addr::new(ipv4[0], ipv4[1], ipv4[2], ipv4[3])),
                            span.clone(),
                        )),
                        span,
                    )
                });
            // Simple IPv4 address
            let ipv6 = one_of::<_, _, Simple<char>>("0123456789abcdefABCDEF:")
                .repeated()
                .collect::<String>()
                .try_map(|ipv6, span: Span| {
                    let ip = ipv6.parse::<Ipv6Addr>();
                    match ip {
                        Ok(ip) => Ok((NetworkAddress::IPAddr((V6(ip), span.clone())), span)),
                        Err(err) => Err(Simple::<char>::custom(span, err.to_string())),
                    }
                });

            let ip = ipv6.or(ipv4);
            // CIDR IP Address (192.168.0.0/16)
            let cidr = ip
                .clone()
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
            // IP Group [..., ...]
            let ip_group = ipaddress
                .separated_by(just(","))
                .allow_trailing()
                .delimited_by(just("["), just("]"))
                .map_with_span(|ips, span| (NetworkAddress::IPGroup(ips), span));

            let ip_variable = just::<_, _, Simple<char>>('$')
                .ignore_then(text::ident())
                .map_with_span(|name, span: Range<usize>| {
                    (NetworkAddress::IPVariable((name, span.clone())), span)
                });

            // Negated IP: !192.168.0.1
            let negated_ip = just::<_, _, Simple<char>>('!')
                .ignore_then(
                    ip_variable
                        .or(ip_group.clone())
                        .or(cidr.clone())
                        .or(ip.clone()),
                )
                .map_with_span(|ip, span: Span| (NetworkAddress::NegIP(Box::new(ip)), span));

            ip_variable
                .or(negated_ip)
                .or(ip_group)
                .or(cidr)
                .or(ip)
                .or(any)
                .padded()
        })
    }
}

impl NetworkPort {
    /// Provides a parser for a network port
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
            let any = text::keyword::<_, _, Simple<char>>("any")
                .map_with_span(|_, span: Span| (NetworkPort::Any(span.clone()), span));
            // Just a number
            let port_number = number
                .map(|(port, span)| (NetworkPort::Port((port, span.clone())), span))
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
                .allow_trailing()
                .delimited_by(just("["), just("]"))
                .map_with_span(|ports, span| (NetworkPort::PortGroup(ports), span));

            // Variable: $ABC
            let port_variable = just::<_, _, Simple<char>>('$')
                .ignore_then(text::ident())
                .map_with_span(|name, span: Range<usize>| {
                    (NetworkPort::PortVar((name, span.clone())), span)
                });

            // Negated port: !5
            let negated_port = just::<_, _, Simple<char>>('!')
                .ignore_then(
                    port_variable
                        .or(port_group.clone())
                        .or(port_range.clone())
                        .or(port_number.clone()),
                )
                .map_with_span(|ports, span: Span| (NetworkPort::NegPort(Box::new(ports)), span));

            negated_port
                .or(port_variable)
                .or(port_group)
                .or(port_range)
                .or(port_number)
                .or(any)
                .padded()
        })
    }
}

impl NetworkDirection {
    /// Provides a parser for a network direction
    fn parser() -> impl Parser<char, (NetworkDirection, Span), Error = Simple<char>> {
        one_of::<_, _, Simple<char>>("<->")
            .repeated()
            .collect::<String>()
            .map_with_span(|dir, span| match dir.as_ref() {
                "->" => (NetworkDirection::SrcToDst, span),
                "<>" => (NetworkDirection::Both, span),
                "<-" => (NetworkDirection::DstToSrc, span),
                el => (NetworkDirection::Unrecognized(el.to_string()), span),
            })
    }
}

impl RuleOption {
    /// Provides a parser for an option inside the signature
    ///
    /// Signature options are divided into two categories:
    /// - Buffers (http.uri;)
    /// - Keyword pairs (msg: ...;)
    ///
    /// For more information, please see the [suricata docs]
    ///
    /// [suricata docs]: https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html#rule-options
    fn parser() -> impl Parser<char, (RuleOption, Span), Error = Simple<char>> {
        let escaped_chars = one_of::<_, _, Simple<char>>("\";\\").delimited_by(just("\\"), empty());
        let unescaped_value = escaped_chars
            .clone()
            .or(none_of::<_, _, Simple<char>>(";,"))
            .repeated()
            .collect::<String>()
            .map_with_span(|options, span: Span| {
                (OptionsVariable::Other((options, span.clone())), span)
            });

        let string_value = escaped_chars
            .or(none_of::<_, _, Simple<char>>("\""))
            .repeated()
            .delimited_by(just("\""), just("\""))
            .collect::<String>()
            .padded()
            .map_with_span(|value, span: Span| {
                (OptionsVariable::String((value, span.clone())), span)
            });

        let keyword = none_of::<_, _, Simple<char>>(":;)")
            .repeated()
            .collect::<String>()
            .padded()
            .map_with_span(|keyword, span| (keyword, span));

        // Keyword pair (msg: "...")
        let keyword_pair = keyword
            .clone()
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
