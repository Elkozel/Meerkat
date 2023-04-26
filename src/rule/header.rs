use ipnet::IpNet;
use std::collections::{HashMap, HashSet};
use std::{fmt, net::IpAddr};
use tower_lsp::lsp_types::{
    CompletionItem, CompletionItemKind, HoverContents, MarkupContent, SemanticTokenType,
};

use crate::rule::Span;
use crate::rule::Spanned;
use crate::semantic_token::ImCompleteSemanticToken;
use crate::semantic_token::LEGEND_TYPE;
use crate::suricata::Keyword;

use super::Completions;
use super::Hover;
use super::Semantics;

/// Represents a signature header
#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub struct Header {
    pub protocol: Option<Spanned<String>>,
    pub source: Option<Spanned<NetworkAddress>>,
    pub source_port: Option<Spanned<NetworkPort>>,
    pub direction: Option<Spanned<NetworkDirection>>,
    pub destination: Option<Spanned<NetworkAddress>>,
    pub destination_port: Option<Spanned<NetworkPort>>,
}
impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Go trough every part and print if the part is Some() and not None()
        if let Some((protocol, _)) = &self.protocol {
            write!(f, "{} ", protocol)?
        };
        if let Some((source, _)) = &self.source {
            write!(f, "{} ", source)?
        };
        if let Some((source_port, _)) = &self.source_port {
            write!(f, "{} ", source_port)?
        };
        if let Some((direction, _)) = &self.direction {
            write!(f, "{} ", direction)?
        };
        if let Some((destination, _)) = &self.destination {
            write!(f, "{} ", destination)?
        };
        if let Some((destination_port, _)) = &self.destination_port {
            write!(f, "{} ", destination_port)
        } else {
            write!(f, "")
        }
    }
}
impl Header {
    /// Find all variables, which are located inside the source or the destiantion
    /// fields of the header
    pub fn find_address_variables(
        &self,
        name: &Option<String>,
        variables: &mut Vec<Spanned<String>>,
    ) {
        // Iterate over source and destination addresses
        self.source
            .iter()
            .chain(self.destination.iter())
            .for_each(|(address, _)| address.find_variables_with_array(name, variables));
    }
    pub fn find_port_variables(&self, name: &Option<String>, variables: &mut Vec<Spanned<String>>) {
        // Iterate over source and destination ports
        self.source_port
            .iter()
            .chain(self.destination_port.iter())
            .for_each(|(address, _)| address.find_variables_with_array(name, variables));
    }
}
impl Semantics for Header {
    fn get_semantics(&self, col: &usize, semantic_tokens: &mut Vec<ImCompleteSemanticToken>) {
        // Push the semantic token for the protocol
        if let Some((_, span)) = &self.protocol {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: span.start + col,
                length: span.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::FUNCTION)
                    .unwrap(),
            });
        };
        // Push the semantic token for the source address
        if let Some((source, _)) = &self.source {
            source.get_semantics(col, semantic_tokens);
        };
        // Push the semantic token for the source port
        if let Some((source_port, _)) = &self.source_port {
            source_port.get_semantics(col, semantic_tokens);
        };
        // Push the semantic token for the direction
        if let Some((_, span)) = &self.direction {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: span.start + col,
                length: span.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::STRUCT)
                    .unwrap(),
            });
        };
        // Push the semantic token for the destination address
        if let Some((destination, _)) = &self.destination {
            destination.get_semantics(col, semantic_tokens);
        };
        // Push the semantic token for the destination port
        if let Some((destination_port, _)) = &self.destination_port {
            destination_port.get_semantics(col, semantic_tokens);
        }
    }
}

impl Hover for Header {
    fn get_hover(
        &self,
        col: &usize,
        keywords: &HashMap<String, Keyword>,
    ) -> Option<Spanned<tower_lsp::lsp_types::HoverContents>> {
        // Check if col is inside the source address
        if let Some((source, span)) = &self.source {
            if span.contains(col) {
                return source.get_hover(col, keywords);
            }
        }
        // Check if col is inside the source port
        if let Some((source_port, span)) = &self.source_port {
            if span.contains(col) {
                return source_port.get_hover(col, keywords);
            }
        }
        // Check if col is inside the direction
        if let Some((direction, span)) = &self.direction {
            if span.contains(col) {
                return direction.get_hover(col, keywords);
            }
        }
        // Check if col is inside the destination address
        if let Some((destination, span)) = &self.destination {
            if span.contains(col) {
                return destination.get_hover(col, keywords);
            }
        }
        // Check if col is inside the destination port
        if let Some((destination_port, span)) = &self.destination_port {
            if span.contains(col) {
                return destination_port.get_hover(col, keywords);
            }
        }
        // Otherwise, return none
        None
    }
}

/// Represents a network address (IP, CIDR range, groups of IPs, variables, etc.)
#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub enum NetworkAddress {
    Any(Span),
    IPAddr(Spanned<IpAddr>),
    CIDR(Spanned<IpAddr>, Spanned<u8>),
    IPGroup(Vec<Spanned<NetworkAddress>>),
    NegIP(Box<Spanned<NetworkAddress>>),
    IPVariable(Spanned<String>),
}

impl fmt::Display for NetworkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkAddress::Any(_) => write!(f, "any"),
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
impl NetworkAddress {
    pub fn find_variables(&self, name: &Option<String>) -> Option<Vec<Spanned<String>>> {
        let mut ret: Vec<Spanned<String>> = vec![];
        self.find_variables_with_array(name, &mut ret);
        if ret.len() == 0 {
            return None;
        } else {
            Some(ret)
        }
    }
    fn find_variables_with_array(
        &self,
        name: &Option<String>,
        vector: &mut Vec<Spanned<String>>,
    ) -> () {
        match &self {
            NetworkAddress::Any(_) => (),
            NetworkAddress::IPAddr(_) => (),
            NetworkAddress::CIDR(_, _) => (),
            NetworkAddress::IPGroup(group) => group.iter().for_each(|(ip, _)| {
                ip.find_variables_with_array(name, vector);
            }),
            NetworkAddress::NegIP(ip) => ip.0.find_variables_with_array(name, vector),
            NetworkAddress::IPVariable(var) => {
                match name {
                    Some(name) => {
                        if *name == var.0 {
                            vector.push(var.clone());
                        }
                    }
                    None => {
                        vector.push(var.clone());
                    }
                };
            }
        }
    }
}
impl Semantics for NetworkAddress {
    fn get_semantics(&self, col: &usize, semantic_tokens: &mut Vec<ImCompleteSemanticToken>) {
        match self {
            NetworkAddress::Any(span) => {
                semantic_tokens.push(ImCompleteSemanticToken {
                    start: span.start + col,
                    length: span.len(),
                    token_type: LEGEND_TYPE
                        .iter()
                        .position(|item| item == &SemanticTokenType::STRUCT)
                        .unwrap(),
                });
            }
            NetworkAddress::IPAddr((_, ip_span)) => {
                semantic_tokens.push(ImCompleteSemanticToken {
                    start: ip_span.start + col,
                    length: ip_span.len(),
                    token_type: LEGEND_TYPE
                        .iter()
                        .position(|item| item == &SemanticTokenType::KEYWORD)
                        .unwrap(),
                });
            }
            NetworkAddress::CIDR((_, ip_span), (_, mask_span)) => {
                semantic_tokens.push(ImCompleteSemanticToken {
                    start: ip_span.start + col,
                    length: ip_span.len(),
                    token_type: LEGEND_TYPE
                        .iter()
                        .position(|item| item == &SemanticTokenType::KEYWORD)
                        .unwrap(),
                });
                semantic_tokens.push(ImCompleteSemanticToken {
                    start: mask_span.start + col,
                    length: mask_span.len(),
                    token_type: LEGEND_TYPE
                        .iter()
                        .position(|item| item == &SemanticTokenType::NUMBER)
                        .unwrap(),
                });
            }
            NetworkAddress::IPGroup(ips) => {
                ips.iter().for_each(|(_, span)| {
                    semantic_tokens.push(ImCompleteSemanticToken {
                        start: span.start + col,
                        length: span.len(),
                        token_type: LEGEND_TYPE
                            .iter()
                            .position(|item| item == &SemanticTokenType::KEYWORD)
                            .unwrap(),
                    })
                });
            }
            NetworkAddress::NegIP(address) => {
                let (address, span) = address.as_ref();
                // Put the negation as a semantic token
                semantic_tokens.push(ImCompleteSemanticToken {
                    start: span.start + col,
                    length: 1,
                    token_type: LEGEND_TYPE
                        .iter()
                        .position(|item| item == &SemanticTokenType::OPERATOR)
                        .unwrap(),
                });
                // Put the address as a semantic token
                address.get_semantics(col, semantic_tokens);
            }
            NetworkAddress::IPVariable((_, variable_span)) => {
                semantic_tokens.push(ImCompleteSemanticToken {
                    start: variable_span.start + col,
                    length: variable_span.len(),
                    token_type: LEGEND_TYPE
                        .iter()
                        .position(|item| item == &SemanticTokenType::VARIABLE)
                        .unwrap(),
                });
            }
        }
    }
}
impl Hover for NetworkAddress {
    fn get_hover(
        &self,
        col: &usize,
        keywords: &HashMap<String, Keyword>,
    ) -> Option<Spanned<tower_lsp::lsp_types::HoverContents>> {
        match self {
            NetworkAddress::Any(_) => None,
            NetworkAddress::IPAddr(_) => None,
            NetworkAddress::CIDR((ip, ip_span), (mask, mask_span)) => {
                let range = IpNet::new(ip.clone(), mask.clone());
                match range {
                    Ok(range) => Some((
                        HoverContents::Markup(MarkupContent {
                            kind: tower_lsp::lsp_types::MarkupKind::Markdown,
                            value: [
                                format!("**{}**", range),
                                format!("{} - {}", range.network(), range.broadcast()),
                            ]
                            .join("\n\n"),
                        }),
                        Span {
                            start: ip_span.start,
                            end: mask_span.end,
                        },
                    )),
                    Err(_) => None,
                }
            }
            NetworkAddress::IPGroup(group) => {
                let (ip, _) = group.iter().find(|(_, span)| span.contains(col))?;
                ip.get_hover(col, keywords)
            }
            NetworkAddress::NegIP(ip) => {
                let (ip, _) = ip.as_ref();
                ip.get_hover(col, keywords)
            }
            NetworkAddress::IPVariable(_) => None,
        }
    }
}

/// Represents a network port (along with ranges of ports, variables, etc.)
#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub enum NetworkPort {
    Any(Span),
    Port(Spanned<u16>),
    PortGroup(Vec<Spanned<NetworkPort>>),
    PortRange(Spanned<u16>, Spanned<u16>),
    /// Specifies an open range.
    ///
    /// the first variable specifies the port, while the second whether it is
    /// open towards up or down.
    PortOpenRange(Spanned<u16>, bool),
    NegPort(Box<Spanned<NetworkPort>>),
    PortVar(Spanned<String>),
}

impl fmt::Display for NetworkPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkPort::Any(_) => write!(f, "any"),
            NetworkPort::Port((port, _)) => write!(f, "{}", port),
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
            NetworkPort::PortVar((port_name, _)) => {
                write!(f, "${}", port_name)
            }
        }
    }
}
impl NetworkPort {
    /// Find all variables inside the network port struct
    pub fn find_variables(&self, name: &Option<String>) -> Option<Vec<Spanned<String>>> {
        let mut ret: Vec<Spanned<String>> = vec![];
        self.find_variables_with_array(name, &mut ret);
        if ret.len() == 0 {
            return None;
        } else {
            Some(ret)
        }
    }
    /// Same as [find_variables], however all results are pushed to the array.
    fn find_variables_with_array(
        &self,
        name: &Option<String>,
        vector: &mut Vec<Spanned<String>>,
    ) -> () {
        match &self {
            NetworkPort::PortGroup(group) => group.iter().for_each(|(port, _)| {
                port.find_variables_with_array(name, vector);
            }),
            NetworkPort::NegPort(port) => port.0.find_variables_with_array(name, vector),
            NetworkPort::PortVar(var) => {
                match name {
                    Some(name) => {
                        if *name == var.0 {
                            vector.push(var.clone());
                        }
                    }
                    None => {
                        vector.push(var.clone());
                    }
                };
            }
            _ => (),
        }
    }
}
impl Semantics for NetworkPort {
    fn get_semantics(&self, col: &usize, semantic_tokens: &mut Vec<ImCompleteSemanticToken>) {
        match self {
            NetworkPort::Any(span) => {
                semantic_tokens.push(ImCompleteSemanticToken {
                    start: span.start + col,
                    length: span.len(),
                    token_type: LEGEND_TYPE
                        .iter()
                        .position(|item| item == &SemanticTokenType::KEYWORD)
                        .unwrap(),
                });
            }
            NetworkPort::Port((_, span)) => {
                semantic_tokens.push(ImCompleteSemanticToken {
                    start: span.start + col,
                    length: span.len(),
                    token_type: LEGEND_TYPE
                        .iter()
                        .position(|item| item == &SemanticTokenType::NUMBER)
                        .unwrap(),
                });
            }
            NetworkPort::PortGroup(group) => {
                group
                    .iter()
                    .for_each(|(port, _)| port.get_semantics(col, semantic_tokens));
            }
            NetworkPort::PortRange((_, from_span), (_, to_span)) => {
                // Push the from port as a semantic token
                semantic_tokens.push(ImCompleteSemanticToken {
                    start: from_span.start + col,
                    length: from_span.len(),
                    token_type: LEGEND_TYPE
                        .iter()
                        .position(|item| item == &SemanticTokenType::NUMBER)
                        .unwrap(),
                });
                // Push the to port as a semantic token
                semantic_tokens.push(ImCompleteSemanticToken {
                    start: to_span.start + col,
                    length: to_span.len(),
                    token_type: LEGEND_TYPE
                        .iter()
                        .position(|item| item == &SemanticTokenType::NUMBER)
                        .unwrap(),
                });
            }
            NetworkPort::PortOpenRange((_, port_span), _) => {
                semantic_tokens.push(ImCompleteSemanticToken {
                    start: port_span.start + col,
                    length: port_span.len(),
                    token_type: LEGEND_TYPE
                        .iter()
                        .position(|item| item == &SemanticTokenType::NUMBER)
                        .unwrap(),
                });
            }
            NetworkPort::NegPort(port) => {
                let (port, span) = port.as_ref();
                // Put the negation as a semantic token
                semantic_tokens.push(ImCompleteSemanticToken {
                    start: span.start + col,
                    length: 1,
                    token_type: LEGEND_TYPE
                        .iter()
                        .position(|item| item == &SemanticTokenType::OPERATOR)
                        .unwrap(),
                });
                // Put the port as a semantic token
                port.get_semantics(col, semantic_tokens);
            }
            NetworkPort::PortVar((_, span)) => {
                // Put the name of the variable as a semantic token
                semantic_tokens.push(ImCompleteSemanticToken {
                    start: span.start + col,
                    length: span.len(),
                    token_type: LEGEND_TYPE
                        .iter()
                        .position(|item| item == &SemanticTokenType::VARIABLE)
                        .unwrap(),
                });
            }
        }
    }
}
impl Hover for NetworkPort {
    fn get_hover(
        &self,
        col: &usize,
        keywords: &HashMap<String, Keyword>,
    ) -> Option<Spanned<tower_lsp::lsp_types::HoverContents>> {
        match self {
            NetworkPort::Any(_) => None,
            NetworkPort::Port(_) => None,
            NetworkPort::PortGroup(_) => None,
            NetworkPort::PortRange(_, _) => None,
            NetworkPort::PortOpenRange(_, _) => None,
            NetworkPort::NegPort(_) => None,
            NetworkPort::PortVar(_) => None,
        }
    }
}
impl Completions for NetworkPort {
    fn get_completion(
        address_variables: &HashSet<String>,
        port_variables: &HashSet<String>,
        completion_tokens: &mut Vec<CompletionItem>,
    ) {
        // Add all common ports
        let mut all_competions = vec![
            CompletionItem {
                label: String::from("SSH"),
                insert_text: Some(String::from("22")),
                kind: Some(CompletionItemKind::VALUE),
                ..Default::default()
            },
            CompletionItem {
                label: String::from("HTTP"),
                insert_text: Some(String::from("80")),
                kind: Some(CompletionItemKind::VALUE),
                ..Default::default()
            },
            CompletionItem {
                label: String::from("HTTPS"),
                insert_text: Some(String::from("443")),
                kind: Some(CompletionItemKind::VALUE),
                ..Default::default()
            },
            CompletionItem {
                label: String::from("SMB"),
                insert_text: Some(String::from("445")),
                kind: Some(CompletionItemKind::VALUE),
                ..Default::default()
            },
            CompletionItem {
                label: String::from("Telnet"),
                insert_text: Some(String::from("23")),
                kind: Some(CompletionItemKind::VALUE),
                ..Default::default()
            },
        ];
        // Add any as a network port
        all_competions.push(CompletionItem {
            label: String::from("any"),
            kind: Some(CompletionItemKind::CONSTANT),
            ..Default::default()
        });
        // Add all port variables
        completion_tokens.extend(all_competions);
    }
}

/// Represents the networking direction
#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub enum NetworkDirection {
    SrcToDst,
    Both,
    DstToSrc,
    /// represents any unrecognized direction
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

impl Hover for NetworkDirection {
    fn get_hover(
        &self,
        col: &usize,
        keywords: &HashMap<String, Keyword>,
    ) -> Option<Spanned<tower_lsp::lsp_types::HoverContents>> {
        None
    }
}

impl Completions for NetworkDirection {
    fn get_completion(
        address_variables: &HashSet<String>,
        port_variables: &HashSet<String>,
        completion_tokens: &mut Vec<CompletionItem>,
    ) {
        let completions = vec![
            CompletionItem {
                label: String::from("To Src"),
                insert_text: Some(String::from("<-")),
                kind: Some(CompletionItemKind::OPERATOR),
                ..Default::default()
            },
            CompletionItem {
                label: String::from("To Dst"),
                insert_text: Some(String::from("->")),
                kind: Some(CompletionItemKind::OPERATOR),
                ..Default::default()
            },
            CompletionItem {
                label: String::from("Both"),
                insert_text: Some(String::from("<>")),
                kind: Some(CompletionItemKind::OPERATOR),
                ..Default::default()
            },
        ];
        completion_tokens.extend(completions);
    }
}
