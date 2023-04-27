//! Provides the completion logic for the language server
//!
//! The completion logic analyzes which part of the rule is needed to be
//! completed and then provides the nessassary options
use std::collections::{HashMap, HashSet};

use ropey::RopeSlice;
use tower_lsp::lsp_types::{CompletionItem, CompletionItemKind};

use crate::{
    rule::{
        header::{NetworkAddress, NetworkPort},
        Completions, Rule, AST,
    },
    suricata::Keyword,
};

/// Fetches the completion options for the signature
pub fn get_completion(
    ast: &AST,
    line_text: &RopeSlice,
    _line: usize,
    col: usize,
    _address_variables: &HashSet<String>,
    _port_variables: &HashSet<String>,
    keywords: &HashMap<String, Keyword>,
) -> Option<Vec<CompletionItem>> {
    let mut completion_tokens = vec![];
    let mut address_variables = HashSet::new();
    let mut port_variables = HashSet::new();

    // Get all variables
    get_variables_from_ast(ast, &mut address_variables, &mut port_variables);
    // match get_next_uncompleted(rule) {
    //     Uncompleted::Action => {
    //         Action::get_completion(&address_variables, &port_variables, &mut completion_tokens)
    //     }
    //     Uncompleted::Protocol => {}
    //     Uncompleted::Direction => NetworkDirection::get_completion(
    //         &address_variables,
    //         &port_variables,
    //         &mut completion_tokens,
    //     ),
    //     Uncompleted::Address => NetworkAddress::get_completion(
    //         &address_variables,
    //         &port_variables,
    //         &mut completion_tokens,
    //     ),
    //     Uncompleted::Port => {
    //         NetworkPort::get_completion(&address_variables, &port_variables, &mut completion_tokens)
    //     }
    //     Uncompleted::OptionKeyword => {
    //         get_completion_for_option_keywords(keywords, &mut completion_tokens)
    //     }
    //     Uncompleted::Other => {}
    // }
    // Generate completion tokens (old way)
    if line_text.get_char(col - 1)? == '$' {
        NetworkAddress::get_completion(&address_variables, &port_variables, &mut completion_tokens);
        NetworkPort::get_completion(&address_variables, &port_variables, &mut completion_tokens);
    } else if line_text.get_char(col - 2)? == ';' || line_text.get_char(col - 1)? == '(' {
        get_completion_for_option_keywords(keywords, &mut completion_tokens);
    } else {
    }
    Some(completion_tokens)
}

fn get_next_uncompleted(rule: &Rule) -> Uncompleted {
    // Check each part of the rule, if it is none, return it as needing completion
    if rule.action.is_none() {
        Uncompleted::Action
    } else if rule.protocol().is_none() {
        Uncompleted::Protocol
    } else if rule.source().is_none() {
        Uncompleted::Address
    } else if rule.source_port().is_none() {
        Uncompleted::Port
    } else if rule.direction().is_none() {
        Uncompleted::Direction
    } else if rule.destination().is_none() {
        Uncompleted::Address
    } else if rule.destination_port().is_none() {
        Uncompleted::Port
    } else if rule.options.is_none() {
        Uncompleted::OptionKeyword
    } else {
        Uncompleted::Other
    }
}

enum Uncompleted {
    Action,
    Protocol,
    Direction,
    Address,
    Port,
    OptionKeyword,
    Other,
}

/// Get completion for the options inside the signature
///
/// Currently, onlt completion of the keywords is provided, however this
/// functionallity could be extended for specific values per keyword
pub fn get_completion_for_option_keywords(
    keywords: &HashMap<String, Keyword>,
    completion_tokens: &mut Vec<CompletionItem>,
) {
    keywords.iter().for_each(|(_, keyword)| match keyword {
        Keyword::NoOption(record) => completion_tokens.push(CompletionItem {
            label: record.name.clone(),
            insert_text: Some(format!("{}; ", record.name)),
            kind: Some(CompletionItemKind::CONSTANT),
            detail: Some(record.description.clone()),
            ..Default::default()
        }),
        Keyword::Other(record) => completion_tokens.push(CompletionItem {
            label: record.name.clone(),
            insert_text: Some(format!("{}: ", record.name.clone())),
            kind: Some(CompletionItemKind::KEYWORD),
            detail: Some(record.description.clone()),
            ..Default::default()
        }),
    })
}

/// generic function to fetch the port of a certain protocol.
fn get_port_by_protocol(protocol: String) -> Vec<u16> {
    match protocol.as_str() {
        "HTTP" => vec![80, 443],
        "HTTP/2" => vec![80, 443],
        "SSL" => vec![443],
        "TLS" => vec![443],
        "SMB" => vec![139, 445],
        "DCERPC" => vec![135],
        "SMTP" => vec![25],
        "FTP" => vec![21],
        "SSH" => vec![22],
        "DNS" => vec![53],
        "Modbus" => vec![502],
        "NFS" => vec![111],
        "NTP" => vec![123],
        "DHCP" => vec![67],
        "TFTP" => vec![69],
        "KRB5" => vec![88],
        "SIP" => vec![5060, 5061],
        "SNMP" => vec![161, 162],
        "RDP" => vec![3389],
        _ => vec![],
    }
}

pub fn get_variables_from_ast(
    ast: &AST,
    address_variables: &mut HashSet<String>,
    port_variables: &mut HashSet<String>,
) {
    ast.rules.iter().for_each(|(_, (rule, _))| {
        // find all address variables
        rule.addresses().into_iter().for_each(|(address, _)| {
            search_for_address_variables(address, address_variables);
        });

        // find all port variables
        rule.ports().into_iter().for_each(|(port, _)| {
            search_for_port_variables(port, port_variables);
        })
    });
}

fn search_for_port_variables(port: &NetworkPort, port_variables: &mut HashSet<String>) {
    match port {
        NetworkPort::PortGroup(group) => group.into_iter().for_each(|port| {
            search_for_port_variables(&port.0, port_variables);
        }),
        NetworkPort::NegPort(port) => search_for_port_variables(&port.as_ref().0, port_variables),
        NetworkPort::PortVar((var_name, _)) => {
            port_variables.insert(var_name.clone());
        }
        _ => (),
    };
}

fn search_for_address_variables(address: &NetworkAddress, address_variables: &mut HashSet<String>) {
    match address {
        NetworkAddress::IPGroup(group) => group.into_iter().for_each(|address| {
            search_for_address_variables(&address.0, address_variables);
        }),
        NetworkAddress::NegIP(ip) => {
            search_for_address_variables(&ip.as_ref().0, address_variables)
        }
        NetworkAddress::IPVariable((var_name, _)) => {
            address_variables.insert(var_name.clone());
        }
        _ => (),
    }
}
