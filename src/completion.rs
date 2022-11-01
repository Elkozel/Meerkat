//! Provides the completion logic for the language server
//!
//! The completion logic analyzes which part of the rule is needed to be
//! completed and then provides the nessassary options
use std::collections::{HashMap, HashSet};

use chumsky::primitive::Container;
use ropey::RopeSlice;
use tower_lsp::lsp_types::{CompletionItem, CompletionItemKind};

use crate::rule::{NetworkAddress, NetworkDirection, NetworkPort, Rule, Spanned, AST};

/// A CSV record, obtained from the suricata cli
#[derive(Debug, Clone)]
pub struct KeywordRecord {
    pub name: String,
    pub description: String,
    pub app_layer: String,
    pub features: String,
    pub documentation: String,
}
impl KeywordRecord {
    pub fn to_keyword(record: &KeywordRecord) -> (String, Keyword) {
        if record.features.starts_with("No option") {
            return (record.name.clone(), Keyword::NoOption((*record).clone()));
        }
        return (record.name.clone(), Keyword::Other((*record).clone()));
    }
}

/// An abstraction layer for the [KeywordRecord] struct
#[derive(Debug)]
pub enum Keyword {
    NoOption(KeywordRecord),
    Other(KeywordRecord),
}

/// Fetches the completion options for the signature
pub fn get_completion(
    line: &RopeSlice,
    ast: &AST,
    offset: &usize,
    variables: &(HashSet<String>, HashSet<String>),
    keywords: &HashMap<String, Keyword>,
) -> Vec<CompletionItem> {
    let mut completion_tokens = vec![];
    let mut address_variables = HashSet::new();
    let mut port_variables = HashSet::new();

    // Get all variables
    get_variables_from_ast(ast, &mut address_variables, &mut port_variables);
    // Generate completion tokens
    if line.get_char(offset - 1)? == "$" {
        get_completion_for_address(&address_variables, &mut completion_tokens);
        get_completion_for_port(&port_variables, &mut completion_tokens);
    }
    else {
        get_completion_for_option_keywords(keywords, &mut completion_tokens);
    }
    completion_tokens
}

enum Uncompleted {
    Action,
    Protocol,
    Direction,
    Address,
    Port,
    OptionKeyword,
}

/// Get completion options for Network addresses (IPs, variables, etc.)
pub fn get_completion_for_address(
    variables: &HashSet<String>,
    completion_tokens: &mut Vec<CompletionItem>,
) {
    // // Push regular IPs
    // let regular_ips = vec![
    //     (
    //         "192.168.0.0/16".to_string(),
    //         "RFC 1918 16-bit block".to_string(),
    //     ),
    //     (
    //         "172.16.0.0./12".to_string(),
    //         "RFC 1918 20-bit block".to_string(),
    //     ),
    //     (
    //         "10.0.0.0/8".to_string(),
    //         "RFC 1918 24-bit block".to_string(),
    //     ),
    // ];
    // regular_ips.iter().for_each(|(ip, details)| {
    //     completion_tokens.push(CompletionItem {
    //         label: ip.clone(),
    //         insert_text: Some(ip.clone()),
    //         kind: Some(CompletionItemKind::VARIABLE),
    //         detail: Some(details.clone()),
    //         ..Default::default()
    //     })
    // });
    // Push variables
    variables.iter().for_each(|var| {
        completion_tokens.push(CompletionItem {
            label: var.clone(),
            insert_text: Some(var.clone()),
            kind: Some(CompletionItemKind::VARIABLE),
            detail: Some(var.clone()),
            ..Default::default()
        })
    });
}

/// Get completion for network ports
pub fn get_completion_for_port(
    variables: &HashSet<String>,
    completion_tokens: &mut Vec<CompletionItem>,
) {
    // push variables
    variables.into_iter().for_each(|var| {
        completion_tokens.push(CompletionItem {
            label: var.clone(),
            insert_text: Some(var.clone()),
            kind: Some(CompletionItemKind::VARIABLE),
            detail: Some(var.clone()),
            ..Default::default()
        })
    })
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
            kind: Some(CompletionItemKind::KEYWORD),
            detail: Some(record.description.clone()),
            ..Default::default()
        }),
        Keyword::Other(record) => completion_tokens.push(CompletionItem {
            label: record.name.clone(),
            insert_text: Some(record.name.clone()),
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
