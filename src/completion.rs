use std::collections::HashMap;

use ropey::RopeSlice;
use tower_lsp::lsp_types::{CompletionItem, CompletionItemKind};

use crate::rule::AST;

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

#[derive(Debug)]
pub enum Keyword {
    NoOption(KeywordRecord),
    Other(KeywordRecord),
}

pub fn get_completion(line: &RopeSlice, ast: &AST, offset: &usize, variables: &Vec<String>, keywords: &HashMap<String, Keyword>) -> Vec<CompletionItem> {
    let mut completion_tokens = vec![];
    // Get all variables (used in the document + specified externally)
    let mut all_variables = search_for_variables(ast);
    // all_variables.extend(variables);
    // for options we check if the offset is between the brackets
    get_completion_for_address(variables, &mut completion_tokens);
    completion_tokens
}

pub fn get_completion_for_address(
    variables: &Vec<String>,
    completion_tokens: &mut Vec<CompletionItem>,
) {
    // Push regular IPs
    let regular_ips = vec![
        (
            "192.168.0.0/16".to_string(),
            "RFC 1918 16-bit block".to_string(),
        ),
        (
            "172.16.0.0./12".to_string(),
            "RFC 1918 20-bit block".to_string(),
        ),
        (
            "10.0.0.0/8".to_string(),
            "RFC 1918 24-bit block".to_string(),
        ),
    ];
    regular_ips.iter().for_each(|(ip, details)| {
        completion_tokens.push(CompletionItem {
            label: ip.clone(),
            insert_text: Some(ip.clone()),
            kind: Some(CompletionItemKind::VARIABLE),
            detail: Some(details.clone()),
            ..Default::default()
        })
    });
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

fn search_for_variables(ast: &AST) -> Vec<String> {
    let mut ret = vec![];
    ast.rules.iter().for_each(|(rule, _)| {
        let (source, _) = &rule.header.0.source;
        match source {
            crate::rule::NetworkAddress::IPVariable((var_name, _)) => ret.push(var_name.clone()),
            _ => ()
        }
        let (destination, _) = &rule.header.0.destination;
        match destination {
            crate::rule::NetworkAddress::IPVariable((var_name, _)) => ret.push(var_name.clone()),
            _ => ()
        }
    });
    ret
}
