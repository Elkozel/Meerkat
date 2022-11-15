//! Provides the hover logic for the language server
//!
//! The hover logic provides additional information:
//! - IP start and end on IP ranges
//! - Description and Documentation for keywords
use std::collections::HashMap;

use ipnet::IpNet;
use tower_lsp::lsp_types::{HoverContents, MarkupContent};

use crate::{
    rule::{Header, NetworkAddress, RuleOption, Span, Spanned, AST},
    suricata::Keyword,
};

/// Provides hover information
pub fn get_hover(
    ast: &AST,
    line: &u32,
    col: &usize,
    keywords: &HashMap<String, Keyword>,
) -> Option<Spanned<HoverContents>> {
    let (rule, _) = ast.rules.get(line)?;
    // check header
    let header_check = rule
        .addresses()
        .into_iter()
        .find(|(_, span)| span.contains(col))
        .map(|address| hover_for_address(address, col));

    //else check options
    hover_for_options(&rule.options, col, keywords).or(header_check?)
}

/// Provides hover information about a network address.
/// See [rule]
fn hover_for_address(
    address: &Spanned<NetworkAddress>,
    col: &usize,
) -> Option<Spanned<HoverContents>> {
    let (address, span) = address;
    match address {
        NetworkAddress::Any => None,
        NetworkAddress::IPAddr(_) => None,
        NetworkAddress::CIDR((ip, _), (mask, _)) => {
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
                    span.clone(),
                )),
                Err(_) => None,
            }
        }
        NetworkAddress::IPGroup(group) => {
            let ip = group.iter().find(|(_, span)| span.contains(col))?;
            hover_for_address(ip, col)
        }
        NetworkAddress::NegIP(ip) => hover_for_address(ip.as_ref(), col),
        NetworkAddress::IPVariable(_) => None,
    }
}

/// Provides hover information for options of the rule
fn hover_for_options(
    options: &Option<Vec<Spanned<RuleOption>>>,
    col: &usize,
    keywords: &HashMap<String, Keyword>,
) -> Option<Spanned<HoverContents>> {
    let binding = options.to_owned()?;
    let (option, _) = binding
        .iter()
        .find(|(_, option_span)| option_span.contains(col))?;
    match option {
        RuleOption::KeywordPair((keyword, span), _) if span.contains(col) => {
            get_contents_for_keyword(&keyword, keywords, span)
        }
        RuleOption::Buffer((keyword, span)) => get_contents_for_keyword(&keyword, keywords, span),
        _ => None,
    }
}

/// Fetches the hover information for a certain keyword
fn get_contents_for_keyword(
    keyword: &String,
    keywords: &HashMap<String, Keyword>,
    span: &Span,
) -> Option<Spanned<HoverContents>> {
    let record = keywords.get(keyword)?;
    // Remove wrapper around keyword record
    let keyword = match record {
        Keyword::NoOption(keyword) => keyword,
        Keyword::Other(keyword) => keyword,
    };
    Some((
        HoverContents::Markup(MarkupContent {
            kind: tower_lsp::lsp_types::MarkupKind::Markdown,
            value: [
                format!("**{}**", keyword.name),
                format!("{}", keyword.description.clone()),
                format!("*Documentation: {}*", keyword.documentation.clone()),
            ]
            .join("\n\n"),
        }),
        span.clone(),
    ))
}
