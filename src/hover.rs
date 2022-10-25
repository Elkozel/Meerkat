//! Provides the hover logic for the language server
//! 
//! The hover logic provides additional information:
//! - IP start and end on IP ranges
//! - Description and Documentation for keywords
use std::collections::HashMap;

use ipnet::IpNet;
use tower_lsp::lsp_types::{HoverContents, MarkupContent};

use crate::{
    completion::Keyword,
    rule::{Header, NetworkAddress, RuleOption, Span, Spanned, AST},
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
    hover_for_header(&rule.header, col).or(hover_for_options(&rule.options, col, keywords))
}

/// Provides a hover information for a header
fn hover_for_header(header: &Spanned<Header>, col: &usize) -> Option<Spanned<HoverContents>> {
    let (header, _) = header;

    if header.source.1.contains(col) {
        hover_for_address(&header.source, col);
    } else if header.destination.1.contains(col) {
        hover_for_address(&header.destination, col);
    }
    None
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
                        value: format!("**{}** - **{}**", range.network(), range.broadcast()),
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
    options: &Vec<Spanned<RuleOption>>,
    col: &usize,
    keywords: &HashMap<String, Keyword>,
) -> Option<Spanned<HoverContents>> {
    let (option, _) = options
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
                format!("#{}", keyword.name),
                "## Description".to_string(),
                keyword.description.clone(),
                "## Documentation".to_string(),
                keyword.documentation.clone(),
            ]
            .join("\n"),
        }),
        span.clone(),
    ))
}
