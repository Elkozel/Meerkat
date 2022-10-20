use std::{collections::HashMap, ops::RangeBounds};

use ipnet::IpNet;
use tower_lsp::lsp_types::{HoverContents, MarkupContent};

use crate::{
    completion::Keyword,
    rule::{NetworkAddress, RuleOption, Spanned, AST, Header, Span},
};

pub fn get_hover(ast: &AST, offset: &usize, keywords: &HashMap<String, Keyword>) -> Option<Spanned<HoverContents>>{
    let (rule, _) = ast.rules.iter().find(|(_, span)| span.contains(offset))?;
    // check header
    hover_for_header(&rule.header, offset)
        .or(hover_for_options(&rule.options, offset, keywords))
}

fn hover_for_header(header: &Spanned<Header>, offset: &usize) -> Option<Spanned<HoverContents>> {
    let (header, _) = header;
    
    if header.source.1.contains(offset) {
        hover_for_address(&header.source, offset);
    }
    else if header.destination.1.contains(offset) {
        hover_for_address(&header.destination, offset);
    }
    None
}

fn hover_for_address(address: &Spanned<NetworkAddress>, offset: &usize) -> Option<Spanned<HoverContents>> {
    let (address, span) = address;
    match address {
        NetworkAddress::Any => None,
        NetworkAddress::IPAddr(_) => None,
        NetworkAddress::CIDR((ip, _), (mask, _)) => {
            let range = IpNet::new(ip.clone(), mask.clone());
            match range {
                Ok(range) => Some((HoverContents::Markup(MarkupContent {
                    kind: tower_lsp::lsp_types::MarkupKind::Markdown,
                    value: format!("**{}** - **{}**", range.network(), range.broadcast()),
                }), span.clone())),
                Err(_) => None,
            }
        }
        NetworkAddress::IPGroup(group) => {
            let ip = group.iter().find(|(_, span)| span.contains(offset))?;
            hover_for_address(ip, offset)
        }
        NetworkAddress::NegIP(ip) => hover_for_address(ip.as_ref(), offset),
        NetworkAddress::IPVariable(_) => None,
    }
}

fn hover_for_options(
    options: &Vec<Spanned<RuleOption>>,
    offset: &usize,
    keywords: &HashMap<String, Keyword>,
) -> Option<Spanned<HoverContents>> {
    let (option, _) = options
        .iter()
        .find(|(_, option_span)| option_span.contains(offset))?;
    match option {
        RuleOption::KeywordPair((keyword, span), _) if span.contains(offset) => {
            get_contents_for_keyword(&keyword, keywords, span)
        }
        RuleOption::Buffer((keyword, span)) => get_contents_for_keyword(&keyword, keywords, span),
        _ => None,
    }
}

fn get_contents_for_keyword(
    keyword: &String,
    keywords: &HashMap<String, Keyword>,
    span: &Span
) -> Option<Spanned<HoverContents>> {
    let record = keywords.get(keyword)?;
    // Remove wrapper around keyword record
    let keyword = match record {
        Keyword::NoOption(keyword) => keyword,
        Keyword::Other(keyword) => keyword,
    };
    Some((HoverContents::Markup(MarkupContent {
        kind: tower_lsp::lsp_types::MarkupKind::Markdown,
        value: [
            format!("#{}", keyword.name),
            "## Description".to_string(),
            keyword.description.clone(),
            "## Documentation".to_string(),
            keyword.documentation.clone(),
        ]
        .join("\n"),
    }), span.clone()))
}
