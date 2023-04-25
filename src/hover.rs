//! Provides the hover logic for the language server
//!
//! The hover logic provides additional information:
//! - IP start and end on IP ranges
//! - Description and Documentation for keywords
use std::collections::HashMap;


use ipnet::IpNet;
use crate::rule::Hover;
use tower_lsp::lsp_types::{HoverContents, MarkupContent};

use crate::{
    rule::{Span, Spanned, AST, header::NetworkAddress, options::RuleOption},
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
    rule.get_hover(col, keywords)
}