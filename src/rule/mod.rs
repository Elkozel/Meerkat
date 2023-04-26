//! Rule structs
//!
//! This module houses all the structures and basic functionallity for every rule
//! The structure follows the structure explained in the [suricata docs]
//! ```
//! A rule/signature consists of the following:
//! - The action, that determines what happens when the signature matches
//! - The header, defining the protocol, IP addresses, ports and direction of the rule.
//! - The rule options, defining the specifics of the rule.
//! ```
//!
//! Furthermore, additionnal types are introduced to track the span of every part of the signatures
//!
//! [suricata docs]: https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html
use std::{
    collections::{HashMap, HashSet},
    fmt,
};

use tower_lsp::lsp_types::{CompletionItem, HoverContents, SemanticTokenType};

use crate::{
    semantic_token::{ImCompleteSemanticToken, LEGEND_TYPE},
    suricata::Keyword,
};

use self::{
    action::Action,
    header::{Header, NetworkAddress, NetworkPort, NetworkDirection},
    options::RuleOption,
};
pub mod action;
pub mod header;
pub mod options;

/// Keeps data about the range in the signatures of the object (start/end char position)
pub type Span = std::ops::Range<usize>;
/// Shows that a signatures part has a char range
pub type Spanned<T> = (T, Span);
/// Trait that shows a part of a rule can provide schemantics
pub trait Semantics {
    fn get_semantics(&self, col: &usize, semantic_tokens: &mut Vec<ImCompleteSemanticToken>);
}
/// Trait that shows a part of a rule can provide hover support
pub trait Hover {
    fn get_hover(
        &self,
        col: &usize,
        keywords: &HashMap<String, Keyword>,
    ) -> Option<Spanned<HoverContents>>;
}
/// Trait, that shows a part of a rule can provide competion items
pub trait Completions {
    fn get_completion(address_variables: &HashSet<String>, port_variables: &HashSet<String>, completion_tokens: &mut Vec<CompletionItem>);
}

/// Represents a given rulefile with a set of signatures, howver it does not have a tree structure.
///
/// As every file has a number of signatures and there could be only one signature by line, it is
/// only logical that the storage structure also is represented in the same way.
#[derive(Debug, PartialEq, Eq)]
pub struct AST {
    pub rules: HashMap<u32, (Rule, Span)>,
}

/// Represents a single signature(or rule)
#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub struct Rule {
    pub action: Option<Spanned<Action>>,
    pub header: Spanned<Header>,
    pub options: Option<Vec<Spanned<RuleOption>>>,
}

/// Print formatted rule
impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some((action, _)) = &self.action {
            write!(f, "{} ", action)?
        }
        write!(f, "{}", &self.header.0)?;
        if let Some(option) = &self.options {
            // If the array is empty, skip this step
            if option.is_empty() {
                return write!(f, "()");
            }

            let options = option
                .iter()
                .map(|(option, _)| option.to_string())
                .collect::<Vec<String>>();
            write!(f, "({};)", options.join("; "))
        } else {
            write!(f, "")
        }
    }
}
impl Rule {
    pub fn protocol(&self) -> &Option<Spanned<String>> {
        let (header, _) = &self.header;
        &header.protocol

    }
    /// Get the source network address from the header
    pub fn source(&self) -> &Option<Spanned<NetworkAddress>> {
        let (header, _) = &self.header;
        &header.source
    }
    /// Get the source network port from the header
    pub fn source_port(&self) -> &Option<Spanned<NetworkPort>> {
        let (header, _) = &self.header;
        &header.source_port
    }
    /// Get the direction from the header
    pub fn direction(&self) -> &Option<Spanned<NetworkDirection>> {
        let (header, _) = &self.header;
        &header.direction
    }
    /// Get the destination network address from the header
    pub fn destination(&self) -> &Option<Spanned<NetworkAddress>> {
        let (header, _) = &self.header;
        &header.destination
    }
    /// Get the destination network port from the header
    pub fn destination_port(&self) -> &Option<Spanned<NetworkPort>> {
        let (header, _) = &self.header;
        &header.destination_port
    }
    /// Get all network address from the header
    pub fn addresses(&self) -> Vec<&Spanned<NetworkAddress>> {
        self.source()
            .iter()
            .chain(self.destination().iter())
            .collect()
    }
    /// Get all network ports from the header
    pub fn ports(&self) -> Vec<&Spanned<NetworkPort>> {
        self.source_port()
            .iter()
            .chain(self.destination_port().iter())
            .collect()
    }
}

impl Semantics for Rule {
    fn get_semantics(&self, col: &usize, semantic_tokens: &mut Vec<ImCompleteSemanticToken>) {
        // Push the action token
        if let Some((_, span)) = &self.action {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: span.start + col,
                length: span.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::FUNCTION)
                    .unwrap(),
            });
        }
        // Push the header tokens
        self.header.0.get_semantics(col, semantic_tokens);
        // Push the tokens from the options
        if let Some(options) = &self.options {
            options.iter().for_each(|(option, _)| {
                option.get_semantics(col, semantic_tokens);
            });
        }
    }
}

impl Hover for Rule {
    fn get_hover(
        &self,
        col: &usize,
        keywords: &HashMap<String, Keyword>,
    ) -> Option<Spanned<HoverContents>> {
        // Check if hover is in the action
        let hover_action = || {
            if let Some((_, _)) = &self.action {
                None
            } else {
                None
            }
        };

        // Check if hover is in the header
        let (header, header_span) = &self.header;
        if header_span.contains(col) {
            return header.get_hover(col, keywords);
        };

        // Check if the hover is in the options
        let hover_options = || {
            if let Some(options) = &self.options {
                options
                    .iter()
                    .find(|(_, option_span)| option_span.contains(col))
                    .and_then(|(option, _)| option.get_hover(col, keywords))
            } else {
                None
            }
        };

        hover_options().or(hover_action())
    }
}
