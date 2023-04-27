use std::collections::HashMap;
use std::fmt;
use tower_lsp::lsp_types::HoverContents;
use tower_lsp::lsp_types::MarkupContent;
use tower_lsp::lsp_types::SemanticTokenType;

use crate::rule::Span;
use crate::rule::Spanned;
use crate::semantic_token::ImCompleteSemanticToken;
use crate::semantic_token::LEGEND_TYPE;
use crate::suricata::Keyword;

use super::Hover;
use super::Semantics;

/// Represents a variable inside the options of a signature
///
/// This is not based on the suricata docs, but based of regular observations
/// The current enum has only two possibilities:
/// - a string, in the format "..."
/// - anything else
///
/// This destinction was made since inside a string the special chars are escaped
/// For more info, please see the [surcata docs].
///
/// [surcata docs]: https://suricata.readthedocs.io/en/suricata-6.0.0/rules/meta.html?highlight=escaped#msg-message
#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub enum OptionsVariable {
    String(Spanned<String>),
    Other(Spanned<String>),
}

impl fmt::Display for OptionsVariable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OptionsVariable::String((string, _)) => write!(
                f,
                "\"{}\"",
                string
                    .replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace(";", "\\;")
            ),
            OptionsVariable::Other((string, _)) => write!(f, "{}", string),
        }
    }
}

impl Semantics for OptionsVariable {
    fn get_semantics(&self, col: &usize, semantic_tokens: &mut Vec<ImCompleteSemanticToken>) {
        match self {
            OptionsVariable::String((_, span)) => {
                semantic_tokens.push(ImCompleteSemanticToken {
                    start: span.start + col,
                    length: span.len(),
                    token_type: LEGEND_TYPE
                        .iter()
                        .position(|item| item == &SemanticTokenType::STRING)
                        .unwrap(),
                });
            }
            OptionsVariable::Other((_, span)) => {
                semantic_tokens.push(ImCompleteSemanticToken {
                    start: span.start + col,
                    length: span.len(),
                    token_type: LEGEND_TYPE
                        .iter()
                        .position(|item| item == &SemanticTokenType::PROPERTY)
                        .unwrap(),
                });
            }
        }
    }
}

/// Represents a single option inside the signature (buffer or key-value pair)
#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub enum RuleOption {
    KeywordPair(Spanned<String>, Vec<Spanned<OptionsVariable>>),
    Buffer(Spanned<String>),
}

impl fmt::Display for RuleOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleOption::KeywordPair((key, _), op) => {
                let options = op
                    .iter()
                    .map(|(option, _)| option.to_string())
                    .collect::<Vec<String>>();
                write!(f, "{}: {}", key, options.join(", "))
            }
            RuleOption::Buffer((keyword, _)) => write!(f, "{}", keyword.to_string()),
        }
    }
}

impl Semantics for RuleOption {
    fn get_semantics(&self, col: &usize, semantic_tokens: &mut Vec<ImCompleteSemanticToken>) {
        match &self {
            RuleOption::KeywordPair((_, span), values) => {
                // Add the keyword semantic token
                semantic_tokens.push(ImCompleteSemanticToken {
                    start: span.start + col,
                    length: span.len(),
                    token_type: LEGEND_TYPE
                        .iter()
                        .position(|item| item == &SemanticTokenType::KEYWORD)
                        .unwrap(),
                });
                // Add the value semantic token
                values.iter().for_each(|(options, _)| {
                    options.get_semantics(col, semantic_tokens);
                });
            }
            RuleOption::Buffer((_, span)) => {
                semantic_tokens.push(ImCompleteSemanticToken {
                    start: span.start + col,
                    length: span.len(),
                    token_type: LEGEND_TYPE
                        .iter()
                        .position(|item| item == &SemanticTokenType::KEYWORD)
                        .unwrap(),
                });
            }
        }
    }
}

impl Hover for RuleOption {
    fn get_hover(&self, col: &usize, keywords: &HashMap<String, Keyword>) -> Option<Spanned<HoverContents>> {
        match self {
            RuleOption::KeywordPair((keyword, span), _) if span.contains(col) => {
                get_contents_for_keyword(keyword, keywords, span)
            },
            RuleOption::Buffer((keyword, span)) if span.contains(col) => {
                get_contents_for_keyword(keyword, keywords, span)
            },
            _ => None
        }
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