//! Provides the semantic tokenization logic for the language server
//! 
//! Semantic tokens are used for syntax highlighting.
//! For more information you can take a look at the [VSCode API docs] or the [Semantic Highlighting Overview].
//! 
//! For how semantic tokens work, please take a look at the explanation for the [ImCompleteSemanticToken] struct
//! 
//! [VSCode API docs]: https://code.visualstudio.com/api/language-extensions/semantic-highlight-guide
//! [Semantic Highlighting Overview]: https://github.com/microsoft/vscode/wiki/Semantic-Highlighting-Overview
use std::ops::Range;

use crate::rule::{NetworkAddress, NetworkPort, RuleOption, Rule, Spanned};
use tower_lsp::lsp_types::SemanticTokenType;

/// A struct which stores only the most important information about the token
/// 
/// It also provides an abstraction for the way tokens are transported, as the 
/// position of each token is given in reference to the previous one (relative
/// positioning). This is explained in depth in the following [GitHub issue]
/// 
/// [GitHub issue]: https://github.com/microsoft/vscode/issues/86415#issuecomment-587327402
#[derive(Debug)]
pub struct ImCompleteSemanticToken {
    pub start: usize,
    pub length: usize,
    pub token_type: usize,
}
/// Define the tokens, which are going to be used
pub const LEGEND_TYPE: &[SemanticTokenType] = &[
    SemanticTokenType::STRING,
    SemanticTokenType::COMMENT,
    SemanticTokenType::FUNCTION, // for action
    SemanticTokenType::VARIABLE, // for IP
    SemanticTokenType::NUMBER,   // for port
    SemanticTokenType::KEYWORD,  // for keywords
    SemanticTokenType::OPERATOR, // for direction
    SemanticTokenType::PROPERTY, // for option values
    SemanticTokenType::STRUCT,   // for IP variables
];

/// Generate semantic tokens from a rule
pub fn semantic_token_from_rule(
    rule: &Spanned<Rule>,
    col: &usize,
    mut semantic_tokens: &mut Vec<ImCompleteSemanticToken>,
) {
    let (rule, _) = rule;
    // Push the action token
    for (_, span) in rule.action.iter() {
        semantic_tokens.push(ImCompleteSemanticToken {
            start: span.start + col,
            length: span.len(),
            token_type: LEGEND_TYPE
                .iter()
                .position(|item| item == &SemanticTokenType::FUNCTION)
                .unwrap(),
        });

    }
    
    // handle network addresses
    for address in rule.addresses() {
        semantic_token_from_address(address, col, semantic_tokens);
    }

    // handle network ports
    for port in rule.ports() {
        semantic_token_from_port(port, col, &mut semantic_tokens);
    }

    // Push the options tokens
    for options in rule.options.iter() {
        options.iter().for_each(|option| {
            semantic_token_from_options(option, col, &mut semantic_tokens)
        });
    }
}

/// Generate semantic tokens from a network address
pub fn semantic_token_from_address(
    expr: &(NetworkAddress, Range<usize>),
    col: &usize,
    semantic_tokens: &mut Vec<ImCompleteSemanticToken>,
) {
    let address = &expr.0;
    let span = &expr.1;
    match address {
        NetworkAddress::Any => {
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
        NetworkAddress::NegIP(ip) => {
            semantic_token_from_address(ip.as_ref(), col, semantic_tokens);
            // semantic_token_from_address(ip.as_ref(), semantic_tokens);
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

/// Generate semantic tokens from a network port
pub fn semantic_token_from_port(
    expr: &(NetworkPort, Range<usize>),
    col: &usize,
    mut semantic_tokens: &mut Vec<ImCompleteSemanticToken>,
) {
    let port = &expr.0;
    let span = &expr.1;
    match port {
        NetworkPort::Any => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: span.start + col,
                length: span.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::STRUCT)
                    .unwrap(),
            });
        }
        NetworkPort::Port(_) => {
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
                .for_each(|port| semantic_token_from_port(port, col, &mut semantic_tokens));
        }
        NetworkPort::PortRange((_, from_span), (_, to_span)) => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: from_span.start + col,
                length: from_span.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::NUMBER)
                    .unwrap(),
            });
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
            semantic_tokens.push(ImCompleteSemanticToken {
                start: port.as_ref().1.start + col,
                length: port.as_ref().1.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::NUMBER)
                    .unwrap(),
            });
        }
        NetworkPort::PortVar((_, variable_span)) => {
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

/// Generate semantic tokens from a signature options
pub fn semantic_token_from_options(
    expr: &(RuleOption, Range<usize>),
    col: &usize,
    semantic_tokens: &mut Vec<ImCompleteSemanticToken>,
) {
    let option = &expr.0;
    match option {
        RuleOption::KeywordPair((_, keyspan), values) => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: keyspan.start + col,
                length: keyspan.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::KEYWORD)
                    .unwrap(),
            });
            values.iter().for_each(|(value, valspan)| match value {
                crate::rule::OptionsVariable::String(_) => {
                    semantic_tokens.push(ImCompleteSemanticToken {
                        start: valspan.start + col,
                        length: valspan.len(),
                        token_type: LEGEND_TYPE
                            .iter()
                            .position(|item| item == &SemanticTokenType::STRING)
                            .unwrap(),
                    });
                }
                crate::rule::OptionsVariable::Other(_) => {
                    semantic_tokens.push(ImCompleteSemanticToken {
                        start: valspan.start + col,
                        length: valspan.len(),
                        token_type: LEGEND_TYPE
                            .iter()
                            .position(|item| item == &SemanticTokenType::PROPERTY)
                            .unwrap(),
                    });
                }
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
