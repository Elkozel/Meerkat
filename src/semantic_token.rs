use std::ops::Range;

use crate::rule::{NetworkAddress, NetworkPort, RuleOption, Rule, Spanned};
use tower_lsp::lsp_types::SemanticTokenType;

#[derive(Debug)]
pub struct ImCompleteSemanticToken {
    pub start: usize,
    pub length: usize,
    pub token_type: usize,
}

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

pub fn semantic_token_from_rule(
    rule: &Spanned<Rule>,
    offset: &usize,
    mut semantic_tokens: &mut Vec<ImCompleteSemanticToken>,
) {
    let (rule, _) = rule;
    // Push the action token
    let action = &rule.action;
    semantic_tokens.push(ImCompleteSemanticToken {
        start: action.1.start + offset,
        length: action.1.len(),
        token_type: LEGEND_TYPE
            .iter()
            .position(|item| item == &SemanticTokenType::FUNCTION)
            .unwrap(),
    });

    // Push the header tokens
    let header = &rule.header.0;
    // handle network addresses
    semantic_token_from_address(&header.source, offset, &mut semantic_tokens);
    semantic_token_from_address(&header.destination, offset, &mut semantic_tokens);

    // handle network ports
    semantic_token_from_port(&header.source_port, offset, &mut semantic_tokens);
    semantic_token_from_port(&header.destination_port, offset, &mut semantic_tokens);

    // Push the options tokens
    let options = &rule.options;
    options
        .iter()
        .for_each(|option| semantic_token_from_options(option, offset, &mut semantic_tokens));
}

pub fn semantic_token_from_address(
    expr: &(NetworkAddress, Range<usize>),
    offset: &usize,
    semantic_tokens: &mut Vec<ImCompleteSemanticToken>,
) {
    let address = &expr.0;
    let span = &expr.1;
    match address {
        NetworkAddress::Any => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: span.start + offset,
                length: span.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::STRUCT)
                    .unwrap(),
            });
        }
        NetworkAddress::IPAddr((_, ip_span)) => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: ip_span.start + offset,
                length: ip_span.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::KEYWORD)
                    .unwrap(),
            });
        }
        NetworkAddress::CIDR((_, ip_span), (_, mask_span)) => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: ip_span.start + offset,
                length: ip_span.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::KEYWORD)
                    .unwrap(),
            });
            semantic_tokens.push(ImCompleteSemanticToken {
                start: mask_span.start + offset,
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
                    start: span.start + offset,
                    length: span.len(),
                    token_type: LEGEND_TYPE
                        .iter()
                        .position(|item| item == &SemanticTokenType::KEYWORD)
                        .unwrap(),
                })
            });
        }
        NetworkAddress::NegIP(ip) => {
            semantic_token_from_address(ip.as_ref(), offset, semantic_tokens);
            // semantic_token_from_address(ip.as_ref(), semantic_tokens);
        }
        NetworkAddress::IPVariable((_, variable_span)) => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: variable_span.start + offset,
                length: variable_span.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::VARIABLE)
                    .unwrap(),
            });
        }
    }
}

pub fn semantic_token_from_port(
    expr: &(NetworkPort, Range<usize>),
    offset: &usize,
    mut semantic_tokens: &mut Vec<ImCompleteSemanticToken>,
) {
    let port = &expr.0;
    let span = &expr.1;
    match port {
        NetworkPort::Any => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: span.start + offset,
                length: span.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::STRUCT)
                    .unwrap(),
            });
        }
        NetworkPort::Port(_) => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: span.start + offset,
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
                .for_each(|port| semantic_token_from_port(port, offset, &mut semantic_tokens));
        }
        NetworkPort::PortRange((_, from_span), (_, to_span)) => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: from_span.start + offset,
                length: from_span.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::NUMBER)
                    .unwrap(),
            });
            semantic_tokens.push(ImCompleteSemanticToken {
                start: to_span.start + offset,
                length: to_span.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::NUMBER)
                    .unwrap(),
            });
        }
        NetworkPort::PortOpenRange((_, port_span), _) => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: port_span.start + offset,
                length: port_span.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::NUMBER)
                    .unwrap(),
            });
        }
        NetworkPort::NegPort(port) => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: port.as_ref().1.start + offset,
                length: port.as_ref().1.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::NUMBER)
                    .unwrap(),
            });
        }
        NetworkPort::PortVar((_, variable_span)) => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: variable_span.start + offset,
                length: variable_span.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::VARIABLE)
                    .unwrap(),
            });            
        }
    }
}

pub fn semantic_token_from_options(
    expr: &(RuleOption, Range<usize>),
    offset: &usize,
    semantic_tokens: &mut Vec<ImCompleteSemanticToken>,
) {
    let option = &expr.0;
    match option {
        RuleOption::KeywordPair((_, keyspan), values) => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: keyspan.start + offset,
                length: keyspan.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::KEYWORD)
                    .unwrap(),
            });
            values.iter().for_each(|(value, valspan)| match value {
                crate::rule::OptionsVariable::String(_) => {
                    semantic_tokens.push(ImCompleteSemanticToken {
                        start: valspan.start + offset,
                        length: valspan.len(),
                        token_type: LEGEND_TYPE
                            .iter()
                            .position(|item| item == &SemanticTokenType::STRING)
                            .unwrap(),
                    });
                }
                crate::rule::OptionsVariable::Other(_) => {
                    semantic_tokens.push(ImCompleteSemanticToken {
                        start: valspan.start + offset,
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
                start: span.start + offset,
                length: span.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::KEYWORD)
                    .unwrap(),
            });
        }
    }
}
