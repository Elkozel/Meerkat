use std::ops::Range;

use crate::parser::ImCompleteSemanticToken;
use crate::rule::{NetworkAddress, NetworkPort, RuleOption, AST};
use tower_lsp::lsp_types::SemanticTokenType;

pub const LEGEND_TYPE: &[SemanticTokenType] = &[
    SemanticTokenType::STRING,
    SemanticTokenType::COMMENT,
    SemanticTokenType::FUNCTION, // for action
    SemanticTokenType::VARIABLE, // for IP
    SemanticTokenType::NUMBER,   // for port
    SemanticTokenType::KEYWORD,  // for keywords
    SemanticTokenType::OPERATOR, // for direction
    SemanticTokenType::PROPERTY, // for option values
];

pub fn semantic_token_from_ast(ast: &AST) -> Vec<ImCompleteSemanticToken> {
    let mut semantic_tokens = vec![];

    ast.rules.iter().for_each(|(rule, _)| {
        // Push the action token
        let action = &rule.action;
        semantic_tokens.push(ImCompleteSemanticToken {
            start: action.1.start,
            length: action.1.len(),
            token_type: LEGEND_TYPE
                .iter()
                .position(|item| item == &SemanticTokenType::FUNCTION)
                .unwrap(),
        });

        // Push the header tokens
        let header = &rule.header.0;
        // handle network addresses
        semantic_token_from_address(&header.source, &mut semantic_tokens);
        semantic_token_from_address(&header.destination, &mut semantic_tokens);

        // handle network ports
        semantic_token_from_port(&header.source_port, &mut semantic_tokens);
        semantic_token_from_port(&header.destination_port, &mut semantic_tokens);

        // Push the options tokens
        let options = &rule.options;
        options
            .iter()
            .for_each(|option| semantic_token_from_options(option, &mut semantic_tokens));
    });

    semantic_tokens
}

pub fn semantic_token_from_address(
    expr: &(NetworkAddress, Range<usize>),
    semantic_tokens: &mut Vec<ImCompleteSemanticToken>,
) {
    let address = &expr.0;
    let span = &expr.1;
    match address {
        NetworkAddress::Any => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: span.start,
                length: span.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::VARIABLE)
                    .unwrap(),
            });
        }
        NetworkAddress::IPAddr(ip) => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: ip.1.start,
                length: ip.1.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::KEYWORD)
                    .unwrap(),
            });
        }
        NetworkAddress::CIDR(ip, mask) => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: ip.1.start,
                length: ip.1.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::KEYWORD)
                    .unwrap(),
            });
            semantic_tokens.push(ImCompleteSemanticToken {
                start: mask.1.start,
                length: mask.1.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::NUMBER)
                    .unwrap(),
            });
        }
        NetworkAddress::IPGroup(ips) => {
            ips.iter().for_each(|(_, span)| {
                semantic_tokens.push(ImCompleteSemanticToken {
                    start: span.start,
                    length: span.len(),
                    token_type: LEGEND_TYPE
                        .iter()
                        .position(|item| item == &SemanticTokenType::KEYWORD)
                        .unwrap(),
                })
            });
        }
        NetworkAddress::NegIP(ip) => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: ip.as_ref().1.start,
                length: ip.as_ref().1.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::STRING)
                    .unwrap(),
            });
            // semantic_token_from_address(ip.as_ref(), semantic_tokens);
        }
        NetworkAddress::IPVariable(_) => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: span.start,
                length: span.len(),
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
    mut semantic_tokens: &mut Vec<ImCompleteSemanticToken>,
) {
    let port = &expr.0;
    let span = &expr.1;
    match port {
        NetworkPort::Any => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: span.start,
                length: span.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::VARIABLE)
                    .unwrap(),
            });
        }
        NetworkPort::Port(_) => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: span.start,
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
                .for_each(|port| semantic_token_from_port(port, &mut semantic_tokens));
        }
        NetworkPort::PortRange((_, from_span), (_, to_span)) => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: from_span.start,
                length: from_span.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::NUMBER)
                    .unwrap(),
            });
            semantic_tokens.push(ImCompleteSemanticToken {
                start: to_span.start,
                length: to_span.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::NUMBER)
                    .unwrap(),
            });
        }
        NetworkPort::PortOpenRange((_, port_span), _) => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: port_span.start,
                length: port_span.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::NUMBER)
                    .unwrap(),
            });
        }
        NetworkPort::NegPort(port) => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: port.as_ref().1.start,
                length: port.as_ref().1.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::NUMBER)
                    .unwrap(),
            });
        }
    }
}

pub fn semantic_token_from_options(
    expr: &(RuleOption, Range<usize>),
    semantic_tokens: &mut Vec<ImCompleteSemanticToken>,
) {
    let option = &expr.0;
    match option {
        RuleOption::KeywordPair((_, keyspan), values) => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: keyspan.start,
                length: keyspan.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::KEYWORD)
                    .unwrap(),
            });
            values.iter().for_each(|(_, valspan)| {
                semantic_tokens.push(ImCompleteSemanticToken {
                    start: valspan.start,
                    length: valspan.len(),
                    token_type: LEGEND_TYPE
                        .iter()
                        .position(|item| item == &SemanticTokenType::PROPERTY)
                        .unwrap(),
                });
            })
        }
        RuleOption::Buffer((_, span)) => {
            semantic_tokens.push(ImCompleteSemanticToken {
                start: span.start,
                length: span.len(),
                token_type: LEGEND_TYPE
                    .iter()
                    .position(|item| item == &SemanticTokenType::KEYWORD)
                    .unwrap(),
            });
        }
    }
}
