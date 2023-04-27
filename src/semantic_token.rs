//! Provides the semantic tokenization logic for the language server
//! 
//! Semantic tokens are used for syntax highlighting.
//! For more information you can take a look at the [VSCode API docs] or the [Semantic Highlighting Overview].
//! 
//! For how semantic tokens work, please take a look at the explanation for the [ImCompleteSemanticToken] struct
//! 
//! [VSCode API docs]: https://code.visualstudio.com/api/language-extensions/semantic-highlight-guide
//! [Semantic Highlighting Overview]: https://github.com/microsoft/vscode/wiki/Semantic-Highlighting-Overview

use crate::rule::{Rule, Spanned, Semantics};
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
    semantic_tokens: &mut Vec<ImCompleteSemanticToken>,
) {
    let (rule, _) = rule;
    rule.get_semantics(col, semantic_tokens);
}