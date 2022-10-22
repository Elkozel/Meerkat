use std::collections::HashMap;

use chumsky::Parser;
use dashmap::DashMap;
use meerkat::completion::{get_completion, Keyword};
use meerkat::hover::get_hover;
use meerkat::reference::get_reference;
use meerkat::rule::{Spanned, AST, Rule};
use meerkat::semantic_token::{LEGEND_TYPE, ImCompleteSemanticToken, semantic_token_from_rule};
use ropey::Rope;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer, LspService, Server};

#[derive(Debug)]
struct Backend {
    client: Client,
    ast_map: DashMap<String, AST>,
    document_map: DashMap<String, Rope>,
    semantic_token_map: DashMap<String, Vec<ImCompleteSemanticToken>>,
    keywords: HashMap<String, Keyword>,
    variables: Vec<String>,
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            server_info: None,
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                completion_provider: Some(CompletionOptions {
                    resolve_provider: Some(false),
                    trigger_characters: Some(vec![
                        " ".to_string(),
                        ":".to_string(),
                        ";".to_string(),
                        "\n".to_string(),
                    ]),
                    work_done_progress_options: Default::default(),
                    all_commit_characters: None,
                }),
                execute_command_provider: Some(ExecuteCommandOptions {
                    // TODO
                    commands: vec!["dummy.do_something".to_string()],
                    work_done_progress_options: Default::default(),
                }),

                workspace: Some(WorkspaceServerCapabilities {
                    workspace_folders: Some(WorkspaceFoldersServerCapabilities {
                        supported: Some(true),
                        change_notifications: Some(OneOf::Left(true)),
                    }),
                    file_operations: None,
                }),
                semantic_tokens_provider: Some(
                    SemanticTokensServerCapabilities::SemanticTokensRegistrationOptions(
                        SemanticTokensRegistrationOptions {
                            text_document_registration_options: {
                                TextDocumentRegistrationOptions {
                                    document_selector: Some(vec![DocumentFilter {
                                        language: Some("suricata".to_string()),
                                        scheme: Some("file".to_string()),
                                        pattern: None,
                                    }]),
                                }
                            },
                            semantic_tokens_options: SemanticTokensOptions {
                                work_done_progress_options: WorkDoneProgressOptions::default(),
                                legend: SemanticTokensLegend {
                                    // TODO
                                    token_types: LEGEND_TYPE.clone().into(),
                                    token_modifiers: vec![],
                                },
                                range: Some(true),
                                full: Some(SemanticTokensFullOptions::Bool(true)),
                            },
                            static_registration_options: StaticRegistrationOptions::default(),
                        },
                    ),
                ),
                references_provider: Some(OneOf::Left(true)),
                rename_provider: Some(OneOf::Left(true)),
                document_formatting_provider: Some(OneOf::Left(true)),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                document_range_formatting_provider: Some(OneOf::Left(true)),
                ..ServerCapabilities::default()
            },
        })
    }
    async fn semantic_tokens_full(
        &self,
        params: SemanticTokensParams,
    ) -> Result<Option<SemanticTokensResult>> {
        let uri = params.text_document.uri.to_string();
        self.client
            .log_message(MessageType::LOG, "semantic_token_full")
            .await;
        let semantic_tokens = || -> Option<Vec<SemanticToken>> {
            let mut im_complete_tokens = self.semantic_token_map.get_mut(&uri)?;
            let rope = self.document_map.get(&uri)?;
            let ast = self.ast_map.get(&uri)?;
            let mut extends_tokens = vec![];
            ast.rules.iter().for_each(|(line, rule)| {
                let line_offset = rope.line_to_char(line as usize);
                semantic_token_from_rule(rule, &line_offset, &mut extends_tokens);
            });
            im_complete_tokens.extend(extends_tokens);
            im_complete_tokens.sort_by(|a, b| a.start.cmp(&b.start));
            let mut pre_line = 0;
            let mut pre_start = 0;
            let semantic_tokens = im_complete_tokens
                .iter()
                .filter_map(|token| {
                    let line = rope.try_byte_to_line(token.start as usize).ok()? as u32;
                    let first = rope.try_line_to_char(line as usize).ok()? as u32;
                    let start = rope.try_byte_to_char(token.start as usize).ok()? as u32 - first;
                    let delta_line = line - pre_line;
                    let delta_start = if delta_line == 0 {
                        start - pre_start
                    } else {
                        start
                    };
                    let ret = Some(SemanticToken {
                        delta_line,
                        delta_start,
                        length: token.length as u32,
                        token_type: token.token_type as u32,
                        token_modifiers_bitset: 0,
                    });
                    pre_line = line;
                    pre_start = start;
                    ret
                })
                .collect::<Vec<_>>();
            Some(semantic_tokens)
        }();
        self.client
            .log_message(
                MessageType::LOG,
                format!("All tokens: {:?}", semantic_tokens),
            )
            .await;
        if let Some(semantic_token) = semantic_tokens {
            return Ok(Some(SemanticTokensResult::Tokens(SemanticTokens {
                result_id: None,
                data: semantic_token,
            })));
        }
        Ok(None)
    }

    async fn semantic_tokens_range(
        &self,
        params: SemanticTokensRangeParams,
    ) -> Result<Option<SemanticTokensRangeResult>> {
        let uri = params.text_document.uri.to_string();
        let semantic_tokens = || -> Option<Vec<SemanticToken>> {
            let im_complete_tokens = self.semantic_token_map.get(&uri)?;
            let rope = self.document_map.get(&uri)?;
            let mut pre_line = 0;
            let mut pre_start = 0;
            let semantic_tokens = im_complete_tokens
                .iter()
                .filter_map(|token| {
                    let line = rope.try_byte_to_line(token.start as usize).ok()? as u32;
                    let first = rope.try_line_to_char(line as usize).ok()? as u32;
                    let start = rope.try_byte_to_char(token.start as usize).ok()? as u32 - first;
                    let ret = Some(SemanticToken {
                        delta_line: line - pre_line,
                        delta_start: if start >= pre_start {
                            start - pre_start
                        } else {
                            start
                        },
                        length: token.length as u32,
                        token_type: token.token_type as u32,
                        token_modifiers_bitset: 0,
                    });
                    pre_line = line;
                    pre_start = start;
                    ret
                })
                .collect::<Vec<_>>();
            Some(semantic_tokens)
        }();
        if let Some(semantic_token) = semantic_tokens {
            return Ok(Some(SemanticTokensRangeResult::Tokens(SemanticTokens {
                result_id: None,
                data: semantic_token,
            })));
        }
        Ok(None)
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "initialized!")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn references(&self, params: ReferenceParams) -> Result<Option<Vec<Location>>> {
        let reference_list = || -> Option<Vec<Location>> {
            let uri = params.text_document_position.text_document.uri;
            let ast = self.ast_map.get(&uri.to_string())?;

            let position = params.text_document_position.position;
            let col = position.character as usize;
            let (reference_list, _) = get_reference(&ast, &position.line, &col, false)?;
            Some(reference_list)
        }();
        Ok(reference_list)
    }

    async fn formatting(&self, params: DocumentFormattingParams) -> Result<Option<Vec<TextEdit>>> {
        let text_edits = || -> Option<Vec<TextEdit>> {
            let uri = params.text_document.uri;
            let ast = self.ast_map.get(&uri.to_string())?;
            let rope = self.document_map.get(&uri.to_string())?;
            let mut ret = vec![];
            ast.rules.iter().for_each(|(rule, rule_span)| {
                let line_nr = rope.char_to_line(rule_span.start);
                let line = rope.get_line(line_nr);
                if let Some(line) = line {
                    let formatted_rule = rule.to_string();
                    if line.to_string() != formatted_rule {
                        let start_range = Position {
                            line: line_nr as u32,
                            character: 0,
                        };
                        let end_range = Position {
                            line: line_nr as u32,
                            character: 0,
                        };
                        ret.push(TextEdit {
                            range: Range {
                                start: start_range,
                                end: end_range,
                            },
                            new_text: formatted_rule,
                        })
                    }
                } else {
                    return;
                }
            });
            Some(ret)
        }();
        Ok(text_edits)
    }

    async fn range_formatting(
        &self,
        params: DocumentRangeFormattingParams,
    ) -> Result<Option<Vec<TextEdit>>> {
        let line_range = params.range.start.line..params.range.end.line;
        let text_edits = || -> Option<Vec<TextEdit>> {
            let uri = params.text_document.uri;
            let ast = self.ast_map.get(&uri.to_string())?;
            let rope = self.document_map.get(&uri.to_string())?;
            let mut ret = vec![];
            ast.rules
                .iter()
                .filter(|(_, (rule, rule_span))| {
                    let rule_line = rope.char_to_line(rule_span.start) as u32;
                    line_range.contains(&rule_line)
                })
                .for_each(|(rule, rule_span)| {
                    let line_nr = rope.char_to_line(rule_span.start);
                    let line = rope.get_line(line_nr);
                    if let Some(line) = line {
                        let formatted_rule = rule.to_string();
                        if line.to_string() != formatted_rule {
                            let start_range = Position {
                                line: line_nr as u32,
                                character: 0,
                            };
                            let end_range = Position {
                                line: line_nr as u32,
                                character: 0,
                            };
                            ret.push(TextEdit {
                                range: Range {
                                    start: start_range,
                                    end: end_range,
                                },
                                new_text: formatted_rule,
                            })
                        }
                    } else {
                        return;
                    }
                });
            Some(ret)
        }();
        Ok(text_edits)
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let hover_content = || -> Option<Hover> {
            let uri = params.text_document_position_params.text_document.uri;
            let ast = self.ast_map.get(&uri.to_string())?;
            let rope = self.document_map.get(&uri.to_string())?;

            let position = params.text_document_position_params.position;
            let offset = position.character as usize;

            let (hover, span) = get_hover(&ast, &position.line, &offset, &self.keywords)?;
            let start_position = offset_to_position(span.start, &rope)?;
            let end_position = offset_to_position(span.end, &rope)?;
            let hover_range = Range {
                start: start_position,
                end: end_position,
            };
            Some(Hover {
                contents: hover,
                range: Some(hover_range),
            })
        }();
        Ok(hover_content)
    }

    async fn did_change_workspace_folders(&self, _: DidChangeWorkspaceFoldersParams) {
        self.client
            .log_message(MessageType::INFO, "workspace folders changed!")
            .await;
    }

    async fn did_change_configuration(&self, _: DidChangeConfigurationParams) {
        self.client
            .log_message(MessageType::INFO, "configuration changed!")
            .await;
    }

    async fn did_change_watched_files(&self, _: DidChangeWatchedFilesParams) {
        self.client
            .log_message(MessageType::INFO, "watched files have changed!")
            .await;
    }

    async fn execute_command(&self, _: ExecuteCommandParams) -> Result<Option<Value>> {
        self.client
            .log_message(MessageType::INFO, "command executed!")
            .await;

        match self.client.apply_edit(WorkspaceEdit::default()).await {
            Ok(res) if res.applied => self.client.log_message(MessageType::INFO, "applied").await,
            Ok(_) => self.client.log_message(MessageType::INFO, "rejected").await,
            Err(err) => self.client.log_message(MessageType::ERROR, err).await,
        }

        Ok(None)
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        self.client
            .log_message(MessageType::INFO, "file opened!")
            .await;
        self.on_change(TextDocumentItem {
            uri: params.text_document.uri,
            text: params.text_document.text,
            version: params.text_document.version,
        })
        .await
    }

    async fn did_change(&self, mut params: DidChangeTextDocumentParams) {
        self.on_change(TextDocumentItem {
            uri: params.text_document.uri,
            text: std::mem::take(&mut params.content_changes[0].text),
            version: params.text_document.version,
        })
        .await
    }

    async fn did_save(&self, _: DidSaveTextDocumentParams) {
        self.client
            .log_message(MessageType::INFO, "file saved!")
            .await;
    }

    async fn did_close(&self, _: DidCloseTextDocumentParams) {
        self.client
            .log_message(MessageType::INFO, "file closed!")
            .await;
    }

    async fn rename(&self, params: RenameParams) -> Result<Option<WorkspaceEdit>> {
        let workspace_edit = || -> Option<WorkspaceEdit> {
            let uri = params.text_document_position.text_document.uri;
            let ast = self.ast_map.get(&uri.to_string())?;
            let rope = self.document_map.get(&uri.to_string())?;

            let position = params.text_document_position.position;
            let col = position.character as usize;
            let (reference_list, variable_name) = get_reference(&ast, &position.line, &col, true)?;
            if reference_list.len() > 0 {
                let edit_list = reference_list
                    .into_iter()
                    .filter_map(|position| {
                        let start_position = position;
                        let end_position = Position::new(position.line, position.character + variable_name.len());
                        Some(TextEdit::new(
                            Range::new(start_position, end_position),
                            params.new_name.clone(),
                        ))
                    })
                    .collect::<Vec<_>>();
                let mut map = HashMap::new();
                map.insert(uri, edit_list);
                let workspace_edit = WorkspaceEdit::new(map);
                Some(workspace_edit)
            } else {
                None
            }
        }();
        Ok(workspace_edit)
    }

    async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
        let uri = params.text_document_position.text_document.uri;
        let position = params.text_document_position.position;
        let completions = || -> Option<Vec<CompletionItem>> {
            let rope = self.document_map.get(&uri.to_string())?;
            let line = rope.get_line(position.line as usize)?;
            let ast = self.ast_map.get(&uri.to_string())?;
            let offset = position.character as usize;
            let completions = get_completion(&line, &ast, &offset, &self.variables, &self.keywords);
            Some(completions)
        }();
        Ok(completions.map(CompletionResponse::Array))
    }
}
#[derive(Debug, Deserialize, Serialize)]

enum CustomNotification {}
struct TextDocumentItem {
    uri: Url,
    text: String,
    version: i32,
}
impl Backend {
    async fn on_change(&self, params: TextDocumentItem) {
        let rope = ropey::Rope::from_str(&params.text);
        self.document_map
            .insert(params.uri.to_string(), rope.clone());
        
        let mut semantic_tokens = vec![];
        let mut errors = vec![];
        let mut ast = AST{ rules: HashMap::with_capacity(rope.len_lines())};
        rope.lines().for_each(|line| {
            let (rule, errors) = Rule::parser().parse_recovery(line);
            ast.rules.insert(line, rule);
            errors.push(errors);

            let line_offset = rope.line_to_char(line);
            semantic_token_from_rule(rule, &line_offset, &mut semantic_tokens)
        });
        // let (ast, errors) = AST::parser().parse_recovery(params.text);
        // let semantic_tokens = if let Some(tokens) = &ast {
        //     semantic_token_from_ast(tokens)
        // } else {
        //     vec![]
        // };
        self.client
            .log_message(MessageType::INFO, format!("{:?}", errors))
            .await;
        let diagnostics = errors
            .into_iter()
            .filter_map(|item| {
                let (message, span) = match item.reason() {
                    chumsky::error::SimpleReason::Unclosed { span, delimiter } => {
                        (format!("Unclosed delimiter {}", delimiter), span.clone())
                    }
                    chumsky::error::SimpleReason::Unexpected => (
                        format!(
                            "{}, expected {}",
                            if item.found().is_some() {
                                "Unexpected token in input"
                            } else {
                                "Unexpected end of input"
                            },
                            if item.expected().len() == 0 {
                                "something else".to_string()
                            } else {
                                item.expected()
                                    .map(|expected| match expected {
                                        Some(expected) => expected.to_string(),
                                        None => "end of input".to_string(),
                                    })
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            }
                        ),
                        item.span(),
                    ),
                    chumsky::error::SimpleReason::Custom(msg) => (msg.to_string(), item.span()),
                };

                let diagnostic = || -> Option<Diagnostic> {
                    // let start_line = rope.try_char_to_line(span.start)?;
                    // let first_char = rope.try_line_to_char(start_line)?;
                    // let start_column = span.start - first_char;
                    let start_position = offset_to_position(span.start, &rope)?;
                    let end_position = offset_to_position(span.end, &rope)?;
                    // let end_line = rope.try_char_to_line(span.end)?;
                    // let first_char = rope.try_line_to_char(end_line)?;
                    // let end_column = span.end - first_char;
                    Some(Diagnostic::new_simple(
                        Range::new(start_position, end_position),
                        message,
                    ))
                }();
                diagnostic
            })
            .collect::<Vec<_>>();

        self.client
            .publish_diagnostics(params.uri.clone(), diagnostics, Some(params.version))
            .await;
            
            self.ast_map.insert(params.uri.to_string(), ast);
        self.client
            .log_message(MessageType::INFO, &format!("{:?}", semantic_tokens))
            .await;
        self.semantic_token_map
            .insert(params.uri.to_string(), semantic_tokens);
        self.client
            .log_message(MessageType::INFO, &format!("AST: {:?}", self.ast_map))
            .await;
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::build(|client| Backend {
        client,
        ast_map: DashMap::new(),
        document_map: DashMap::new(),
        semantic_token_map: DashMap::new(),
        keywords: HashMap::new(),
        variables: vec![],
    })
    .finish();
    Server::new(stdin, stdout, socket).serve(service).await;
}

fn offset_to_position(offset: usize, rope: &Rope) -> Option<Position> {
    let line = rope.try_char_to_line(offset).ok()?;
    let first_char = rope.try_line_to_char(line).ok()?;
    let column = offset - first_char;
    Some(Position::new(line as u32, column as u32))
}
