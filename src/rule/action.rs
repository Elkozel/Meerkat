use ropey::Error;
use std::str::FromStr;
use std::{collections::HashSet, fmt};
use tower_lsp::lsp_types::{CompletionItem, CompletionItemKind};

use super::Completions;

#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub enum Action {
    Alert,      // generate an alert
    Pass,       // stop further inspection of the packet
    Drop,       // drop packet and generate alert
    Reject,     // send RST/ICMP unreach error to the sender of the matching packet.
    Rejectsrc,  // same as just reject
    Rejectdst,  // send RST/ICMP error packet to receiver of the matching packet.
    Rejectboth, // send RST/ICMP error packets to both sides of the conversation.
    Other(String),
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Action::Alert => write!(f, "alert"),
            Action::Pass => write!(f, "pass"),
            Action::Drop => write!(f, "drop"),
            Action::Reject => write!(f, "reject"),
            Action::Rejectsrc => write!(f, "rejectsrc"),
            Action::Rejectdst => write!(f, "rejectdst"),
            Action::Rejectboth => write!(f, "rejectboth"),
            Action::Other(action) => write!(f, "{}", action),
        }
    }
}

impl FromStr for Action {
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let res = match s {
            "alert" => Action::Alert,
            "pass" => Action::Pass,
            "drop" => Action::Drop,
            "reject" => Action::Reject,
            "rejectsrc" => Action::Rejectsrc,
            "rejectdst" => Action::Rejectdst,
            "rejectboth" => Action::Rejectboth,
            other => Action::Other(other.to_string()),
        };
        Ok(res)
    }

    type Err = Error;
}

impl Completions for Action {
    fn get_completion(
        address_variables: &HashSet<String>,
        port_variables: &HashSet<String>,
        completion_tokens: &mut Vec<CompletionItem>,
    ) {
        // Create an array with all possible actions
        let possible_strings = vec![
            "alert",
            "pass",
            "drop",
            "reject",
            "rejectsrc",
            "rejectdst",
            "rejectboth",
        ];

        // Convert all string actions to CompletionItems
        let completions = possible_strings
            .iter()
            .map(|action| CompletionItem {
                label: action.to_string(),
                kind: Some(CompletionItemKind::OPERATOR),
                ..Default::default()
            })
            .collect::<Vec<CompletionItem>>();
        completion_tokens.extend(completions);
    }
}
