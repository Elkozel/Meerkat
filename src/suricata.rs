//! Suricata API
//!
//! Provides the functions to use suricata if it is installed on the system
//!
//! These functions include:
//! - Parsing logs
//! - Fetching errors and generating diagnostics
//! - Fetching keywords

use chrono::{DateTime, FixedOffset, Local, NaiveDate};
use chumsky::{
    prelude::Simple,
    primitive::{empty, end, just, take_until},
    text::{self, TextParser},
    Parser,
};
use csv::ReaderBuilder;
use ropey::Rope;
use serde::Deserialize;
use std::path::Path;
use std::{collections::HashMap, error::Error};
use tempfile::{tempdir, NamedTempFile};
use tokio::process::Command;
use tower_lsp::lsp_types::{Diagnostic, DiagnosticSeverity, Position, Range};

/// Verify a list of rules
pub async fn verify_rule(rope: &Rope) -> Result<Vec<Diagnostic>, Box<dyn Error>> {
    let temp_dir = tempdir()?;
    let tempfile = NamedTempFile::new_in(&temp_dir)?;
    rope.write_to(&tempfile)?;
    let log_file = get_process_output(tempfile.path(), temp_dir.path()).await?;
    tempfile.close()?;
    let logs = LogMessage::parse_logs().parse(log_file);

    let mut curr_line = 0;

    // Go over each log
    let diagnostics = match logs {
        Ok(logs) => {
            logs.iter()
                .rev()
                .filter_map(|error| -> Option<Diagnostic> {
                    // Check if the log has an error code
                    match &error.err_code {
                        // Check it is the error code, which contains the line and file
                        Some(_)
                            if error.message.contains("at line ")
                                && error.message.contains("from file ") =>
                        {
                            // Find the location of file name and line in output
                            let line_loc = error.message.rfind("at line ")? + "at line ".len();

                            // Get current line and file from logs
                            let parsed_line = &error.message[line_loc..];
                            // Check if parse was successfull
                            if let Ok(line_num) = parsed_line.parse::<u32>() {
                                curr_line = line_num;
                            }
                            // Return none
                            None
                        }
                        // Else push error to the user
                        Some(err_code) => {
                            let range = Range::new(
                                Position {
                                    line: curr_line - 1, // Since lines are indexed at 0
                                    character: 0,
                                },
                                Position {
                                    line: curr_line - 1, // Since lines are indexed at 0
                                    character: u32::MAX,
                                },
                            );
                            let source = String::from("Suricata");
                            Some(Diagnostic::new_with_code_number(
                                range,
                                DiagnosticSeverity::ERROR,
                                err_code.err_code as i32,
                                Some(source),
                                error.message.clone(),
                            ))
                        }
                        _ => None,
                    }
                })
                .collect::<Vec<Diagnostic>>()
        }
        Err(_) => {
            vec![]
        }
    };
    Ok(diagnostics)
}

/// Gets the output that Suricata produced and returns it as a String
async fn get_process_output(rule_file: &Path, log_path: &Path) -> Result<String, Box<dyn Error>> {
    // Execute suricata
    // -S loaded exclusively
    // -l log directory (maybe)
    // -r pcap offline mode
    let suricata_process = Command::new("suricata")
        .args([
            "-S",
            rule_file.display().to_string().as_str(),
            "-l",
            log_path.display().to_string().as_str(),
            "--engine-analysis",
        ])
        .output()
        .await?;

    // Get the output from the command
    let log_file = String::from_utf8(suricata_process.stderr)?;
    // A hacky method to fix suricata strange output
    let log_file = log_file.replace("\n\"", "\"");
    Ok(log_file)
}

/// A CSV record, obtained from the suricata cli
#[derive(Debug, Clone, Deserialize)]
pub struct KeywordRecord {
    pub name: String,
    pub description: String,
    pub app_layer: String,
    pub features: String,
    pub documentation: String,
}
impl KeywordRecord {
    /// Convert a Keywords record into a Keyword (adding an abstraction layer)
    pub fn to_keyword(record: KeywordRecord) -> (String, Keyword) {
        if record.features.starts_with("No option") {
            return (record.name.clone(), Keyword::NoOption(record));
        }
        return (record.name.clone(), Keyword::Other(record));
    }
}

/// An abstraction layer for the [KeywordRecord] struct
#[derive(Debug)]
pub enum Keyword {
    NoOption(KeywordRecord),
    Other(KeywordRecord),
}

pub async fn get_keywords() -> Result<HashMap<String, Keyword>, Box<dyn Error>> {
    let mut ret = HashMap::new();
    // Execute suricata
    // -r pcap offline mode
    let keywords_command = Command::new("suricata")
        .arg("--list-keywords=csv")
        .output()
        .await?;

    // Get the output from the command
    let mut log_file = String::from_utf8(keywords_command.stdout)?;
    // Skip all the log files
    let csv_start = log_file.find("name;description;app layer;features;documentation");
    if let Some(csv_start) = csv_start {
        log_file = (&log_file[csv_start..]).to_string();
    }
    // Hacky solution to suricata adding ; after every record
    log_file = log_file.replace("documentation", "documentation;");
    // Hacky solution to suricata using non-standard header names
    log_file = log_file.replace("app layer", "app_layer");

    // Get all CSV records
    let mut reader = ReaderBuilder::new()
        .delimiter(b';')
        .from_reader(log_file.as_bytes());
    for record in reader.deserialize() {
        // Ignore errors
        if let Ok(keyword_record) = record {
            let (name, keyword) = KeywordRecord::to_keyword(keyword_record);
            ret.insert(name, keyword);
        }
    }
    Ok(ret)
}

#[derive(Clone, Debug)]
struct SuricataErrorCode {
    err_type: String,
    err_code: u32,
}

#[derive(Clone, Debug)]
struct LogMessage {
    timestamp: DateTime<FixedOffset>,
    log_level: String,
    err_code: Option<SuricataErrorCode>,
    message: String,
}
impl SuricataErrorCode {
    // Example input: "[ERRCODE: SC_ERR_INVALID_SIGNATURE(39)]""
    fn parser() -> impl Parser<char, SuricataErrorCode, Error = Simple<char>> {
        let err_type = text::ident();
        let err_code = text::int(10)
            .delimited_by(just("("), just(")"))
            .map(|s: String| s.parse::<u32>().unwrap());
        just::<_, _, Simple<char>>("ERRCODE:")
            .then(err_type.padded())
            .then(err_code.padded())
            .delimited_by(just("["), just("]"))
            .padded()
            .map(|((_, err_type), err_code)| SuricataErrorCode {
                err_type: err_type,
                err_code: err_code,
            })
    }
}

impl LogMessage {
    pub fn parser() -> impl Parser<char, LogMessage, Error = Simple<char>> {
        let zeroes = just::<_, _, Simple<char>>('0').repeated();
        let integer = zeroes
            .or_not()
            .ignore_then(text::digits(10))
            .from_str::<u32>()
            .unwrapped();

        let date = integer.separated_by(just("/")).exactly(3);
        let time = integer.separated_by(just(":")).exactly(3);
        let timestamp = date
            .padded()
            .then_ignore(just("--"))
            .then(time.padded())
            .map(|(date, time)| {
                let offset = Local::now().offset().to_owned();
                let datetime =
                    NaiveDate::from_ymd_opt(date[2].try_into().unwrap(), date[1], date[0])
                        .and_then(|a| a.and_hms_opt(time[0], time[1], time[2]))
                        .and_then(|a| Some(a.and_local_timezone(offset)))
                        .unwrap();
                datetime.earliest().unwrap()
            });

        let log_level = text::ident::<_, Simple<char>>()
            .delimited_by(just("<"), just(">"))
            .padded();
        let dash = just::<_, _, Simple<char>>("-").padded();

        timestamp
            .then_ignore(dash)
            .then(log_level)
            .then_ignore(dash)
            .then(SuricataErrorCode::parser().or_not())
            .then_ignore(dash.or_not())
            .then(take_until(
                text::newline::<Simple<char>>().or(end::<Simple<char>>()),
            ))
            .map(
                |(((timestamp, log_level), err_code), (message, _))| LogMessage {
                    timestamp,
                    log_level,
                    err_code,
                    message: message.into_iter().collect(),
                },
            )
    }
    pub fn parse_logs() -> impl Parser<char, Vec<LogMessage>, Error = Simple<char>> {
        LogMessage::parser()
            .separated_by(empty())
            .allow_leading()
            .allow_trailing()
    }
}
