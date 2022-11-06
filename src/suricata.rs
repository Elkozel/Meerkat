//! Suricata API
//!
//! Provides the functions to use suricata if it is installed on the system
//!
//! These functions include:
//! - Parsing logs
//! - Fetching errors and generating diagnostics
//! - Fetching keywords (TODO)

use chrono::{DateTime, FixedOffset, Local, NaiveDate};
use chumsky::{
    prelude::Simple,
    primitive::{empty, end, just, take_until},
    text::{self, TextParser},
    Parser,
};
use std::{path::Path, process::Command, str};
use tower_lsp::lsp_types::{Diagnostic, Range, Position};

const INVALID_SIGNATURE_ERROR_CODE: u32 = 39;
const ERROR_TYPE: &str = "Error";

/// Verify a list of rules
pub fn verify_rule(path: &str) -> Vec<Diagnostic> {
    let diagnostics = vec![];
    let log_file = get_process_output(path);
    println!("Log file: {}", &log_file);
    let logs: Vec<LogMessage> = LogMessage::parse_logs().parse(log_file).unwrap();

    let mut curr_line = 0;
    let mut curr_file = "";
    // Go over each log
    logs.iter()
        .filter(|log_msg| log_msg.log_level == ERROR_TYPE) // look at only error logs
        .rev() // go in reverese order
        .for_each(|error| {
            || -> Option<_> {
                // Check if the log has an error code
                match &error.err_code {
                    // Check it is the error code, which contains the line and file
                    Some(err_code) if err_code.err_code == INVALID_SIGNATURE_ERROR_CODE => {
                        // Find the location of file name and line in output
                        let from_file_loc = error.message.rfind("from file ")? + "from file ".len();
                        let line_loc = error.message.rfind("at line ")? + "at line ".len();

                        // Get current line and file from logs
                        curr_file = &error.message[from_file_loc..line_loc - "at line ".len()];
                        let parsed_line = &error.message[line_loc..];
                        // Check if parse was successfull
                        match parsed_line.parse::<u32>() {
                            Ok(line_num) => curr_line = line_num,
                            Err(_) => (),
                        }

                        println!("curr line: {}, curr file: {}", &curr_line, &curr_file);
                        Some(())
                    }
                    // Else push error to the user
                    _ => {
                        let range = Range::new(
                            Position { line: curr_line, character: 0 }, 
                            Position { line: curr_line, character: u32::MAX }
                        );
                        Diagnostic::new_simple(range, error.message.clone());
                        Some(())
                    }
                }
            }();
        });
    diagnostics
}

fn get_process_output(rule_file: &str) -> String {
    // Generate absolute path
    let path = Path::new(rule_file)
        .canonicalize()
        .expect("Could not generate path to file");
    let rules_file = path
        .to_str()
        .expect("Path encoding is not valid for the OS");

    // Execute suricata
    // -S loaded exclusively
    // -l log directory (maybe)
    // -r pcap offline mode
    let suricata_process = Command::new("suricata")
        .args([format!("-S {}", rules_file).as_str(), "--engine-analysis"])
        .output()
        .expect("Could not execute suricata");

    // Get the output from the command
    let log_file = String::from_utf8(suricata_process.stdout).expect("The response was not UTF-8");
    log_file
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
                let datetime = NaiveDate::from_ymd(date[2].try_into().unwrap(), date[1], date[0])
                    .and_hms(time[0], time[1], time[2]);
                let offset = Local::now().offset().to_owned();
                DateTime::<FixedOffset>::from_local(datetime, offset)
            });

        let log_level = text::ident().delimited_by(just("<"), just(">")).padded();
        let dash = just::<_, _, Simple<char>>("-").padded();

        timestamp
            .then_ignore(dash)
            .then(log_level)
            .then_ignore(dash)
            .then(SuricataErrorCode::parser().or_not())
            .then_ignore(dash.or_not())
            .then(take_until(text::newline::<Simple<char>>().or(end::<Simple<char>>())))
            .map(|(((timestamp, log_level), err_code), msg)| {
                let (message, _) = msg;
                LogMessage {
                    timestamp,
                    log_level,
                    err_code,
                    message: message.into_iter().collect(),
                }
            })
    }
    pub fn parse_logs() -> impl Parser<char, Vec<LogMessage>, Error = Simple<char>> {
        LogMessage::parser()
            .separated_by(empty())
            .allow_leading()
            .allow_trailing()
    }
}
