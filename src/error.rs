//! Custom error types for the parsing of Tor documents

use std::num::ParseIntError;
use std::string::ToString;

use thiserror;

/// Error that occured when parsing a Tor document
#[derive(thiserror::Error, Debug)]
pub enum DocumentParseError {
    #[error("an internal parsing error occured (raised by nom)")]
    Internal(#[from] nom::error::Error<String>),
    #[error("Parsing stopped after {index} characters before input was complete (line {line}, character {character})")]
    InputRemaining {
        index: usize,
        line: usize,
        character: usize,
    },
    #[error("When parsing a document, not all necessary information were present")]
    Incomplete(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("An item with keyword '{keyword}' unexpectedly had no or not enough arguments")]
    ItemArgumentsMissing { keyword: String },
    #[error("An item with keyword '{keyword}' was not expected at this position")]
    UnexpectedKeyword { keyword: String },
    #[error("Could not decode string as base64")]
    InvalidBase64(#[from] base64::DecodeError),
    #[error("Could not parse date/time")]
    InvalidDate(#[from] chrono::format::ParseError),
    #[error("Could not parse integer in {context}")]
    InvalidInt { context: String },
    #[error("Unknown flag '{flag}'")]
    UnknownFlag { flag: String },
    #[error("Unknown protocol '{protocol}'")]
    UnknownProtocol { protocol: String },
    #[error("Invalid protocol version '{raw}'")]
    InvalidProtocolVersion { raw: String },
    #[error("Invalid exit policy entry '{raw}'")]
    InvalidExitPolicyEntry { raw: String },
    #[error("Malformed exit policy")]
    MalformedExitPolicy,
    #[error("Invalid argument dictionary")]
    InvalidArgumentDict,
    #[error("Invalid bandwidth weight entry")]
    InvalidBandwidthWeight,
    #[error("Consensus weights missing")]
    ConsensusWeightsMissing,
    #[error("Consensus weights cannot be parsed")]
    MalformedConsensusWeights,
    #[error("valid-after missing")]
    ValidAfterMissing,
    #[error("Content range '{from}'...'{to}' not found")]
    ContentRangeNotFound { from: String, to: String },
    #[error("Invalid IP address of relay: {0}")]
    InvalidIpAddress(String),
    #[error("Error parsing the IP Address")]
    IpParseError(String),
    #[error("Error parsing a range")]
    RangeParseError(String),
    #[error("Error parsing a value")]
    ValueParseError(String),
    #[error("Error expected \"accept\" or \"reject\" received: {0}")]
    PolicyParseError(String),
}

impl DocumentParseError {
    /// Create a new error of variant `InputRemaining`, based on the
    /// observed parser inputs.
    pub(crate) fn remaining(total_input: &str, remaining_input: &str) -> DocumentParseError {
        if remaining_input.len() > total_input.len() {
            panic!(
                "More input remaining ({}) than was available before parsing ({}) of Tor document.",
                remaining_input.len(),
                total_input.len()
            );
        }
        let consumed = total_input.len() - remaining_input.len();
        let line = total_input[..consumed].matches('\n').count() + 1;
        let character = match total_input[..consumed].rfind('\n') {
            Some(index) => consumed - index,
            None => consumed + 1,
        };
        DocumentParseError::InputRemaining {
            index: consumed,
            line,
            character,
        }
    }

    /// Create a new ItemArgumentsMissing error, easily
    pub fn args_missing(keyword: impl Into<String>) -> DocumentParseError {
        DocumentParseError::ItemArgumentsMissing {
            keyword: keyword.into(),
        }
    }
}

/// Error when combining consensus and descriptors
#[derive(thiserror::Error, Debug)]
pub enum DocumentCombiningError {
    #[error("No descriptor with digest {digest} found.")]
    MissingDescriptor { digest: super::meta::Fingerprint },
    #[error("Descriptors cannot be found because the consensus file is not in a suitable folder structure")]
    InvalidFolderStructure,
    #[error("There was an error when parsing one of the referenced descriptor documents")]
    DocumentParseError(#[from] DocumentParseError),
}

pub(crate) trait ErrorContext<T> {
    type IntoError;

    fn context(self, context: impl ToString) -> Result<T, Self::IntoError>;
}

impl<T> ErrorContext<T> for Result<T, ParseIntError> {
    type IntoError = DocumentParseError;

    fn context(self, context: impl ToString) -> Result<T, Self::IntoError> {
        self.map_err(|_| DocumentParseError::InvalidInt {
            context: context.to_string(),
        })
    }
}
