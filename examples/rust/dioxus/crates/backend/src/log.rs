#![allow(dead_code)]

use crate::infrastructure::log::append;
use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use ic_stable_structures::storable::{Bound, Storable};
use std::borrow::Cow;

/// Convenience function to create and append an info log
///
/// # Returns
/// * `Result<u64, ()>` - The index where the log was appended or an error
pub fn info(title: &str, content: &str, source: &str) -> Result<u64, ()> {
    let log = Log::new(LogType::Info, title, content, source, None, None);
    append(&log)
}

/// Convenience function to create and append a warning log
///
/// # Returns
/// * `Result<u64, ()>` - The index where the log was appended or an error
pub fn warning(title: &str, content: &str, source: &str) -> Result<u64, ()> {
    let log = Log::new(LogType::Warning, title, content, source, None, None);
    append(&log)
}

/// Convenience function to create and append an error log
///
/// # Returns
/// * `Result<u64, ()>` - The index where the log was appended or an error
pub fn error(title: &str, content: &str, source: &str) -> Result<u64, ()> {
    let log = Log::new(LogType::Error, title, content, source, None, None);
    append(&log)
}

/// Convenience function to create and append a debug log
///
/// # Returns
/// * `Result<u64, ()>` - The index where the log was appended or an error
pub fn debug(title: &str, content: &str, source: &str) -> Result<u64, ()> {
    let log = Log::new(LogType::Debug, title, content, source, None, None);
    append(&log)
}

/// Convenience function to create and append a critical log
///
/// # Returns
/// * `Result<u64, ()>` - The index where the log was appended or an error
pub fn critical(title: &str, content: &str, source: &str) -> Result<u64, ()> {
    let log = Log::new(LogType::Critical, title, content, source, None, None);
    append(&log)
}

/// Represents different severity levels for log entries
#[derive(Debug, Clone, Copy, PartialEq, Eq, CandidType, Deserialize, Hash)]
pub enum LogType {
    /// Informational messages
    Info,
    /// Warning messages indicating potential issues
    Warning,
    /// Error messages indicating failures
    Error,
    /// Debug messages for development purposes
    Debug,
    /// Critical messages indicating severe issues requiring immediate attention
    Critical,
}

/// Implements string representation for LogType enum values
impl std::fmt::Display for LogType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogType::Info => write!(f, "INFO"),
            LogType::Warning => write!(f, "WARNING"),
            LogType::Error => write!(f, "ERROR"),
            LogType::Debug => write!(f, "DEBUG"),
            LogType::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Represents a log entry in the system
#[derive(Debug, Clone, PartialEq, Eq, CandidType, Deserialize)]
pub struct Log {
    /// The severity level of the log
    pub log_type: LogType,
    /// Brief title/summary of the log entry
    pub title: String,
    /// Detailed message content of the log
    pub content: String,
    /// Timestamp when the log was created (in nanoseconds since 1970-01-01)
    pub timestamp: u64,
    /// Component or module that generated the log
    pub source: String,
    /// Optional principal ID of the user associated with this log entry
    pub user_principal: Option<Principal>,
    /// Optional additional structured or unstructured data
    pub metadata: Option<String>,
}

impl Log {
    /// Creates a new log entry with the current timestamp
    ///
    /// # Arguments
    /// * `log_type` - Severity level of the log
    /// * `title` - Brief title/summary
    /// * `content` - Detailed message
    /// * `source` - Component or module generating the log
    /// * `user_principal` - Optional user principal associated with the log
    /// * `metadata` - Optional additional data
    ///
    /// # Returns
    /// A new Log instance with the current timestamp
    pub fn new(
        log_type: LogType,
        title: &str,
        content: &str,
        source: &str,
        user_principal: Option<Principal>,
        metadata: Option<&str>,
    ) -> Self {
        use ic_cdk::api::time;
        Self {
            log_type,
            title: title.to_owned(),
            content: content.to_owned(),
            timestamp: time(),
            source: source.to_owned(),
            user_principal,
            metadata: metadata.map(|s| s.to_owned()),
        }
    }
}

impl Storable for Log {
    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
        match Encode!(self) {
            Ok(bytes) => Cow::Owned(bytes),
            Err(e) => panic!("Failed to encode Log: {:?}", e),
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        match Encode!(&self) {
            Ok(bytes) => bytes,
            Err(e) => panic!("Failed to encode Log: {:?}", e),
        }
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        match Decode!(bytes.as_ref(), Self) {
            Ok(log) => log,
            Err(e) => panic!("Failed to decode Log: {:?}", e),
        }
    }

    const BOUND: Bound = Bound::Unbounded;
}
