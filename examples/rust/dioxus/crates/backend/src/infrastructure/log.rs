use super::STATE;
use crate::log::Log;

/// Appends a log entry to the global log storage
///
/// # Arguments
/// * `log` - The log entry to append
///
/// # Returns
/// * `Result<u64, ()>` - The index where the log was appended or an error
///
/// # Example
/// ```
/// let log = Log::new(LogType::Info, "Test", "This is a test", "module", None, None);
/// match append(&log) {
///     Ok(idx) => ic_cdk::print(format!("Log added at index {}", idx)),
///     Err(_) => ic_cdk::print("Failed to add log"),
/// }
/// ```
pub fn append(log: &Log) -> Result<u64, ()> {
    STATE.with_borrow_mut(|state| match state.log.append(log) {
        Ok(idx) => Ok(idx),
        Err(e) => {
            ic_cdk::api::debug_print(format!("Error appending log: {:?}", e));
            Err(())
        }
    })
}
