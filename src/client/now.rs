//! Time on either platform.
//!
//! The daemon-free helper the client uses for expirations. Kept behind one
//! function so that the two targets agree on units (nanoseconds since the Unix
//! epoch, as `Delegation.expiration` uses).

/// Nanoseconds since the Unix epoch.
#[cfg(feature = "wasm-js")]
pub(crate) fn now_ns() -> u64 {
    // `Date::now()` is milliseconds as a float; nanoseconds since the epoch fit
    // in a `u64` until the year 2554.
    (web_sys::js_sys::Date::now() * 1_000_000.0) as u64
}

/// Nanoseconds since the Unix epoch.
#[cfg(all(not(feature = "wasm-js"), feature = "native"))]
pub(crate) fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0)
}
