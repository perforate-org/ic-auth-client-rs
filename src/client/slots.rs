//! Every name a client writes under, in one place.
//!
//! Port of upstream `src/client/slots.ts`. The list exists once so that a name
//! cannot be added to some stores and missed in others, and so that a namespace
//! moves every name at once.

/// The bare slot names, before a namespace is applied.
pub const SLOT_SESSION: &str = "session";
/// Where a redirect ceremony keeps its key until it returns.
pub const SLOT_SESSION_PENDING: &str = "session-pending";
/// The key an application signs with, and its delegation.
pub const SLOT_APP: &str = "app";
/// Where a ceremony keeps the credential it minted until its session is stored.
pub const SLOT_APP_PENDING: &str = "app-pending";
/// The record of who is signed in here and until when.
pub const SLOT_STATE: &str = "ic-session-state";

/// What separates a namespace from the name it prefixes.
///
/// A cross-origin contract rather than a detail: a sibling subdomain reads the
/// state record by name, so both sides have to agree on this byte.
pub const NAMESPACE_SEPARATOR: char = ':';

/// Every name one client writes under, with its namespace already applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slots {
    /// The session's key and the chain issued to it.
    pub session: String,
    /// Where a sign-in ceremony keeps its key until it returns.
    pub session_pending: String,
    /// The key an application signs with, and its delegation.
    pub app: String,
    /// Where a ceremony keeps the credential it minted until its session is stored.
    pub app_pending: String,
    /// The record of who is signed in here and until when.
    pub state: String,
}

impl Slots {
    /// The names one client writes under, prefixed where a namespace is set.
    pub fn new(namespace: Option<&str>) -> Self {
        let prefix = match namespace {
            None | Some("") => String::new(),
            Some(namespace) => format!("{namespace}{NAMESPACE_SEPARATOR}"),
        };
        Self {
            session: format!("{prefix}{SLOT_SESSION}"),
            session_pending: format!("{prefix}{SLOT_SESSION_PENDING}"),
            app: format!("{prefix}{SLOT_APP}"),
            app_pending: format!("{prefix}{SLOT_APP_PENDING}"),
            state: format!("{prefix}{SLOT_STATE}"),
        }
    }
}

impl Default for Slots {
    fn default() -> Self {
        Self::new(None)
    }
}

/// The names one client writes under, prefixed where a namespace is set.
///
/// Kept as a free function as well, matching upstream's `slotsFor`.
pub fn slots_for(namespace: Option<&str>) -> Slots {
    Slots::new(namespace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_names() {
        let slots = slots_for(None);
        assert_eq!(slots.session, "session");
        assert_eq!(slots.session_pending, "session-pending");
        assert_eq!(slots.app, "app");
        assert_eq!(slots.app_pending, "app-pending");
        assert_eq!(slots.state, "ic-session-state");
    }

    #[test]
    fn namespace_prefixes_every_name() {
        let slots = slots_for(Some("notes"));
        assert_eq!(slots.session, "notes:session");
        assert_eq!(slots.session_pending, "notes:session-pending");
        assert_eq!(slots.app, "notes:app");
        assert_eq!(slots.app_pending, "notes:app-pending");
        assert_eq!(slots.state, "notes:ic-session-state");
    }

    #[test]
    fn empty_namespace_is_no_namespace() {
        assert_eq!(slots_for(Some("")), slots_for(None));
    }
}
