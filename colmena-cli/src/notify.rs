use colmena_core::config::{Action, NotificationsConfig};
use colmena_core::firewall::Priority;

/// Notification hook — called after every firewall decision.
///
/// Currently a no-op placeholder. Sound/TTS notifications were removed
/// to keep the codebase OS-agnostic (previous implementation depended on
/// macOS-only commands). The `notifications.enabled` config flag is
/// preserved for future cross-platform notification support.
pub fn notify(
    _action: &Action,
    _priority: &Priority,
    _tool_name: &str,
    _agent_id: Option<&str>,
    _notifications: Option<&NotificationsConfig>,
) {
    // no-op — reserved for future cross-platform notification support
}
