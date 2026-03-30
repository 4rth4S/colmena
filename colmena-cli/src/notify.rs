use std::process::Command;

use colmena_core::config::{Action, NotificationsConfig};
use colmena_core::firewall::Priority;

/// Fire a non-blocking notification based on the decision.
/// Uses macOS `afplay` for sounds and optionally `say` for announcements.
pub fn notify(
    action: &Action,
    priority: &Priority,
    tool_name: &str,
    agent_id: Option<&str>,
    notifications: Option<&NotificationsConfig>,
) {
    let config = match notifications {
        Some(c) if c.enabled => c,
        _ => return,
    };

    let sound = match (action, priority) {
        (Action::AutoApprove, _) => return, // silent
        (Action::Ask, Priority::Low) => "/System/Library/Sounds/Glass.aiff",
        (Action::Ask, _) => "/System/Library/Sounds/Hero.aiff",
        (Action::Block, _) => "/System/Library/Sounds/Basso.aiff",
    };

    // Non-blocking sound — spawn and forget
    let _ = Command::new("afplay").arg(sound).spawn();

    // Optional say announcement
    if config.say_announcements {
        let agent = agent_id.unwrap_or("Agent");
        let verb = match action {
            Action::Ask => "needs approval for",
            Action::Block => "was blocked from",
            Action::AutoApprove => return,
        };
        let msg = format!("{agent} {verb} {tool_name}");
        let _ = Command::new("say").arg(&msg).spawn();
    }
}
