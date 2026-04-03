use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Simple token-bucket rate limiter per tool name.
/// Resets the counter when the window expires.
pub struct RateLimiter {
    state: Mutex<HashMap<String, (Instant, u32)>>,
    max_calls: u32,
    window_secs: u64,
}

impl RateLimiter {
    pub fn new(max_calls: u32, window_secs: u64) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            max_calls,
            window_secs,
        }
    }

    /// Check if a call is allowed for the given tool. Returns Ok(()) if allowed,
    /// Err(message) if rate limited.
    pub fn check(&self, tool_name: &str) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();

        let entry = state.entry(tool_name.to_string()).or_insert((now, 0));

        // Reset window if expired
        if now.duration_since(entry.0).as_secs() >= self.window_secs {
            *entry = (now, 0);
        }

        entry.1 += 1;

        if entry.1 > self.max_calls {
            Err(format!(
                "Rate limit exceeded for '{}': max {} calls per {}s window",
                tool_name, self.max_calls, self.window_secs
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allows_within_limit() {
        let limiter = RateLimiter::new(3, 60);
        assert!(limiter.check("tool_a").is_ok());
        assert!(limiter.check("tool_a").is_ok());
        assert!(limiter.check("tool_a").is_ok());
    }

    #[test]
    fn test_rejects_over_limit() {
        let limiter = RateLimiter::new(2, 60);
        assert!(limiter.check("tool_b").is_ok());
        assert!(limiter.check("tool_b").is_ok());
        assert!(limiter.check("tool_b").is_err());
    }

    #[test]
    fn test_independent_tool_buckets() {
        let limiter = RateLimiter::new(1, 60);
        assert!(limiter.check("tool_x").is_ok());
        assert!(limiter.check("tool_y").is_ok());
        assert!(limiter.check("tool_x").is_err());
        assert!(limiter.check("tool_y").is_err());
    }

    #[test]
    fn test_window_reset() {
        // Use a 0-second window so it resets immediately
        let limiter = RateLimiter::new(1, 0);
        assert!(limiter.check("tool_c").is_ok());
        // Window is 0 seconds, so next check resets the counter
        assert!(limiter.check("tool_c").is_ok());
    }
}
