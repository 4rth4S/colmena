/// Sanitize error messages by replacing absolute paths with generic placeholders.
/// Used by both CLI and MCP to avoid leaking internal filesystem paths.
pub fn sanitize_error(msg: &str) -> String {
    let re = regex::Regex::new(r"(/[A-Za-z][A-Za-z0-9._/-]+)").unwrap();
    re.replace_all(msg, "<path>").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_replaces_absolute_paths() {
        let msg = "Failed to read /Users/foo/bar/config.yaml";
        let sanitized = sanitize_error(msg);
        assert_eq!(sanitized, "Failed to read <path>");
        assert!(!sanitized.contains("/Users"));
    }

    #[test]
    fn test_sanitize_preserves_non_path_text() {
        let msg = "Something went wrong with value 42";
        assert_eq!(sanitize_error(msg), msg);
    }

    #[test]
    fn test_sanitize_multiple_paths() {
        let msg = "Cannot copy /src/a.rs to /dst/b.rs";
        let sanitized = sanitize_error(msg);
        assert_eq!(sanitized, "Cannot copy <path> to <path>");
    }
}
