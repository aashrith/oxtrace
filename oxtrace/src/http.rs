//! Minimal, allocation-light parsing of HTTP/1.x plaintext seen at the TLS boundary.
//!
//! We only ever see the first `MAX_CAPTURE` bytes of each read/write, so everything here is
//! best-effort and must tolerate truncated input.

const METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

/// JSON keys that carry prompt-side token counts across common LLM APIs
/// (Anthropic / OpenAI Responses, OpenAI Chat Completions, Gemini).
const INPUT_KEYS: &[&str] = &[
    "\"input_tokens\"",
    "\"prompt_tokens\"",
    "\"promptTokenCount\"",
];
/// JSON keys that carry completion-side token counts.
const OUTPUT_KEYS: &[&str] = &[
    "\"output_tokens\"",
    "\"completion_tokens\"",
    "\"candidatesTokenCount\"",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    /// Request target with the query string removed, to keep label cardinality sane.
    pub path: String,
    pub host: String,
}

/// Parses an HTTP/1.x request line and `Host` header from the start of a write.
pub fn parse_request(data: &[u8]) -> Option<Request> {
    let head = head(data);
    let mut lines = head.split("\r\n");
    let mut parts = lines.next()?.splitn(3, ' ');
    let method = parts.next()?;
    let target = parts.next()?;
    if !METHODS.contains(&method) || !parts.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let host = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.trim().to_owned())
        .unwrap_or_default();
    let path = target.split('?').next().unwrap_or(target);
    Some(Request {
        method: method.to_owned(),
        path: path.to_owned(),
        host,
    })
}

/// Parses the status code from an HTTP/1.x status line at the start of a read.
pub fn parse_status(data: &[u8]) -> Option<u16> {
    let rest = data.strip_prefix(b"HTTP/1.")?;
    let code = rest.get(2..5)?;
    std::str::from_utf8(code).ok()?.parse().ok()
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    pub input: Option<u64>,
    pub output: Option<u64>,
}

/// Finds LLM token usage counters in a chunk of a response body.
///
/// Streaming APIs report cumulative counts in several events, so the largest value seen wins.
pub fn scan_usage(data: &[u8]) -> Usage {
    Usage {
        input: max_value(data, INPUT_KEYS),
        output: max_value(data, OUTPUT_KEYS),
    }
}

fn max_value(data: &[u8], keys: &[&str]) -> Option<u64> {
    keys.iter()
        .flat_map(|key| find_all(data, key.as_bytes()).filter_map(|end| number_after(&data[end..])))
        .max()
}

/// Yields the index just past each occurrence of `needle`.
fn find_all<'a>(haystack: &'a [u8], needle: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    haystack
        .windows(needle.len())
        .enumerate()
        .filter(move |(_, window)| *window == needle)
        .map(move |(i, _)| i + needle.len())
}

/// Parses `\s*:\s*<digits>` at the start of `rest`.
fn number_after(rest: &[u8]) -> Option<u64> {
    let rest = rest
        .trim_ascii_start()
        .strip_prefix(b":")?
        .trim_ascii_start();
    let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    std::str::from_utf8(&rest[..digits]).ok()?.parse().ok()
}

/// The header block (everything before the blank line), lossily decoded.
fn head(data: &[u8]) -> &str {
    let end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(data.len());
    match std::str::from_utf8(&data[..end]) {
        Ok(s) => s,
        Err(e) => std::str::from_utf8(&data[..e.valid_up_to()]).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_request_line_and_host() {
        let req = parse_request(
            b"POST /v1/messages?beta=true HTTP/1.1\r\nhost: api.anthropic.com\r\ncontent-type: application/json\r\n\r\n{}",
        )
        .unwrap();
        assert_eq!(
            req,
            Request {
                method: "POST".into(),
                path: "/v1/messages".into(),
                host: "api.anthropic.com".into(),
            }
        );
    }

    #[test]
    fn rejects_non_http_writes() {
        assert_eq!(parse_request(b"{\"model\": \"x\"}"), None);
        assert_eq!(parse_request(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), None);
        assert_eq!(parse_request(b"HTTP/1.1 200 OK\r\n\r\n"), None);
    }

    #[test]
    fn parses_status() {
        assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(parse_status(b"HTTP/1.0 529 Overloaded\r\n"), Some(529));
        assert_eq!(parse_status(b"data: {}\n\n"), None);
        assert_eq!(parse_status(b"HTTP/1.1 2"), None);
    }

    #[test]
    fn scans_anthropic_usage() {
        let body =
            br#"{"usage":{"input_tokens":25,"cache_read_input_tokens":900,"output_tokens": 154}}"#;
        assert_eq!(
            scan_usage(body),
            Usage {
                input: Some(25),
                output: Some(154)
            }
        );
    }

    #[test]
    fn scans_openai_usage() {
        let body =
            br#"{"usage": {"prompt_tokens": 12, "completion_tokens": 7, "total_tokens": 19}}"#;
        assert_eq!(
            scan_usage(body),
            Usage {
                input: Some(12),
                output: Some(7)
            }
        );
    }

    #[test]
    fn takes_max_across_streaming_events() {
        let body = b"event: message_start\ndata: {\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}\n\n\
                     event: message_delta\ndata: {\"usage\":{\"output_tokens\":42}}\n\n";
        assert_eq!(
            scan_usage(body),
            Usage {
                input: Some(10),
                output: Some(42)
            }
        );
    }

    #[test]
    fn tolerates_truncation() {
        assert_eq!(scan_usage(b"{\"output_tokens\":"), Usage::default());
        assert_eq!(scan_usage(b""), Usage::default());
        assert!(parse_request(b"POST /v1/chat/completions HTTP/1.1\r\nHo").is_some());
    }
}
