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

/// Content and transfer encoding flags parsed from a response's header block.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ResponseEncoding {
    pub gzip: bool,
    pub chunked: bool,
}

/// Parses encoding-related headers from the first response chunk.
/// Returns `None` if the header block isn't complete yet (no `\r\n\r\n`).
pub fn parse_response_encoding(data: &[u8]) -> Option<ResponseEncoding> {
    let hdr = head(data);
    if hdr.len() == data.len() && !data.windows(4).any(|w| w == b"\r\n\r\n") {
        return None;
    }
    let mut enc = ResponseEncoding::default();
    for line in hdr.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-encoding")
            && value.eq_ignore_ascii_case("gzip")
        {
            enc.gzip = true;
        }
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            enc.chunked = true;
        }
    }
    Some(enc)
}

/// Returns the body portion of `data` (everything after `\r\n\r\n`), or `None`.
pub fn body_after_headers(data: &[u8]) -> Option<&[u8]> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &data[i + 4..])
}

/// Removes HTTP/1.1 chunked transfer-encoding framing, returning the unchunked payload.
/// Best-effort: truncated chunks are included as-is.
pub fn dechunk(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut pos = 0;
    while pos < data.len() {
        let remaining = &data[pos..];
        let Some(crlf) = remaining.windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let size_str = match std::str::from_utf8(&remaining[..crlf]) {
            Ok(s) => s.trim(),
            Err(_) => break,
        };
        let chunk_len = match usize::from_str_radix(size_str, 16) {
            Ok(n) => n,
            Err(_) => break,
        };
        if chunk_len == 0 {
            break;
        }
        let chunk_start = pos + crlf + 2;
        let chunk_end = (chunk_start + chunk_len).min(data.len());
        out.extend_from_slice(&data[chunk_start..chunk_end]);
        // Skip past chunk data + trailing \r\n.
        pos = chunk_end + 2;
    }
    out
}

/// Decompresses gzip data, returning the plaintext. Returns an empty vec on error.
/// Bounded to `max_bytes` of output to limit memory usage.
pub fn decompress_gzip(data: &[u8], max_bytes: usize) -> Vec<u8> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut decoder = GzDecoder::new(data);
    let mut out = vec![0u8; max_bytes];
    let mut total = 0;
    loop {
        match decoder.read(&mut out[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => break,
        }
        if total >= max_bytes {
            break;
        }
    }
    out.truncate(total);
    out
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

    #[test]
    fn parses_gzip_content_encoding() {
        let resp = b"HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ncontent-type: application/json\r\n\r\n";
        let enc = parse_response_encoding(resp).unwrap();
        assert!(enc.gzip);
        assert!(!enc.chunked);
    }

    #[test]
    fn parses_chunked_transfer_encoding() {
        let resp = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n";
        let enc = parse_response_encoding(resp).unwrap();
        assert!(!enc.gzip);
        assert!(enc.chunked);
    }

    #[test]
    fn parses_gzip_and_chunked() {
        let resp = b"HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ntransfer-encoding: chunked\r\n\r\n";
        let enc = parse_response_encoding(resp).unwrap();
        assert!(enc.gzip);
        assert!(enc.chunked);
    }

    #[test]
    fn no_encoding_headers() {
        let resp = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n";
        let enc = parse_response_encoding(resp).unwrap();
        assert!(!enc.gzip);
        assert!(!enc.chunked);
    }

    #[test]
    fn incomplete_headers_returns_none() {
        let resp = b"HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\n";
        assert!(parse_response_encoding(resp).is_none());
    }

    #[test]
    fn body_after_headers_extracts_body() {
        let data = b"HTTP/1.1 200 OK\r\n\r\nhello";
        assert_eq!(body_after_headers(data), Some(b"hello".as_slice()));
    }

    #[test]
    fn dechunk_single_chunk() {
        let chunked = b"5\r\nhello\r\n0\r\n\r\n";
        assert_eq!(dechunk(chunked), b"hello");
    }

    #[test]
    fn dechunk_multiple_chunks() {
        let chunked = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(dechunk(chunked), b"hello world");
    }

    #[test]
    fn dechunk_truncated_input() {
        let chunked = b"ff\r\npartial";
        let result = dechunk(chunked);
        assert_eq!(result, b"partial");
    }

    #[test]
    fn decompress_gzip_roundtrip() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let original = br#"{"usage":{"input_tokens":25,"output_tokens":154}}"#;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();
        let decompressed = decompress_gzip(&compressed, 4096);
        assert_eq!(decompressed, original);
    }

    #[test]
    fn decompress_gzip_bounded() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let original = vec![b'x'; 8192];
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();
        let decompressed = decompress_gzip(&compressed, 1024);
        assert_eq!(decompressed.len(), 1024);
    }

    #[test]
    fn decompress_gzip_invalid_data() {
        let garbage = b"not gzip at all";
        let result = decompress_gzip(garbage, 4096);
        assert!(result.is_empty());
    }

    #[test]
    fn scan_usage_from_gzip_body() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let json = br#"{"usage":{"input_tokens":25,"output_tokens":154}}"#;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(json).unwrap();
        let compressed = encoder.finish().unwrap();
        let decompressed = decompress_gzip(&compressed, 65536);
        let usage = scan_usage(&decompressed);
        assert_eq!(
            usage,
            Usage {
                input: Some(25),
                output: Some(154)
            }
        );
    }

    #[test]
    fn dechunk_then_decompress_gzip() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let json = br#"{"usage":{"prompt_tokens":12,"completion_tokens":7}}"#;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(json).unwrap();
        let compressed = encoder.finish().unwrap();
        // Wrap in chunked framing.
        let mut chunked = format!("{:x}\r\n", compressed.len()).into_bytes();
        chunked.extend_from_slice(&compressed);
        chunked.extend_from_slice(b"\r\n0\r\n\r\n");
        let dechunked = dechunk(&chunked);
        let decompressed = decompress_gzip(&dechunked, 65536);
        let usage = scan_usage(&decompressed);
        assert_eq!(
            usage,
            Usage {
                input: Some(12),
                output: Some(7)
            }
        );
    }
}
