# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-10-28

### Added

- Published on crates.io: `cargo install oxtrace` works with stable Rust alone. The crate
  ships precompiled eBPF programs for x86_64 and aarch64, so neither nightly nor bpf-linker
  is needed.

## [0.1.0] - 2026-10-28

### Added

- Uprobes on libssl `SSL_write`, `SSL_read`, `SSL_write_ex` and `SSL_read_ex` that capture
  TLS plaintext into a BPF ring buffer.
- HTTP/1.x exchange tracking per TLS session, with a line printed per completed exchange.
- LLM token usage extraction for Anthropic, OpenAI and Gemini-style responses, including
  streamed (SSE) responses.
- Prometheus/OpenMetrics endpoint: `oxtrace_http_requests_total`,
  `oxtrace_http_response_header_seconds`, `oxtrace_http_duration_seconds`,
  `oxtrace_llm_tokens_total`, `oxtrace_tls_bytes_total`.
- `--pid`, `--target`, `--metrics-addr`, `--idle-ms` and `--quiet` options.
- End-to-end test against a fake LLM API and CI on x86_64 and arm64 kernels.

[Unreleased]: https://github.com/aashrith/oxtrace/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/aashrith/oxtrace/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/aashrith/oxtrace/releases/tag/v0.1.0
