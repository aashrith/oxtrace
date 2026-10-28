# oxtrace

[![CI](https://github.com/aashrith/oxtrace/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/aashrith/oxtrace/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/aashrith/oxtrace)](https://github.com/aashrith/oxtrace/releases/latest)
[![crates.io](https://img.shields.io/crates/v/oxtrace)](https://crates.io/crates/oxtrace)
[![License](https://img.shields.io/badge/license-MIT%20%7C%20Apache--2.0%20%7C%20GPL--2.0-blue)](#license)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange?logo=rust)](https://www.rust-lang.org)
[![Linux 5.8+](https://img.shields.io/badge/linux-5.8%2B-yellow?logo=linux&logoColor=white)](#quick-start)

**Zero-instrumentation observability powered by eBPF and Rust ([Aya](https://aya-rs.dev)).**

oxtrace attaches uprobes to libssl and reads TLS traffic *as plaintext, inside the kernel*,
before it is encrypted and after it is decrypted. That means you see every HTTPS call a
process makes, including LLM API calls with their latency and token usage, without
SDK wrappers, proxies, sidecars, certificates or code changes.

```console
$ sudo oxtrace
[INFO  oxtrace] attached 6 probes to libssl; metrics on http://127.0.0.1:9464/metrics
curl               17611 POST localhost:18443 /v1/messages -> 200     44.5ms  tokens in=25 out=154
curl               17613 POST localhost:18443 /v1/messages -> 200    307.8ms  tokens in=10 out=42
python3            17615 POST localhost:18443 /v1/chat/completions -> 200      0.7ms  tokens in=12 out=7
```

> Status: early (v0.1). Install from [GitHub releases](#quick-start) or
> [crates.io](https://crates.io/crates/oxtrace). The first use case is LLM API traffic; the goal is general-purpose,
> kernel-level tracing exported via OpenTelemetry. See the [roadmap](#roadmap).

## What you get

Prometheus/OpenMetrics on `--metrics-addr` (default `127.0.0.1:9464`):

| Metric | Labels | Meaning |
| --- | --- | --- |
| `oxtrace_http_requests_total` | `comm`, `host`, `method`, `path`, `status` | Completed HTTP/1.x exchanges over TLS |
| `oxtrace_http_response_header_seconds` | `comm`, `host`, `path` | Request write → response status line (time to first byte) |
| `oxtrace_http_duration_seconds` | `comm`, `host`, `path` | Request write → last response read (covers whole streams) |
| `oxtrace_llm_tokens_total` | `comm`, `host`, `kind` (`input`/`output`) | Token usage reported by Anthropic, OpenAI and Gemini-style APIs |
| `oxtrace_tls_bytes_total` | `comm`, `direction` | Plaintext bytes through libssl |

Token counts are taken from the `usage` fields in API responses, including streamed (SSE)
responses where counts arrive cumulatively.

oxtrace never prints or exports payloads. It parses them in memory and keeps only the
fields above.

## How it works

```
 your process                  kernel (eBPF)                    oxtrace (userspace)
 ────────────                  ─────────────                    ───────────────────
 SSL_write(buf) ──uprobe──▶  copy plaintext ─┐
 SSL_read(buf)  ──uretprobe▶ copy plaintext ─┼─▶ ring buffer ─▶ HTTP/1.x parser
                                             │                  usage scanner
 (also SSL_write_ex / SSL_read_ex)  ─────────┘                  exchange tracker ─▶ /metrics
```

* `oxtrace-ebpf`: `#![no_std]` Rust programs compiled to BPF bytecode. Writes are captured on
  entry; reads on return, using a per-thread map to remember the destination buffer.
* `oxtrace-common`: the `#[repr(C)]` event shared by both sides.
* `oxtrace`: loads the programs, drains the ring buffer, pairs requests with responses per
  TLS session (`SSL *`), and serves metrics.

## Quick start

Requirements: Linux 5.8+ (BPF ring buffer), root, and a process using OpenSSL's `libssl`
(curl, CPython, Ruby, PHP, most distro-packaged software).

Download a static binary for x86_64 or arm64 from the
[latest release](https://github.com/aashrith/oxtrace/releases/latest):

```sh
arch=$(uname -m)  # x86_64 or aarch64
curl -fsSL "https://github.com/aashrith/oxtrace/releases/latest/download/oxtrace-$arch-unknown-linux-musl.tar.gz" | tar -xz
sudo ./oxtrace-$arch-unknown-linux-musl/oxtrace
```

Or install from [crates.io](https://crates.io/crates/oxtrace) (stable Rust 1.88+ only; the
eBPF programs ship precompiled):

```sh
cargo install oxtrace
sudo ~/.cargo/bin/oxtrace
```

Or build from source:

```sh
rustup toolchain install nightly --component rust-src
# bpf-linker: see https://github.com/aya-rs/bpf-linker#installation
cargo build --release
sudo ./target/release/oxtrace
```

Options:

```
-p, --pid <PID>              Only trace this process
-t, --target <TARGET>        Library/binary with the OpenSSL API (default: libssl; repeatable)
    --metrics-addr <ADDR>    Prometheus/OpenMetrics address (default: 127.0.0.1:9464)
    --idle-ms <MS>           Finish an exchange after the response is idle this long (default: 2000)
-q, --quiet                  Don't print a line per exchange
```

### On macOS

eBPF is Linux-only, but Docker Desktop's VM kernel supports uprobes:

```sh
docker build -t oxtrace-dev dev/
docker run --rm -it --privileged -v "$PWD":/src oxtrace-dev cargo build --release
docker run --rm -it --privileged -v "$PWD":/src oxtrace-dev scripts/e2e.sh
```

## Current limitations

* **HTTP/1.x only** ([#10](https://github.com/aashrith/oxtrace/issues/10)). HTTP/2 (HPACK) is not parsed yet. Python
  `httpx`/`requests`, curl and Node's `fetch` default to HTTP/1.1 against LLM APIs.
* **OpenSSL API only** ([#12](https://github.com/aashrith/oxtrace/issues/12), [#13](https://github.com/aashrith/oxtrace/issues/13)). Go's `crypto/tls`, rustls and Java's JSSE
  aren't hooked yet. Binaries that statically link OpenSSL/BoringSSL with symbols can be
  targeted with `--target <path>`.
* **Compressed responses** ([#7](https://github.com/aashrith/oxtrace/issues/7)): token usage isn't extracted from gzip-encoded bodies.
* **16 KiB per read/write** ([#8](https://github.com/aashrith/oxtrace/issues/8)): usage at the end of a very large non-streamed
  response can be missed.
* **Runs as root** ([#14](https://github.com/aashrith/oxtrace/issues/14)). Processes are labeled by name; there's no
  container/Kubernetes awareness yet ([#11](https://github.com/aashrith/oxtrace/issues/11)).

## Roadmap

Progress is tracked in the pinned [roadmap issue](https://github.com/aashrith/oxtrace/issues/18). Highlights:

* OpenTelemetry (OTLP) export with GenAI semantic conventions: [#9](https://github.com/aashrith/oxtrace/issues/9)
* Per-model token labels and cost estimation: [#5](https://github.com/aashrith/oxtrace/issues/5), [#6](https://github.com/aashrith/oxtrace/issues/6)
* HTTP/2, gzip and large responses: [#10](https://github.com/aashrith/oxtrace/issues/10), [#7](https://github.com/aashrith/oxtrace/issues/7), [#8](https://github.com/aashrith/oxtrace/issues/8)
* Go `crypto/tls` and rustls: [#12](https://github.com/aashrith/oxtrace/issues/12), [#13](https://github.com/aashrith/oxtrace/issues/13)
* Containers, Kubernetes and Helm: [#11](https://github.com/aashrith/oxtrace/issues/11)
* Least-privilege operation, overhead benchmarks and older-kernel CI: [#14](https://github.com/aashrith/oxtrace/issues/14),
  [#15](https://github.com/aashrith/oxtrace/issues/15), [#16](https://github.com/aashrith/oxtrace/issues/16)

Have an idea? [Open a feature request](https://github.com/aashrith/oxtrace/issues/new/choose).

## Getting help and contributing

* Questions and ideas: [SUPPORT.md](SUPPORT.md)
* Contributing: [CONTRIBUTING.md](CONTRIBUTING.md). New here? Pick a
  [good first issue](https://github.com/aashrith/oxtrace/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22good%20first%20issue%22)
  or browse [help wanted](https://github.com/aashrith/oxtrace/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22help%20wanted%22).
* Please follow the [code of conduct](CODE_OF_CONDUCT.md).
* Security issues: [SECURITY.md](SECURITY.md)
* Release notes: [CHANGELOG.md](CHANGELOG.md)

## License

The userspace crate (`oxtrace`) is licensed under either of [Apache-2.0](LICENSE-APACHE) or
[MIT](LICENSE-MIT) at your option.

The eBPF programs (`oxtrace-ebpf`) and the shared types (`oxtrace-common`) are licensed under
either of [MIT](LICENSE-MIT) or [GPL-2.0](LICENSE-GPL2) at your option, because they are
loaded into the Linux kernel and use GPL-only helpers.
