# Contributing to oxtrace

Thanks for your interest! Bug reports, ideas, docs fixes and pull requests are all welcome,
and you don't need to be an eBPF expert. Many useful changes are pure userspace Rust.

Everyone taking part is expected to follow the [code of conduct](CODE_OF_CONDUCT.md).

## Asking questions and reporting issues

* **Questions and ideas:** see [SUPPORT.md](SUPPORT.md).
* **Bugs:** open an issue using the bug report template. Include `uname -r`, your distro,
  architecture, OpenSSL version and the client you were tracing. Most eBPF bugs are
  kernel- or library-specific, so these details matter.
* **Feature requests:** open an issue using the feature request template. For anything
  large (a new probe type, a new exporter, a new protocol), please open an issue to agree on
  the approach before writing code.
* **Security vulnerabilities:** never in public issues. See [SECURITY.md](SECURITY.md).

## Development setup

On Linux:

```sh
rustup toolchain install nightly --component rust-src
# bpf-linker: https://github.com/aya-rs/bpf-linker#installation
cargo build --release
```

On macOS, use the dev container (eBPF cannot be built or run natively):

```sh
docker build -t oxtrace-dev dev/
docker run --rm -it --privileged -v "$PWD":/src oxtrace-dev bash
```

`cargo run` uses `sudo -E` as its runner (see `.cargo/config.toml`), because loading eBPF
programs needs privileges.

## Layout

* `oxtrace-ebpf/`: kernel-side programs (`#![no_std]`, built for `bpfel-unknown-none`)
* `oxtrace-common/`: types shared between kernel and userspace
* `oxtrace/`: userspace loader, parsers and metrics
* `scripts/`: end-to-end test and a fake LLM API server

## Making a change

1. Fork the repository and create a branch from `main` (e.g. `fix/sse-usage-parsing`,
   `feat/otlp-export`). Maintainers may push branches to this repository directly; the same
   PR process applies.
2. Make your change, with tests (see below).
3. Open a pull request against `main` and fill in the template. Draft PRs are welcome for
   early feedback.
4. A maintainer will review, usually within a week. Expect questions; review is a
   conversation, not a verdict.
5. Once approved and CI is green, a maintainer merges with **squash and merge**, so your PR
   title becomes the commit message.

### Conventions

* **Code style:** `rustfmt` (nightly, configured in `rustfmt.toml`) and `clippy` with no
  warnings. Match the surrounding code's naming and comment density.
* **Commits and PR titles:** imperative mood, short summary line (e.g. "Parse usage from
  gzip-encoded responses"). Explain *why* in the body if it isn't obvious.
* **Kernel side:** keep it small. Do parsing and aggregation in userspace. Every byte copied
  in the probe is paid on every TLS call of every traced process.
* **Privacy:** never log or export payload contents. oxtrace sees plaintext secrets (API keys,
  prompts), so only derived fields may leave the process.

### Definition of done

A change is ready to merge when:

- [ ] `cargo +nightly fmt --all` and `cargo clippy --all-targets -- -D warnings` are clean
- [ ] `cargo test --config 'target."cfg(all())".runner="env"'` passes
- [ ] `sudo scripts/e2e.sh` passes locally (or in the dev container) for anything touching
      probes, parsing or metrics, and new behavior is covered by a unit test or an e2e check
- [ ] Probe changes don't add significant per-call overhead (mention any measurements)
- [ ] User-visible changes (flags, metrics, labels) are reflected in the README
- [ ] CI is green on all kernels and architectures

### After your change is merged

You aren't on the hook for maintaining it, but if a regression is traced back to your change
we may ping you on the issue. Help is appreciated, never required. Contributors are listed in
[CONTRIBUTORS.md](CONTRIBUTORS.md); add yourself in your PR if you like.

## Releasing (maintainers)

1. In a PR, bump `workspace.package.version` and the `oxtrace-common` dependency version in
   the root `Cargo.toml`, and move the `[Unreleased]` notes in `CHANGELOG.md` under the new
   version.
2. After it merges, tag `main` and push the tag:

   ```sh
   git tag -a v0.2.0 -m v0.2.0 && git push origin v0.2.0
   ```

The release workflow checks that the tag matches the crate version, builds static binaries
for x86_64 and arm64, runs the end-to-end test against them, and publishes a GitHub release
with checksums and notes taken from `CHANGELOG.md`. It also publishes `oxtrace-common` and
`oxtrace` to crates.io, including the precompiled eBPF objects.

## Licensing

By contributing, you agree that your contributions will be licensed under the same terms as
the crate you are changing (see the README).
