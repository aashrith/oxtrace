# Linux build/test environment for oxtrace. Useful on macOS, where eBPF can't be built or
# run natively; Docker Desktop's VM kernel supports uprobes, so `--privileged` runs work.
#
#   docker build -t oxtrace-dev dev/
#   docker run --rm -it --privileged -v "$PWD":/src oxtrace-dev cargo build --release
FROM rust:1-bookworm
ARG BPF_LINKER_VERSION=v0.12.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 zstd \
 && rm -rf /var/lib/apt/lists/* \
 && rustup toolchain install nightly --component rust-src \
 && rustup component add clippy rustfmt \
 && rustup component add --toolchain nightly rustfmt \
 && curl -fsSL "https://github.com/aya-rs/bpf-linker/releases/download/${BPF_LINKER_VERSION}/bpf-linker-$(uname -m)-unknown-linux-musl.tar.zst" \
    | tar --zstd -xpf - -C /usr/local/bin
WORKDIR /src
