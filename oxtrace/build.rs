use std::{env, fs, path::PathBuf};

use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let Some(ebpf_package) = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "oxtrace-ebpf")
    else {
        return use_prebuilt();
    };
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}

/// Building outside the workspace (e.g. `cargo install oxtrace` from crates.io), where the
/// eBPF sources aren't available: use the object the release workflow compiled for this
/// architecture and packaged with the crate. This also spares users a nightly toolchain and
/// bpf-linker.
fn use_prebuilt() -> anyhow::Result<()> {
    let arch = env::var("CARGO_CFG_TARGET_ARCH")?;
    let src = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?)
        .join("bpf")
        .join(format!("oxtrace-{arch}.o"));
    let dst = PathBuf::from(env::var("OUT_DIR")?).join("oxtrace");
    println!("cargo::rerun-if-changed={}", src.display());
    fs::copy(&src, &dst).with_context(|| {
        format!(
            "no prebuilt eBPF object for {arch} at {}; build from a git checkout instead",
            src.display()
        )
    })?;
    Ok(())
}
