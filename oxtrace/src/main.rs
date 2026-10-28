mod http;
mod metrics;
mod tracker;

use std::{net::SocketAddr, num::NonZeroU32, sync::Arc, time::Duration};

use anyhow::{Context as _, bail};
use aya::{
    maps::RingBuf,
    programs::{UProbe, uprobe::UProbeScope},
};
use clap::Parser;
use log::{debug, info, warn};
use oxtrace_common::TlsEvent;
use tokio::{
    io::{Interest, unix::AsyncFd},
    signal,
};

use crate::{metrics::Metrics, tracker::Tracker};

/// (eBPF program, libssl symbol) pairs. Read probes come in entry/return pairs.
const PROBES: &[(&str, &str)] = &[
    ("ssl_write", "SSL_write"),
    ("ssl_write_ex", "SSL_write_ex"),
    ("ssl_read", "SSL_read"),
    ("ssl_read_ret", "SSL_read"),
    ("ssl_read_ex", "SSL_read_ex"),
    ("ssl_read_ex_ret", "SSL_read_ex"),
];

/// Zero-instrumentation tracing of HTTPS traffic, including LLM API calls, via eBPF.
#[derive(Debug, Parser)]
#[command(version)]
struct Opt {
    /// Only trace this process.
    #[arg(short, long)]
    pid: Option<u32>,

    /// Library or binary that contains the OpenSSL API. Bare names such as `libssl` are
    /// resolved via the linker cache. Repeat for binaries with statically linked TLS.
    #[arg(short, long = "target", default_value = "libssl")]
    targets: Vec<String>,

    /// Address to serve Prometheus/OpenMetrics on.
    #[arg(long, default_value = "127.0.0.1:9464")]
    metrics_addr: SocketAddr,

    /// Finish an exchange once its response has been idle this long, in milliseconds.
    #[arg(long, default_value_t = 2000)]
    idle_ms: u64,

    /// Don't print a line per completed exchange.
    #[arg(short, long)]
    quiet: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/oxtrace"
    )))?;

    let scope = match opt.pid.map(NonZeroU32::new) {
        Some(Some(pid)) => UProbeScope::OneProcess(pid),
        Some(None) => UProbeScope::CallingProcess,
        None => UProbeScope::AllProcesses,
    };
    let mut attached = 0;
    for (prog, symbol) in PROBES {
        let program: &mut UProbe = ebpf
            .program_mut(prog)
            .with_context(|| format!("program {prog} not found"))?
            .try_into()?;
        program.load()?;
        for target in &opt.targets {
            // Not every TLS library exports every symbol (e.g. the `_ex` variants).
            match program.attach(*symbol, target.as_str(), scope) {
                Ok(_) => attached += 1,
                Err(e) => warn!("{prog}: could not attach to {symbol} in {target}: {e}"),
            }
        }
    }
    if attached == 0 {
        bail!("no probes attached; is OpenSSL installed? try --target <path>");
    }

    let metrics = Arc::new(Metrics::new());
    tokio::spawn({
        let metrics = metrics.clone();
        let addr = opt.metrics_addr;
        async move {
            if let Err(e) = metrics::serve(addr, metrics).await {
                warn!("metrics server on {addr} failed: {e}");
            }
        }
    });
    info!(
        "attached {attached} probes to {}; metrics on http://{}/metrics",
        opt.targets.join(", "),
        opt.metrics_addr
    );

    let ring = RingBuf::try_from(ebpf.take_map("EVENTS").context("EVENTS map not found")?)?;
    // SAFETY: the RingBuf owns its map fd, which stays open and unchanged while the AsyncFd
    // owns it.
    let mut ring = unsafe { AsyncFd::register_with_interest(ring, Interest::READABLE) }?;
    let mut tracker = Tracker::new(metrics, !opt.quiet);
    let mut sweep = tokio::time::interval(Duration::from_millis(500));
    let idle_ns = opt.idle_ms * 1_000_000;
    let ctrl_c = signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            res = &mut ctrl_c => {
                res?;
                break;
            }
            guard = ring.readable_mut() => {
                let mut guard = guard?;
                let ring = guard.get_inner_mut();
                while let Some(item) = ring.next() {
                    if item.len() < size_of::<TlsEvent>() {
                        continue;
                    }
                    // SAFETY: the kernel side reserves exactly one `TlsEvent` per record.
                    let ev = unsafe { &*item.as_ptr().cast::<TlsEvent>() };
                    tracker.on_event(ev);
                }
                guard.clear_ready();
            }
            _ = sweep.tick() => tracker.sweep(monotonic_ns(), idle_ns),
        }
    }
    tracker.sweep(u64::MAX, 0);
    Ok(())
}

/// `CLOCK_MONOTONIC`, the same clock as `bpf_ktime_get_ns`.
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}
