use std::{collections::HashMap, sync::Arc};

use oxtrace_common::{DIR_READ, DIR_WRITE, TlsEvent};

use crate::{
    http::{self, Request},
    metrics::{EndpointLabels, Metrics, RequestLabels, TlsLabels, TokenLabels},
};

/// A request/response pair in flight on one TLS session.
struct Exchange {
    pid: u32,
    comm: String,
    req: Request,
    started_ns: u64,
    last_ns: u64,
    status: Option<u16>,
    input_tokens: u64,
    output_tokens: u64,
}

/// Turns raw TLS events into HTTP exchanges and metrics.
pub struct Tracker {
    metrics: Arc<Metrics>,
    /// Keyed by `(pid, SSL *)`: the pointer is only unique within a process.
    exchanges: HashMap<(u32, u64), Exchange>,
    comms: HashMap<u32, String>,
    print: bool,
}

impl Tracker {
    pub fn new(metrics: Arc<Metrics>, print: bool) -> Self {
        Self {
            metrics,
            exchanges: HashMap::new(),
            comms: HashMap::new(),
            print,
        }
    }

    pub fn on_event(&mut self, ev: &TlsEvent) {
        let data = &ev.data[..(ev.captured as usize).min(ev.data.len())];
        let key = (ev.pid, ev.conn);
        let comm = self.process_name(ev);
        let direction = if ev.direction == DIR_WRITE {
            "write"
        } else {
            "read"
        };
        self.metrics
            .tls_bytes
            .get_or_create(&TlsLabels {
                comm: comm.clone(),
                direction,
            })
            .inc_by(ev.len.into());

        match ev.direction {
            DIR_WRITE => {
                // Anything that isn't a request line is a body continuation; ignore it.
                let Some(req) = http::parse_request(data) else {
                    return;
                };
                if let Some(prev) = self.exchanges.remove(&key) {
                    self.finish(prev);
                }
                self.exchanges.insert(
                    key,
                    Exchange {
                        pid: ev.pid,
                        comm,
                        req,
                        started_ns: ev.ts_ns,
                        last_ns: ev.ts_ns,
                        status: None,
                        input_tokens: 0,
                        output_tokens: 0,
                    },
                );
            }
            DIR_READ => {
                let Some(ex) = self.exchanges.get_mut(&key) else {
                    return;
                };
                ex.last_ns = ev.ts_ns;
                if ex.status.is_none()
                    && let Some(status) = http::parse_status(data)
                {
                    ex.status = Some(status);
                    self.metrics
                        .response_header
                        .get_or_create(&endpoint(ex))
                        .observe(seconds(ev.ts_ns - ex.started_ns));
                }
                let usage = http::scan_usage(data);
                // Counters are cumulative, so record only the growth since the last chunk.
                for (seen, total, kind) in [
                    (usage.input, &mut ex.input_tokens, "input"),
                    (usage.output, &mut ex.output_tokens, "output"),
                ] {
                    if let Some(n) = seen
                        && n > *total
                    {
                        self.metrics
                            .tokens
                            .get_or_create(&TokenLabels {
                                comm: ex.comm.clone(),
                                host: ex.req.host.clone(),
                                kind,
                            })
                            .inc_by(n - *total);
                        *total = n;
                    }
                }
            }
            _ => {}
        }
    }

    /// Finishes exchanges whose response has gone quiet, and drops ones that never got one.
    pub fn sweep(&mut self, now_ns: u64, idle_ns: u64) {
        const ABANDON_NS: u64 = 300 * 1_000_000_000;
        let expired: Vec<_> = self
            .exchanges
            .iter()
            .filter(|(_, ex)| match ex.status {
                Some(_) => now_ns.saturating_sub(ex.last_ns) > idle_ns,
                None => now_ns.saturating_sub(ex.started_ns) > ABANDON_NS,
            })
            .map(|(key, _)| *key)
            .collect();
        for key in expired {
            if let Some(ex) = self.exchanges.remove(&key) {
                self.finish(ex);
            }
        }
        if self.comms.len() > 4096 {
            self.comms.clear();
        }
    }

    fn finish(&self, ex: Exchange) {
        let Some(status) = ex.status else {
            return;
        };
        let elapsed = seconds(ex.last_ns - ex.started_ns);
        self.metrics
            .requests
            .get_or_create(&RequestLabels {
                comm: ex.comm.clone(),
                host: ex.req.host.clone(),
                method: ex.req.method.clone(),
                path: ex.req.path.clone(),
                status,
            })
            .inc();
        self.metrics
            .duration
            .get_or_create(&endpoint(&ex))
            .observe(elapsed);
        if self.print {
            let tokens = if ex.input_tokens + ex.output_tokens > 0 {
                format!("  tokens in={} out={}", ex.input_tokens, ex.output_tokens)
            } else {
                String::new()
            };
            println!(
                "{:<16} {:>7} {} {} {} -> {} {:>8.1}ms{}",
                ex.comm,
                ex.pid,
                ex.req.method,
                ex.req.host,
                ex.req.path,
                status,
                elapsed * 1e3,
                tokens
            );
        }
    }

    /// Process name from `/proc`, since the event's `comm` is the *thread* name
    /// (e.g. `tokio-runtime-w`), which makes for poor labels.
    fn process_name(&mut self, ev: &TlsEvent) -> String {
        self.comms
            .entry(ev.pid)
            .or_insert_with(|| {
                std::fs::read_to_string(format!("/proc/{}/comm", ev.pid))
                    .map(|s| s.trim_end().to_owned())
                    .unwrap_or_else(|_| {
                        let len = ev
                            .comm
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(ev.comm.len());
                        String::from_utf8_lossy(&ev.comm[..len]).into_owned()
                    })
            })
            .clone()
    }
}

fn endpoint(ex: &Exchange) -> EndpointLabels {
    EndpointLabels {
        comm: ex.comm.clone(),
        host: ex.req.host.clone(),
        path: ex.req.path.clone(),
    }
}

fn seconds(ns: u64) -> f64 {
    ns as f64 / 1e9
}
