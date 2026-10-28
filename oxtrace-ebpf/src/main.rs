#![no_std]
#![no_main]

//! Uprobes on libssl that copy TLS plaintext into a ring buffer.
//!
//! Writes are captured on entry, since the buffer is already filled. Reads are captured on
//! return: the entry probe stashes the destination buffer per thread, and the return probe
//! copies however many bytes the call actually produced.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user,
        bpf_probe_read_user_buf,
    },
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};
use oxtrace_common::{DIR_READ, DIR_WRITE, MAX_CAPTURE, TlsEvent};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(32 * 1024 * 1024, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct PendingRead {
    conn: u64,
    buf: u64,
    /// `size_t *readbytes` for `SSL_read_ex`; 0 for `SSL_read`.
    readbytes: u64,
}

/// In-flight reads keyed by `pid_tgid`, bridging entry and return probes.
#[map]
static PENDING_READS: HashMap<u64, PendingRead> = HashMap::with_max_entries(16384, 0);

// int SSL_write(SSL *ssl, const void *buf, int num)
#[uprobe]
pub fn ssl_write(ctx: ProbeContext) -> u32 {
    if let (Some(conn), Some(buf), Some(num)) =
        (ctx.arg::<u64>(0), ctx.arg::<u64>(1), ctx.arg::<i32>(2))
        && num > 0
    {
        emit(conn, buf, num as u32, DIR_WRITE);
    }
    0
}

// int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written)
#[uprobe]
pub fn ssl_write_ex(ctx: ProbeContext) -> u32 {
    if let (Some(conn), Some(buf), Some(num)) =
        (ctx.arg::<u64>(0), ctx.arg::<u64>(1), ctx.arg::<u64>(2))
        && num > 0
    {
        emit(conn, buf, num as u32, DIR_WRITE);
    }
    0
}

// int SSL_read(SSL *ssl, void *buf, int num)
#[uprobe]
pub fn ssl_read(ctx: ProbeContext) -> u32 {
    stash_read(&ctx, false);
    0
}

#[uretprobe]
pub fn ssl_read_ret(ctx: RetProbeContext) -> u32 {
    let ret: i32 = ctx.ret();
    if let Some(pending) = take_read()
        && ret > 0
    {
        emit(pending.conn, pending.buf, ret as u32, DIR_READ);
    }
    0
}

// int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes)
#[uprobe]
pub fn ssl_read_ex(ctx: ProbeContext) -> u32 {
    stash_read(&ctx, true);
    0
}

#[uretprobe]
pub fn ssl_read_ex_ret(ctx: RetProbeContext) -> u32 {
    let ret: i32 = ctx.ret();
    if let Some(pending) = take_read()
        && ret == 1
        && let Ok(n) = unsafe { bpf_probe_read_user(pending.readbytes as *const u64) }
        && n > 0
    {
        emit(pending.conn, pending.buf, n as u32, DIR_READ);
    }
    0
}

fn stash_read(ctx: &ProbeContext, ex: bool) {
    let (Some(conn), Some(buf)) = (ctx.arg::<u64>(0), ctx.arg::<u64>(1)) else {
        return;
    };
    let readbytes = if ex {
        ctx.arg::<u64>(3).unwrap_or(0)
    } else {
        0
    };
    let pending = PendingRead {
        conn,
        buf,
        readbytes,
    };
    let _ = PENDING_READS.insert(bpf_get_current_pid_tgid(), pending, 0);
}

fn take_read() -> Option<PendingRead> {
    let key = bpf_get_current_pid_tgid();
    let pending = unsafe { PENDING_READS.get(key) }.copied();
    let _ = PENDING_READS.remove(key);
    pending
}

fn emit(conn: u64, buf: u64, len: u32, direction: u8) {
    let Some(mut entry) = EVENTS.reserve::<TlsEvent>(0) else {
        return;
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let captured = if (len as usize) < MAX_CAPTURE {
        len as usize
    } else {
        MAX_CAPTURE
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).ts_ns = bpf_ktime_get_ns();
        (*ev).conn = conn;
        (*ev).pid = (pid_tgid >> 32) as u32;
        (*ev).tid = pid_tgid as u32;
        (*ev).len = len;
        (*ev).direction = direction;
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
        let data = &mut (&mut (*ev).data)[..captured];
        (*ev).captured = match bpf_probe_read_user_buf(buf as *const u8, data) {
            Ok(()) => captured as u32,
            Err(_) => 0,
        };
    }
    entry.submit(0);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
