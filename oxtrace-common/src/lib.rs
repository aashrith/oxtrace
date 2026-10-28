#![no_std]

/// Maximum number of plaintext bytes copied out of a single `SSL_read`/`SSL_write` call.
pub const MAX_CAPTURE: usize = 16384;

/// Plaintext handed to `SSL_write` (outbound).
pub const DIR_WRITE: u8 = 0;
/// Plaintext returned from `SSL_read` (inbound).
pub const DIR_READ: u8 = 1;

/// One TLS read or write, as seen in plaintext at the libssl boundary.
///
/// Shared between the eBPF programs and userspace, so the layout must stay `#[repr(C)]`
/// with explicit padding.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TlsEvent {
    /// `CLOCK_MONOTONIC` timestamp from `bpf_ktime_get_ns`.
    pub ts_ns: u64,
    /// The `SSL *` pointer. Stable for the lifetime of a TLS session within a process.
    pub conn: u64,
    pub pid: u32,
    pub tid: u32,
    /// Bytes actually read or written by the call.
    pub len: u32,
    /// Bytes copied into `data` (`min(len, MAX_CAPTURE)`, or 0 if the copy failed).
    pub captured: u32,
    pub direction: u8,
    pub comm: [u8; 16],
    pub _pad: [u8; 7],
    pub data: [u8; MAX_CAPTURE],
}
