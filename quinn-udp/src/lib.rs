//! Uniform interface to send and receive UDP packets with advanced features useful for QUIC
//!
//! This crate exposes kernel UDP stack features available on most modern systems which are required
//! for an efficient and conformant QUIC implementation. As of this writing, these are not available
//! in std or major async runtimes, and their niche character and complexity are a barrier to adding
//! them. Hence, a dedicated crate.
//!
//! Exposed features include:
//!
//! - Segmentation offload for bulk send and receive operations, reducing CPU load.
//! - Reporting the exact destination address of received packets and specifying explicit source
//!   addresses for sent packets, allowing responses to be sent from the address that the peer
//!   expects when there are multiple possibilities. This is common when bound to a wildcard address
//!   in IPv6 due to [RFC 8981] temporary addresses.
//! - [Explicit Congestion Notification], which is required by QUIC to prevent packet loss and reduce
//!   latency on congested links when supported by the network path.
//! - Disabled IP-layer fragmentation, which allows the true physical MTU to be detected and reduces
//!   risk of QUIC packet loss.
//!
//! Some features are unavailable in some environments. This can be due to an outdated operating
//! system or drivers. Some operating systems may not implement desired features at all, or may not
//! yet be supported by the crate. When support is unavailable, functionality will gracefully
//! degrade.
//!
//! [RFC 8981]: https://www.rfc-editor.org/rfc/rfc8981.html
//! [Explicit Congestion Notification]: https://www.rfc-editor.org/rfc/rfc3168.html
#![warn(unreachable_pub)]
#![warn(clippy::use_self)]

use core::time::Duration;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
#[cfg(unix)]
use std::os::unix::io::AsFd;
#[cfg(windows)]
use std::os::windows::io::AsSocket;
#[cfg(not(wasm_browser))]
use std::{sync::Mutex, time::Instant};

#[cfg(apple_fast)]
mod apple_fast;

#[cfg(any(unix, windows))]
mod cmsg;

#[cfg(unix)]
#[path = "unix.rs"]
mod imp;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;

#[cfg(windows)]
#[path = "windows.rs"]
mod imp;

// No ECN support
#[cfg(not(any(wasm_browser, unix, windows)))]
#[path = "fallback.rs"]
mod imp;

#[allow(unused_imports, unused_macros)]
mod log {
    #[cfg(all(feature = "log", not(feature = "tracing-log")))]
    pub(crate) use log::{debug, error, info, trace, warn};

    #[cfg(feature = "tracing-log")]
    pub(crate) use tracing::{debug, error, info, trace, warn};

    #[cfg(not(any(feature = "log", feature = "tracing-log")))]
    mod no_op {
        macro_rules! trace    ( ($($tt:tt)*) => {{}} );
        macro_rules! debug    ( ($($tt:tt)*) => {{}} );
        macro_rules! info     ( ($($tt:tt)*) => {{}} );
        macro_rules! log_warn ( ($($tt:tt)*) => {{}} );
        macro_rules! error    ( ($($tt:tt)*) => {{}} );

        pub(crate) use {debug, error, info, log_warn as warn, trace};
    }

    #[cfg(not(any(feature = "log", feature = "tracing-log")))]
    pub(crate) use no_op::*;
}

#[cfg(not(wasm_browser))]
pub use imp::UdpSocketState;

/// Number of UDP packets to send/receive at a time
#[cfg(not(wasm_browser))]
pub const BATCH_SIZE: usize = imp::BATCH_SIZE;
/// Number of UDP packets to send/receive at a time
#[cfg(wasm_browser)]
pub const BATCH_SIZE: usize = 1;

/// Metadata for a single buffer filled with bytes received from the network
///
/// This associated buffer can contain one or more datagrams, see [`stride`].
///
/// [`stride`]: RecvMeta::stride
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub struct RecvMeta {
    /// The source address of the datagram(s) contained in the buffer
    pub addr: SocketAddr,
    /// The number of bytes the associated buffer has
    pub len: usize,
    /// The size of a single datagram in the associated buffer
    ///
    /// When GRO (Generic Receive Offload) is used this indicates the size of a single
    /// datagram inside the buffer. If the buffer is larger, that is if [`len`] is greater
    /// then this value, then the individual datagrams contained have their boundaries at
    /// `stride` increments from the start. The last datagram could be smaller than
    /// `stride`.
    ///
    /// [`len`]: RecvMeta::len
    pub stride: usize,
    /// The Explicit Congestion Notification bits for the datagram(s) in the buffer
    pub ecn: Option<EcnCodepoint>,
    /// The destination IP address which was encoded in this datagram
    ///
    /// Populated on platforms: Windows, Linux, Android (API level > 25),
    /// FreeBSD, OpenBSD, NetBSD, macOS, and iOS.
    pub dst_ip: Option<IpAddr>,
    /// The interface index of the interface on which the datagram was received
    pub interface_index: Option<u32>,
    /// Kernel receive timestamp as Unix epoch
    ///
    /// Populated on platforms: Linux, Android.
    pub timestamp: Option<Duration>,
}

impl Default for RecvMeta {
    /// Constructs a value with arbitrary fields, intended to be overwritten
    fn default() -> Self {
        Self {
            addr: SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
            len: 0,
            stride: 0,
            ecn: None,
            dst_ip: None,
            interface_index: None,
            timestamp: None,
        }
    }
}

/// An outgoing packet
#[derive(Debug, Clone)]
pub struct Transmit<'a> {
    /// The socket this datagram should be sent to
    pub destination: SocketAddr,
    /// Explicit congestion notification bits to set on the packet
    pub ecn: Option<EcnCodepoint>,
    /// Contents of the datagram
    pub contents: &'a [u8],
    /// The segment size if this transmission contains multiple datagrams.
    /// This is `None` if the transmit only contains a single datagram
    pub segment_size: Option<usize>,
    /// Optional source IP address for the datagram
    pub src_ip: Option<IpAddr>,
}

impl Transmit<'_> {
    /// Computes the effective segment-size of the packet.
    ///
    /// Some (older) network drivers don't like being told to do GSO even if
    /// there is effectively only a single segment.
    /// (i.e. `segment_size == contents.len()`)
    /// Additionally, a `segment_size` that is greater than the content also
    /// means there is effectively only a single segment.
    /// This case is actually quite common when splitting up a prepared GSO batch
    /// again after GSO has been disabled because the last datagram in a GSO
    /// batch is allowed to be smaller than the segment size.
    #[cfg_attr(apple_fast, allow(dead_code))] // Used by prepare_msg, which is unused when apple_fast
    fn effective_segment_size(&self) -> Option<usize> {
        match self.segment_size? {
            size if size >= self.contents.len() => None,
            size => Some(size),
        }
    }
}

/// Slice a `Transmit` into batches that each fit one backend syscall, and
/// dispatch them via [`UdpSocketState::send_batch`].
///
/// A `Transmit` can carry more than one syscall accepts — more segments than
/// the GSO/batch budget ([`max_gso_segments`]) or more than the kernel's
/// `u16::MAX`-per-call byte limit. Each backend mishandles that differently
/// (Linux: `EMSGSIZE`/`EIO`; the Apple `sendmsg_x` batch: silently truncated to
/// `BATCH_SIZE`; Windows: an IO error), so the slicing happens here — above the
/// backend, where the arithmetic is identical — rather than in each one.
///
/// On a multi-segment failure that the backend recognizes as "GSO isn't usable
/// on this path" ([`try_halt_gso`], Linux/Android only), GSO is halted and the
/// same offset retried as single-segment datagrams.
///
/// [`max_gso_segments`]: UdpSocketState::max_gso_segments
/// [`try_halt_gso`]: UdpSocketState::try_halt_gso
#[cfg(not(wasm_browser))]
fn send_sliced(
    state: &UdpSocketState,
    socket: UdpSockRef<'_>,
    transmit: &Transmit<'_>,
) -> std::io::Result<()> {
    let segment_size = transmit.segment_size.unwrap_or(transmit.contents.len());
    let mut max_bytes =
        max_batch_bytes(state.max_gso_segments(), segment_size, transmit.destination);

    let mut pos = 0;
    while pos < transmit.contents.len() {
        let remaining = transmit.contents.len() - pos;
        let batch_end = pos + next_batch_bytes(remaining, max_bytes, segment_size);
        let batch = Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &transmit.contents[pos..batch_end],
            // Keep `segment_size`: each backend elides the GSO cmsg when a batch
            // holds one segment or less.
            segment_size: transmit.segment_size,
            src_ip: transmit.src_ip,
        };
        match state.send_batch(&socket, &batch) {
            Ok(()) => pos = batch_end,
            // Only a multi-segment batch (`max_bytes > segment_size`) can blame
            // GSO. If the backend halts it (dropping the budget to 1), retry the
            // same offset as single-segment datagrams.
            Err(e) if max_bytes > segment_size && state.try_halt_gso(&e) => {
                max_bytes = segment_size;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Maximum UDP payload bytes packable into one backend syscall.
///
/// Two upper bounds:
///   * `u16::MAX - ip_udp_header_overhead`: the kernel builds one IP packet per
///     `sendmsg` whose 16-bit total-length field caps header + payload at
///     `u16::MAX`. IPv4 headers can include up to 40 bytes of options (60 total);
///     IPv6's fixed header is 40; UDP is 8.
///   * `max_gso_segments * segment_size`: the GSO/batch budget — the kernel
///     rejects more than `UDP_MAX_SEGMENTS` segments and the Apple `sendmsg_x`
///     array holds at most `BATCH_SIZE`.
///
/// The batch may end with a partial segment, so a transmit whose total byte
/// length is at most `max_batch_bytes` ships in a single syscall even when
/// `contents.len() / segment_size` exceeds the segment budget by one partial
/// segment.
#[cfg(not(wasm_browser))]
fn max_batch_bytes(max_gso_segments: usize, segment_size: usize, destination: SocketAddr) -> usize {
    let header_overhead = match destination {
        SocketAddr::V4(_) => 60 + 8,
        SocketAddr::V6(_) => 40 + 8,
    };
    let max_payload = (u16::MAX as usize) - header_overhead;
    max_payload.min(max_gso_segments * segment_size)
}

/// Number of bytes to send in the next syscall, given `remaining` bytes left in
/// the transmit and a per-call budget of `max_bytes`.
///
/// `max_batch_bytes` can land mid-segment (the `u16::MAX` byte cap is rarely a
/// multiple of `segment_size`). But a GSO buffer is segmented purely by byte
/// offset — every `segment_size` bytes — with no knowledge of intended datagram
/// boundaries. So an *intermediate* batch must stop on a segment boundary;
/// otherwise the split emits a short datagram in the middle of the stream and
/// shifts every segment after it. Only the genuine final batch (the remainder of
/// the whole transmit) may carry a partial last segment.
#[cfg(not(wasm_browser))]
fn next_batch_bytes(remaining: usize, max_bytes: usize, segment_size: usize) -> usize {
    if remaining <= max_bytes {
        // Final batch: send what's left, partial last segment and all.
        remaining
    } else {
        // Intermediate batch: round the byte budget down to whole segments, but
        // always make progress even if a single segment exceeds the budget.
        (max_bytes / segment_size).max(1) * segment_size
    }
}

/// Asynchronous transport-layer errors reported by the operating system
///
/// On Linux and Android these are delivered via the socket error queue
/// (`MSG_ERRQUEUE`) and originate from ICMP messages.
///
/// These errors are out-of-band and do not correspond to a received packet.
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub struct TransportError {
    /// Address associated with the error
    ///
    /// This is the remote peer or an intermediate network device that triggered the error.
    /// Returns `None` if the kernel cannot determine the source (e.g. `AF_UNSPEC`).
    pub addr: Option<SocketAddr>,
    /// Transport-layer error details
    pub payload: TransportErrorPayload,
    /// The raw error code from the underlying operating system
    pub raw_errno: i32,
}

impl TransportError {
    /// Returns the recommended MTU for packet-too-big errors
    pub fn mtu(&self) -> Option<u32> {
        match self.payload {
            TransportErrorPayload::TooBig { mtu } => Some(mtu),
            _ => None,
        }
    }
}

/// Transport-layer error details reported by the kernel
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub enum TransportErrorPayload {
    /// Destination host or port is unreachable
    Unreachable,
    /// Packet exceeds path MTU
    TooBig {
        /// Recommended Maximum Transmission Unit
        mtu: u32,
    },
    /// Other transport-layer or kernel-reported error
    Other,
}

/// Log at most 1 IO error per minute
#[cfg(not(wasm_browser))]
const IO_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Logs a warning message when sendmsg fails
///
/// Logging will only be performed if at least [`IO_ERROR_LOG_INTERVAL`]
/// has elapsed since the last error was logged.
#[cfg(all(not(wasm_browser), any(feature = "tracing-log", feature = "log")))]
fn log_sendmsg_error(
    last_send_error: &Mutex<Instant>,
    err: impl core::fmt::Debug,
    transmit: &Transmit<'_>,
) {
    let now = Instant::now();
    let last_send_error = &mut *last_send_error.lock().expect("poisend lock");
    if now.saturating_duration_since(*last_send_error) > IO_ERROR_LOG_INTERVAL {
        *last_send_error = now;
        log::warn!(
            "sendmsg error: {:?}, Transmit: {{ destination: {:?}, src_ip: {:?}, ecn: {:?}, len: {:?}, segment_size: {:?} }}",
            err,
            transmit.destination,
            transmit.src_ip,
            transmit.ecn,
            transmit.contents.len(),
            transmit.segment_size
        );
    }
}

// No-op
#[cfg(not(any(wasm_browser, feature = "tracing-log", feature = "log")))]
fn log_sendmsg_error(_: &Mutex<Instant>, _: impl core::fmt::Debug, _: &Transmit<'_>) {}

/// A borrowed UDP socket
///
/// On Unix, constructible via `From<T: AsFd>`. On Windows, constructible via `From<T:
/// AsSocket>`.
// Wrapper around socket2 to avoid making it a public dependency and incurring stability risk
#[cfg(not(wasm_browser))]
pub struct UdpSockRef<'a>(socket2::SockRef<'a>);

#[cfg(unix)]
impl<'s, S> From<&'s S> for UdpSockRef<'s>
where
    S: AsFd,
{
    fn from(socket: &'s S) -> Self {
        Self(socket.into())
    }
}

#[cfg(windows)]
impl<'s, S> From<&'s S> for UdpSockRef<'s>
where
    S: AsSocket,
{
    fn from(socket: &'s S) -> Self {
        Self(socket.into())
    }
}

/// Explicit congestion notification codepoint
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EcnCodepoint {
    /// The ECT(0) codepoint, indicating that an endpoint is ECN-capable
    Ect0 = 0b10,
    /// The ECT(1) codepoint, indicating that an endpoint is ECN-capable
    Ect1 = 0b01,
    /// The CE codepoint, signalling that congestion was experienced
    Ce = 0b11,
}

impl EcnCodepoint {
    /// Create new object from the given bits
    pub fn from_bits(x: u8) -> Option<Self> {
        use EcnCodepoint::*;
        Some(match x & 0b11 {
            0b10 => Ect0,
            0b01 => Ect1,
            0b11 => Ce,
            _ => {
                return None;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn v4_dest() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    }

    fn v6_dest() -> SocketAddr {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    }

    #[test]
    fn max_batch_bytes_capped_by_gso_budget() {
        // 8 segments * 1200 bytes = 9600 bytes, well under the byte budget.
        assert_eq!(max_batch_bytes(8, 1200, v4_dest()), 8 * 1200);
    }

    #[test]
    fn max_batch_bytes_capped_by_byte_limit() {
        // 64 * 1200 = 76800 bytes exceeds the byte budget, so the byte limit
        // wins: IPv4 payload budget = 65535 - 68 = 65467; IPv6 = 65535 - 48 = 65487.
        assert_eq!(max_batch_bytes(64, 1200, v4_dest()), 65535 - 68);
        assert_eq!(max_batch_bytes(64, 1200, v6_dest()), 65535 - 48);
    }

    #[test]
    fn max_batch_bytes_differs_by_family() {
        // IPv6's smaller header overhead lets us pack 20 more bytes per batch.
        let v4 = max_batch_bytes(usize::MAX, 1, v4_dest());
        let v6 = max_batch_bytes(usize::MAX, 1, v6_dest());
        assert_eq!(v4, u16::MAX as usize - 68);
        assert_eq!(v6, u16::MAX as usize - 48);
        assert_eq!(v6 - v4, 20);
    }

    /// Regression: the bench transmits 65487 bytes (IPv6 `u16::MAX - 48`) with
    /// `segment_size = 1280`, which is 51 full segments + a 207-byte partial.
    /// Our byte-based cap allows the full transmit in one call.
    #[test]
    fn max_batch_bytes_allows_partial_last_segment() {
        let max = max_batch_bytes(64, 1280, v6_dest());
        assert_eq!(max, 65487);
        // 51 * 1280 + 207 = 65487 — fits in one batch.
        assert!(51 * 1280 + 207 <= max);
    }

    #[test]
    fn next_batch_bytes_final_batch_keeps_partial() {
        // Everything left fits in the budget: send it all, partial tail and all.
        assert_eq!(next_batch_bytes(65487, 65487, 1280), 65487);
        assert_eq!(next_batch_bytes(500, 65487, 1280), 500);
    }

    #[test]
    fn next_batch_bytes_intermediate_is_segment_aligned() {
        // A transmit larger than the byte cap must be split *on a segment
        // boundary*, not at the raw byte cap (which would emit a runt mid-stream).
        let max = max_batch_bytes(64, 1280, v6_dest()); // 65487, not a multiple of 1280
        let batch = next_batch_bytes(81920, max, 1280); // 64 * 1280 = 81920
        assert_eq!(batch, 51 * 1280, "must round 65487 down to 51 whole segments");
        assert_eq!(batch % 1280, 0, "intermediate batch must be segment-aligned");
        // The remainder then rides in a second, also-aligned batch.
        assert_eq!(81920 - batch, 13 * 1280);
    }

    #[test]
    fn next_batch_bytes_always_progresses() {
        // Even if a single segment exceeds the byte budget, send one segment so
        // the loop can't spin forever (the oversized datagram then fails loudly).
        assert_eq!(next_batch_bytes(10_000, 1000, 1500), 1500);
    }

    #[test]
    fn next_batch_bytes_single_segment_after_gso_halt() {
        // After a GSO halt the budget drops to one segment; every batch is then
        // exactly one datagram.
        assert_eq!(next_batch_bytes(81920, 1280, 1280), 1280);
    }

    /// Walks the whole slicing loop over an oversized transmit and asserts every
    /// emitted batch is segment-aligned except the final remainder — the
    /// property the integration test verifies against a real kernel.
    #[test]
    fn slicing_preserves_segment_alignment() {
        const SEGMENT: usize = 1280;
        let total = 100 * SEGMENT + 333; // 100 full segments + a real partial tail
        let max = max_batch_bytes(64, SEGMENT, v6_dest());

        let mut pos = 0;
        let mut batches = 0;
        while pos < total {
            let remaining = total - pos;
            let len = next_batch_bytes(remaining, max, SEGMENT);
            assert!(len > 0);
            if remaining > max {
                assert_eq!(len % SEGMENT, 0, "intermediate batch split a segment");
            }
            pos += len;
            batches += 1;
        }
        assert_eq!(pos, total, "slicing must cover exactly the whole transmit");
        assert!(batches >= 2, "this transmit should require multiple syscalls");
    }

    #[test]
    fn effective_segment_size() {
        assert_eq!(
            make_transmit(&[0u8; 10], Some(15)).effective_segment_size(),
            None,
            "segment_size > content_len should yield no effective segment_size"
        );
        assert_eq!(
            make_transmit(&[0u8; 10], Some(10)).effective_segment_size(),
            None,
            "segment_size == content_len should yield no effective segment_size"
        );
        assert_eq!(
            make_transmit(&[0u8; 10], None).effective_segment_size(),
            None,
            "no segment_size should yield no effective segment_size"
        );
        assert_eq!(
            make_transmit(&[0u8; 10], Some(5)).effective_segment_size(),
            Some(5),
            "segment_size < content_len should yield effective segment_size"
        );
    }

    fn make_transmit(contents: &[u8], segment_size: Option<usize>) -> Transmit<'_> {
        Transmit {
            destination: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 1)),
            ecn: None,
            contents,
            segment_size,
            src_ip: None,
        }
    }
}
