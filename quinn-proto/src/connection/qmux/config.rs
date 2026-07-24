//! Connection configuration

use std::sync::Arc;

use crate::{TransportConfig, VarInt};

use super::params::DEFAULT_MAX_RECORD_SIZE;

/// Parameters governing a QMux connection
///
/// Most knobs come from the shared [`TransportConfig`]. QMux uses `max_idle_timeout`,
/// `keep_alive_interval` (keep-alives are sent as QX_PING frames), `receive_window`,
/// `stream_receive_window`, `send_window`, `send_fairness`,
/// `max_concurrent_bidi_streams`, `max_concurrent_uni_streams`,
/// `datagram_receive_buffer_size` (which also determines the advertised
/// `max_datagram_frame_size`, as in QUIC; `None` disables datagram support), and
/// `datagram_send_buffer_size`. Settings for QUIC's packetization, loss recovery,
/// congestion control, ACKs, and MTU discovery have no counterpart on a reliable ordered
/// transport and are ignored.
#[derive(Debug, Clone)]
pub struct Config {
    /// Shared transport-level limits and timers
    pub transport: Arc<TransportConfig>,
    /// Largest record Size field the peer may use in records it sends to us; at least
    /// 16382 (the default)
    pub max_record_size: VarInt,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            transport: Arc::new(TransportConfig::default()),
            max_record_size: VarInt::from_u64(DEFAULT_MAX_RECORD_SIZE).unwrap(),
        }
    }
}

impl Config {
    /// Create a configuration with default limits
    pub fn new() -> Self {
        Self::default()
    }
}
