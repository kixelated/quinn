//! Connection configuration

use std::time::Duration;

use quinn_proto::VarInt;

/// Parameters governing a QMux connection
///
/// Controls both the transport parameters advertised to the peer and local resource
/// limits.
#[derive(Debug, Clone)]
pub struct Config {
    pub(crate) receive_window: VarInt,
    pub(crate) stream_receive_window: VarInt,
    pub(crate) max_concurrent_bidi_streams: VarInt,
    pub(crate) max_concurrent_uni_streams: VarInt,
    pub(crate) send_window: u64,
    pub(crate) max_idle_timeout: Option<Duration>,
    pub(crate) max_record_size: VarInt,
    pub(crate) max_datagram_frame_size: Option<VarInt>,
    pub(crate) datagram_send_queue: usize,
    pub(crate) datagram_recv_queue: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            receive_window: VarInt::from_u32(8 * 1024 * 1024),
            stream_receive_window: VarInt::from_u32(1024 * 1024),
            max_concurrent_bidi_streams: VarInt::from_u32(100),
            max_concurrent_uni_streams: VarInt::from_u32(100),
            send_window: 8 * 1024 * 1024,
            max_idle_timeout: Some(Duration::from_secs(30)),
            max_record_size: VarInt::from_u64(crate::proto::params::DEFAULT_MAX_RECORD_SIZE)
                .unwrap(),
            max_datagram_frame_size: Some(VarInt::from_u32(16382)),
            datagram_send_queue: 1024,
            datagram_recv_queue: 1024,
        }
    }
}

impl Config {
    /// Create a configuration with default limits
    pub fn new() -> Self {
        Self::default()
    }

    /// Connection-level flow control window for data received from the peer
    pub fn receive_window(&mut self, value: VarInt) -> &mut Self {
        self.receive_window = value;
        self
    }

    /// Per-stream flow control window for data received from the peer
    pub fn stream_receive_window(&mut self, value: VarInt) -> &mut Self {
        self.stream_receive_window = value;
        self
    }

    /// Number of bidirectional streams the peer may have open concurrently
    pub fn max_concurrent_bidi_streams(&mut self, value: VarInt) -> &mut Self {
        self.max_concurrent_bidi_streams = value;
        self
    }

    /// Number of unidirectional streams the peer may have open concurrently
    pub fn max_concurrent_uni_streams(&mut self, value: VarInt) -> &mut Self {
        self.max_concurrent_uni_streams = value;
        self
    }

    /// Maximum quantity of stream data buffered locally awaiting transmission
    pub fn send_window(&mut self, value: u64) -> &mut Self {
        self.send_window = value;
        self
    }

    /// Close the connection after this long without receiving a record; `None` disables
    ///
    /// The effective timeout is the minimum of both endpoints' values. Keep-alive pings
    /// are sent at a third of the effective timeout.
    pub fn max_idle_timeout(&mut self, value: Option<Duration>) -> &mut Self {
        self.max_idle_timeout = value;
        self
    }

    /// Largest record Size field the peer may send; at least 16382
    pub fn max_record_size(&mut self, value: VarInt) -> &mut Self {
        self.max_record_size = value;
        self
    }

    /// Largest DATAGRAM frame the peer may send; `None` disables datagram support
    pub fn max_datagram_frame_size(&mut self, value: Option<VarInt>) -> &mut Self {
        self.max_datagram_frame_size = value;
        self
    }

    /// Outgoing datagrams queued beyond this count displace the oldest queued datagram
    pub fn datagram_send_queue(&mut self, value: usize) -> &mut Self {
        self.datagram_send_queue = value;
        self
    }

    /// Incoming datagrams queued beyond this count displace the oldest queued datagram
    pub fn datagram_recv_queue(&mut self, value: usize) -> &mut Self {
        self.datagram_recv_queue = value;
        self
    }
}
