//! Sans-IO QMux connection state machine
//!
//! [`Connection`] multiplexes QUIC streams and flow control over a single reliable,
//! ordered byte stream, per draft-ietf-quic-qmux-02. It reuses quinn-proto's stream state
//! machine (`StreamsState`) unmodified: the draft interprets acknowledgment as occurring
//! "as soon as data is passed to the underlying transport", so frames are treated as
//! acknowledged the moment they are serialized into a record, and nothing is ever
//! retransmitted at this layer.
//!
//! Like [`crate::Connection`], this type performs no I/O. Feed received transport
//! bytes to [`Connection::handle_input`] (or whole records to
//! [`Connection::handle_record`] on message-oriented transports such as WebSocket), write
//! out records produced by [`Connection::poll_transmit`], run [`Connection::handle_timeout`]
//! at [`Connection::poll_timeout`], and drain [`Connection::poll`] for application events.

use std::{collections::VecDeque, sync::Arc};

use bytes::Bytes;
use rustc_hash::FxHashMap;
use thiserror::Error;
use tracing::trace;

use super::{
    State as ConnectionState,
    spaces::{Retransmits, ThinRetransmits},
    stats::FrameStats,
    streams::StreamsState,
};
use crate::{
    Dir, Instant, Side, StreamId, TransportError, TransportErrorCode, VarInt,
    transport_parameters::TransportParameters,
};

// The poll-level stream API is the rest of this crate's, re-exported for convenience
pub use crate::{
    Chunks, ClosedStream, FinishError, ReadError, ReadableError, RecvStream, SendStream,
    StreamEvent, Streams, WriteError, Written,
};

mod config;
pub use config::Config;

mod frame;
mod params;
mod record;
mod timer;

use frame::{Close, Frame};
use params::QmuxParams;
use record::Deframer;
use timer::IdleTimer;

/// Events yielded by [`Connection::poll`]
#[derive(Debug)]
pub enum Event {
    /// The peer's transport parameters arrived; streams may now be opened
    Connected,
    /// Stream activity, as in quinn
    Stream(StreamEvent),
    /// One or more datagrams were received
    DatagramReceived,
    /// The connection was terminated
    ConnectionLost {
        /// Why the connection ended
        reason: ConnectionError,
    },
}

/// Reasons a QMux connection may terminate
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ConnectionError {
    /// The peer violated the protocol
    #[error("transport error: {0}")]
    TransportError(#[from] TransportError),
    /// The peer's transport layer closed the connection
    #[error("closed by peer: code {}", error_code.into_inner())]
    ConnectionClosed {
        /// Error code supplied by the peer
        error_code: VarInt,
        /// Type of the frame that provoked the closure, if any
        frame_type: Option<VarInt>,
        /// Peer-supplied reason
        reason: Bytes,
    },
    /// The peer's application closed the connection
    #[error("closed by peer application: code {}", error_code.into_inner())]
    ApplicationClosed {
        /// Application-supplied error code
        error_code: VarInt,
        /// Application-supplied reason
        reason: Bytes,
    },
    /// The idle timeout expired
    #[error("timed out")]
    TimedOut,
    /// The local application closed the connection
    #[error("closed")]
    LocallyClosed,
    /// The underlying transport failed or was closed without a CONNECTION_CLOSE
    #[error("underlying transport closed")]
    TransportClosed,
}

/// Errors from [`Connection::send_datagram`]
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum SendDatagramError {
    /// The peer's transport parameters have not arrived yet
    #[error("peer transport parameters not yet received")]
    NotYetReady,
    /// The peer does not accept datagrams
    #[error("datagrams not supported by peer")]
    UnsupportedByPeer,
    /// The datagram exceeds the peer's advertised limits
    #[error("datagram too large")]
    TooLarge,
}

/// A QMux connection over a reliable, ordered transport
pub struct Connection {
    side: Side,
    config: Arc<Config>,
    streams: StreamsState,
    /// Control frames awaiting serialization; drained by `write_control_frames`
    pending: Retransmits,
    conn_state: ConnectionState,
    stats: FrameStats,

    params_sent: bool,
    params_received: bool,
    peer_params: Option<QmuxParams>,

    /// Next expected receive offset per live stream, enforcing the draft's in-order rule
    recv_offsets: FxHashMap<StreamId, u64>,
    deframer: Deframer,
    idle: IdleTimer,

    next_ping_seq: u64,
    greatest_ping_recv: Option<u64>,
    ping_request_pending: bool,
    ping_responses: VecDeque<VarInt>,

    datagram_send: VecDeque<Bytes>,
    datagram_recv: VecDeque<Bytes>,

    /// CONNECTION_CLOSE / APPLICATION_CLOSE frame awaiting transmission
    close: Option<Close>,
    close_sent: bool,
    error: Option<ConnectionError>,
    events: VecDeque<Event>,
}

impl Connection {
    /// Create a connection; `side` distinguishes client- from server-initiated stream IDs
    pub fn new(config: Arc<Config>, side: Side, now: Instant) -> Self {
        let streams = StreamsState::new(
            side,
            config.max_concurrent_uni_streams,
            config.max_concurrent_bidi_streams,
            config.send_window,
            config.receive_window,
            config.stream_receive_window,
        );
        let idle = IdleTimer::new(config.max_idle_timeout, now);
        Self {
            side,
            config,
            streams,
            pending: Retransmits::default(),
            conn_state: ConnectionState::Established,
            stats: FrameStats::default(),
            params_sent: false,
            params_received: false,
            peer_params: None,
            recv_offsets: FxHashMap::default(),
            deframer: Deframer::default(),
            idle,
            next_ping_seq: 0,
            greatest_ping_recv: None,
            ping_request_pending: false,
            ping_responses: VecDeque::new(),
            datagram_send: VecDeque::new(),
            datagram_recv: VecDeque::new(),
            close: None,
            close_sent: false,
            error: None,
            events: VecDeque::new(),
        }
    }

    /// Which side of the connection this is
    pub fn side(&self) -> Side {
        self.side
    }

    /// Whether the peer's transport parameters have been received
    pub fn is_established(&self) -> bool {
        self.params_received && self.error.is_none()
    }

    /// Whether the connection has terminated
    pub fn is_closed(&self) -> bool {
        self.error.is_some()
    }

    /// The reason the connection terminated, if it has
    pub fn error(&self) -> Option<&ConnectionError> {
        self.error.as_ref()
    }

    /// Feed bytes received from the underlying transport
    ///
    /// Accepts arbitrary chunkings; records are reassembled internally. On error the
    /// connection is closed and a final CONNECTION_CLOSE record is available from
    /// [`Self::poll_transmit`].
    pub fn handle_input(&mut self, data: &[u8], now: Instant) -> Result<(), ConnectionError> {
        if self.is_closed() {
            return Ok(());
        }
        self.deframer.push(data);
        loop {
            match self.deframer.next(self.config.max_record_size.into_inner()) {
                Ok(Some(payload)) => self.handle_record(payload, now)?,
                Ok(None) => return Ok(()),
                Err(e) => return Err(self.fail(e)),
            }
        }
    }

    /// Process the frames payload of one record
    ///
    /// For message-oriented transports (e.g. WebSocket) where the transport already
    /// delimits records; byte-stream transports use [`Self::handle_input`].
    pub fn handle_record(&mut self, payload: Bytes, now: Instant) -> Result<(), ConnectionError> {
        if self.is_closed() {
            return Ok(());
        }
        self.idle.on_record_received(now);
        let payload_len = payload.len();
        let mut buf = payload;
        loop {
            let frame = match Frame::decode(&mut buf) {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(e) => return Err(self.fail(e)),
            };
            if let Err(e) = self.on_frame(frame, payload_len, now) {
                return Err(self.fail(e));
            }
            if self.is_closed() {
                // The peer closed the connection; ignore any trailing frames
                return Ok(());
            }
        }
        self.streams.queue_max_stream_id(&mut self.pending);
        Ok(())
    }

    /// The underlying transport failed or reached EOF without a close frame
    pub fn transport_closed(&mut self) {
        self.lost(ConnectionError::TransportClosed);
    }

    /// Close the connection, notifying the peer with an APPLICATION_CLOSE frame
    ///
    /// The final record is produced by the next [`Self::poll_transmit`]; the caller should
    /// then flush it and gracefully shut down its sending side of the transport.
    pub fn close(&mut self, error_code: VarInt, reason: Bytes) {
        if self.is_closed() {
            return;
        }
        self.close = Some(Close {
            is_application: true,
            error_code,
            frame_type: None,
            reason,
        });
        self.lost(ConnectionError::LocallyClosed);
    }

    /// Produce the next record to write to the underlying transport
    ///
    /// Returns `None` when there is nothing to send. The returned buffer includes the
    /// record's Size prefix; on message-oriented transports use the frames payload
    /// starting past the prefix... instead see [`Self::poll_transmit_payload`].
    pub fn poll_transmit(&mut self, now: Instant) -> Option<Bytes> {
        self.transmit(now).map(|frames| record::wrap(&frames))
    }

    /// Like [`Self::poll_transmit`], but without the record Size prefix
    ///
    /// For message-oriented transports where each transport message is one record.
    pub fn poll_transmit_payload(&mut self, now: Instant) -> Option<Bytes> {
        self.transmit(now).map(Bytes::from)
    }

    fn transmit(&mut self, now: Instant) -> Option<Vec<u8>> {
        if self.close_sent {
            return None;
        }
        let mut buf = Vec::new();

        // The transport parameters must be the very first frame we send
        if !self.params_sent {
            let mut blob = Vec::new();
            self.local_params().encode(&mut blob);
            frame::encode_transport_parameters(&mut buf, &blob);
            self.params_sent = true;
        }

        if self.error.is_some() {
            // Drain: emit the close frame (if any) and go quiet. An idle timeout or
            // transport failure sends nothing.
            let Some(close) = self.close.take() else {
                self.close_sent = true;
                return match buf.is_empty() {
                    true => None,
                    false => Some(buf),
                };
            };
            frame::encode_close(&mut buf, &close);
            self.close_sent = true;
            self.idle.on_record_sent(now);
            return Some(buf);
        }

        let budget = self.record_budget();

        while let Some(&seq) = self.ping_responses.front() {
            if buf.len() + frame::ping_size(seq) > budget {
                break;
            }
            frame::encode_ping(&mut buf, true, seq);
            self.ping_responses.pop_front();
        }
        if self.ping_request_pending {
            let seq = VarInt::from_u64(self.next_ping_seq).expect("ping sequence overflow");
            if buf.len() + frame::ping_size(seq) <= budget {
                frame::encode_ping(&mut buf, false, seq);
                self.next_ping_seq += 1;
                self.ping_request_pending = false;
            }
        }

        while let Some(datagram) = self.datagram_send.front() {
            if buf.len() + frame::datagram_frame_size(datagram.len()) > budget {
                break;
            }
            frame::encode_datagram(&mut buf, datagram);
            self.datagram_send.pop_front();
        }

        // Flow control and stream lifecycle frames. Everything drained from `pending` is
        // copied into `thin` for QUIC loss recovery; with a reliable transport the only
        // part we need back is which RESET_STREAM frames were written, which are
        // considered acknowledged on transmission.
        let mut thin = ThinRetransmits::default();
        self.streams.write_control_frames(
            &mut buf,
            &mut self.pending,
            &mut thin,
            &mut self.stats,
            budget,
        );
        if let Some(retransmits) = thin.get() {
            let resets: Vec<_> = retransmits.reset_stream.iter().map(|&(id, _)| id).collect();
            for id in resets {
                self.streams.reset_acked(id);
            }
        }

        // Stream data goes last: a STREAM frame that omits its Length field extends to the
        // end of the record. Everything serialized is immediately treated as acknowledged,
        // freeing send buffers and firing `StreamEvent::Finished`.
        let metas = self.streams.write_stream_frames(&mut buf, budget, true);
        for meta in metas {
            self.streams.received_ack_of(meta);
        }

        if buf.is_empty() {
            return None;
        }
        self.idle.on_record_sent(now);
        Some(buf)
    }

    /// The instant at which [`Self::handle_timeout`] should next run
    pub fn poll_timeout(&self) -> Option<Instant> {
        match self.is_closed() {
            true => None,
            false => self.idle.next_timeout(),
        }
    }

    /// Process idle timeout expiry and keep-alive scheduling
    pub fn handle_timeout(&mut self, now: Instant) {
        if self.is_closed() {
            return;
        }
        if self.idle.is_expired(now) {
            // The draft has idle timeout shut the transport down without sending frames
            self.lost(ConnectionError::TimedOut);
            return;
        }
        if self.idle.poll_keepalive(now) {
            self.ping_request_pending = true;
        }
    }

    /// Yield application events
    pub fn poll(&mut self) -> Option<Event> {
        if let Some(event) = self.events.pop_front() {
            return Some(event);
        }
        self.streams.poll().map(Event::Stream)
    }

    /// Open and accept streams
    pub fn streams(&mut self) -> Streams<'_> {
        Streams {
            state: &mut self.streams,
            conn_state: &self.conn_state,
        }
    }

    /// Operate on a stream's send half
    pub fn send_stream(&mut self, id: StreamId) -> SendStream<'_> {
        SendStream {
            id,
            state: &mut self.streams,
            pending: &mut self.pending,
            conn_state: &self.conn_state,
        }
    }

    /// Operate on a stream's receive half
    pub fn recv_stream(&mut self, id: StreamId) -> RecvStream<'_> {
        RecvStream {
            id,
            state: &mut self.streams,
            pending: &mut self.pending,
        }
    }

    /// Queue a datagram for transmission
    ///
    /// Unlike QUIC, a QMux datagram is delivered reliably and in order once sent, and is
    /// subject to the same head-of-line blocking as other data. If the send queue is full
    /// the oldest queued datagram is dropped.
    pub fn send_datagram(&mut self, data: Bytes) -> Result<(), SendDatagramError> {
        let Some(peer) = &self.peer_params else {
            return Err(SendDatagramError::NotYetReady);
        };
        let Some(max_frame) = peer.max_datagram_frame_size else {
            return Err(SendDatagramError::UnsupportedByPeer);
        };
        let size = frame::datagram_frame_size(data.len()) as u64;
        if size
            > max_frame
                .into_inner()
                .min(peer.max_record_size.into_inner())
        {
            return Err(SendDatagramError::TooLarge);
        }
        if self.datagram_send.len() >= self.config.datagram_send_queue {
            self.datagram_send.pop_front();
        }
        self.datagram_send.push_back(data);
        Ok(())
    }

    /// Receive a queued datagram
    pub fn recv_datagram(&mut self) -> Option<Bytes> {
        self.datagram_recv.pop_front()
    }

    /// Largest datagram payload the peer accepts, or `None` before the handshake or when
    /// the peer disabled datagrams
    pub fn max_datagram_size(&self) -> Option<usize> {
        let peer = self.peer_params.as_ref()?;
        let max_frame = peer.max_datagram_frame_size?;
        let capacity = max_frame
            .into_inner()
            .min(peer.max_record_size.into_inner());
        // Subtract the frame type and a worst-case length prefix
        Some(usize::try_from(capacity.saturating_sub(1 + 4)).unwrap_or(usize::MAX))
    }

    fn local_params(&self) -> QmuxParams {
        let idle_ms = self
            .config
            .max_idle_timeout
            .map(|timeout| u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        QmuxParams {
            max_idle_timeout: VarInt::from_u64(idle_ms).unwrap_or(VarInt::MAX),
            initial_max_data: self.config.receive_window,
            initial_max_stream_data_bidi_local: self.config.stream_receive_window,
            initial_max_stream_data_bidi_remote: self.config.stream_receive_window,
            initial_max_stream_data_uni: self.config.stream_receive_window,
            initial_max_streams_bidi: self.config.max_concurrent_bidi_streams,
            initial_max_streams_uni: self.config.max_concurrent_uni_streams,
            max_record_size: self.config.max_record_size,
            max_datagram_frame_size: self.config.max_datagram_frame_size,
        }
    }

    /// Largest frames payload we may place in a single record
    fn record_budget(&self) -> usize {
        let peer = self
            .peer_params
            .as_ref()
            .map(|p| p.max_record_size.into_inner())
            .unwrap_or(params::DEFAULT_MAX_RECORD_SIZE);
        usize::try_from(peer).unwrap_or(usize::MAX)
    }

    fn on_frame(
        &mut self,
        frame: Frame,
        payload_len: usize,
        now: Instant,
    ) -> Result<(), TransportError> {
        // QX_TRANSPORT_PARAMETERS must be the first frame received, exactly once
        if self.params_received == matches!(frame, Frame::TransportParameters(_)) {
            return Err(TransportError::new(
                TransportErrorCode::PROTOCOL_VIOLATION,
                match self.params_received {
                    true => "duplicate QX_TRANSPORT_PARAMETERS frame".into(),
                    false => "first frame was not QX_TRANSPORT_PARAMETERS".into(),
                },
            ));
        }

        match frame {
            Frame::TransportParameters(blob) => {
                let peer = QmuxParams::decode(blob)?;
                let tp = TransportParameters {
                    initial_max_data: peer.initial_max_data,
                    initial_max_stream_data_bidi_local: peer.initial_max_stream_data_bidi_local,
                    initial_max_stream_data_bidi_remote: peer.initial_max_stream_data_bidi_remote,
                    initial_max_stream_data_uni: peer.initial_max_stream_data_uni,
                    initial_max_streams_bidi: peer.initial_max_streams_bidi,
                    initial_max_streams_uni: peer.initial_max_streams_uni,
                    ..TransportParameters::default()
                };
                self.streams.set_params(&tp);
                self.idle
                    .set_peer_timeout(peer.max_idle_timeout.into_inner(), now);
                self.peer_params = Some(peer);
                self.params_received = true;
                self.events.push_back(Event::Connected);
                // Wake anything waiting to open a stream now that limits are known
                for dir in [Dir::Bi, Dir::Uni] {
                    self.events
                        .push_back(Event::Stream(StreamEvent::Available { dir }));
                }
            }
            Frame::Stream(stream) => {
                // The draft requires stream payloads to arrive in offset order; a gap can
                // only mean a peer bug, since the transport is ordered. Data on a stream
                // that already ended (entry removed on FIN or reset) is likewise a
                // violation of its final size.
                let id = stream.id;
                let expected = self.recv_offsets.entry(id).or_insert(0);
                if stream.offset != *expected {
                    return Err(TransportError::new(
                        TransportErrorCode::PROTOCOL_VIOLATION,
                        "stream payload received out of order".into(),
                    ));
                }
                *expected += stream.data.len() as u64;
                if stream.fin {
                    self.recv_offsets.remove(&id);
                }
                let transmit = self.streams.received(stream, payload_len)?;
                if transmit.should_transmit() {
                    self.pending.max_data = true;
                }
            }
            Frame::ResetStream(reset) => {
                self.recv_offsets.remove(&reset.id);
                let transmit = self.streams.received_reset(reset)?;
                if transmit.should_transmit() {
                    self.pending.max_data = true;
                }
            }
            Frame::ResetStreamAt(reset) => {
                // On a reliable transport all stream data was already delivered to us, so
                // the partial-delivery guarantee is trivially satisfied; treat as a reset
                self.recv_offsets.remove(&reset.id);
                let transmit = self.streams.received_reset(reset)?;
                if transmit.should_transmit() {
                    self.pending.max_data = true;
                }
            }
            Frame::StopSending { id, error_code } => {
                self.streams.received_stop_sending(id, error_code);
            }
            Frame::MaxData(max) => self.streams.received_max_data(max),
            Frame::MaxStreamData { id, offset } => {
                self.streams
                    .received_max_stream_data(id, offset.into_inner())?;
            }
            Frame::MaxStreams { dir, count } => {
                self.streams.received_max_streams(dir, count.into_inner())?;
            }
            Frame::DataBlocked { offset } => {
                trace!(offset = offset.into_inner(), "peer reports DATA_BLOCKED");
            }
            Frame::StreamDataBlocked { id, offset } => {
                trace!(stream = %id, offset = offset.into_inner(), "peer reports STREAM_DATA_BLOCKED");
            }
            Frame::StreamsBlocked { dir, limit } => {
                trace!(
                    ?dir,
                    limit = limit.into_inner(),
                    "peer reports STREAMS_BLOCKED"
                );
            }
            Frame::Close(close) => {
                let reason = match close.is_application {
                    true => ConnectionError::ApplicationClosed {
                        error_code: close.error_code,
                        reason: close.reason,
                    },
                    false => ConnectionError::ConnectionClosed {
                        error_code: close.error_code,
                        frame_type: close.frame_type,
                        reason: close.reason,
                    },
                };
                self.lost(reason);
            }
            Frame::Datagram(data) => {
                let Some(max_frame) = self.config.max_datagram_frame_size else {
                    return Err(TransportError::new(
                        TransportErrorCode::PROTOCOL_VIOLATION,
                        "DATAGRAM frame received but datagrams are disabled".into(),
                    ));
                };
                if frame::datagram_frame_size(data.len()) as u64 > max_frame.into_inner() {
                    return Err(TransportError::new(
                        TransportErrorCode::PROTOCOL_VIOLATION,
                        "oversized DATAGRAM frame".into(),
                    ));
                }
                // Received datagrams may be dropped when the application lags
                if self.datagram_recv.len() >= self.config.datagram_recv_queue {
                    self.datagram_recv.pop_front();
                }
                self.datagram_recv.push_back(data);
                self.events.push_back(Event::DatagramReceived);
            }
            Frame::PingRequest(seq) => {
                let seq = seq.into_inner();
                if self
                    .greatest_ping_recv
                    .is_some_and(|greatest| seq <= greatest)
                {
                    return Err(TransportError::new(
                        TransportErrorCode::PROTOCOL_VIOLATION,
                        "QX_PING sequence number did not increase".into(),
                    ));
                }
                self.greatest_ping_recv = Some(seq);
                self.ping_responses
                    .push_back(VarInt::from_u64(seq).expect("validated varint"));
            }
            Frame::PingResponse(seq) => {
                if seq.into_inner() >= self.next_ping_seq {
                    return Err(TransportError::new(
                        TransportErrorCode::PROTOCOL_VIOLATION,
                        "QX_PING response for a request we never sent".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Record a protocol error: queue a CONNECTION_CLOSE and terminate
    fn fail(&mut self, error: TransportError) -> ConnectionError {
        let reason = ConnectionError::TransportError(error.clone());
        if self.error.is_none() {
            self.close = Some(Close {
                is_application: false,
                error_code: VarInt::from_u64(error.code.into()).unwrap_or(VarInt::MAX),
                frame_type: None,
                reason: error.reason.clone().into(),
            });
            self.lost(reason.clone());
        }
        reason
    }

    /// Terminate the connection with `reason` if it hasn't terminated already
    fn lost(&mut self, reason: ConnectionError) {
        if self.error.is_some() {
            return;
        }
        self.error = Some(reason.clone());
        self.conn_state = ConnectionState::Draining;
        self.events.push_back(Event::ConnectionLost { reason });
    }
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("side", &self.side)
            .field("established", &self.params_received)
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
