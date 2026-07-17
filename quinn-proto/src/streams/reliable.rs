//! Stream state machine facade for reliable, ordered transports.

use bytes::Bytes;

use super::{Event, Pending, RecvStream, SendStream, Streams, StreamsState, WriteStats};
use crate::{
    Dir, Side, StreamId, TransportError, VarInt,
    frame::{self, Frame as WireFrame},
};

/// Stream-related transport parameters supplied by the peer.
///
/// These are the subset of QUIC transport parameters used by QMUX.
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub struct Parameters {
    /// Maximum total stream data the peer permits this endpoint to send.
    pub initial_max_data: VarInt,
    /// Per-stream limit for bidirectional streams initiated by the peer.
    pub initial_max_stream_data_bidi_local: VarInt,
    /// Per-stream limit for bidirectional streams initiated by this endpoint.
    pub initial_max_stream_data_bidi_remote: VarInt,
    /// Per-stream limit for unidirectional streams.
    pub initial_max_stream_data_uni: VarInt,
    /// Number of bidirectional streams this endpoint may initiate.
    pub initial_max_streams_bidi: VarInt,
    /// Number of unidirectional streams this endpoint may initiate.
    pub initial_max_streams_uni: VarInt,
}

/// Local configuration for a [`Connection`].
#[derive(Debug, Copy, Clone)]
pub struct Config {
    /// Number of peer-initiated bidirectional streams initially permitted.
    pub max_remote_bidi: VarInt,
    /// Number of peer-initiated unidirectional streams initially permitted.
    pub max_remote_uni: VarInt,
    /// Maximum bytes retained until carrier writes complete.
    pub send_window: u64,
    /// Connection-level receive window.
    pub receive_window: VarInt,
    /// Per-stream receive window.
    pub stream_receive_window: VarInt,
}

/// A batch of stream frames ready to be written as one record payload.
///
/// Call [`Connection::transmitted`] only after `payload` has been
/// successfully written to the reliable carrier. Dropping this value is
/// appropriate when the carrier fails and the whole connection will be closed.
#[derive(Debug)]
#[must_use = "the payload must be written and passed to Connection::transmitted"]
pub struct Transmit {
    /// Encoded QUIC v1 stream and flow-control frames, without a QMUX record header.
    pub payload: Bytes,
    stream_frames: frame::StreamMetaVec,
    control_frames: Pending,
}

/// A QUIC stream or flow-control frame accepted by [`Connection`].
///
/// QMUX can decode a mixed record itself, forward these frames to
/// [`Connection::received_frame`], and retain carrier-owned frames such as
/// QX_PING, transport parameters, datagrams, and connection close.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Frame {
    /// Stream data at a particular offset.
    Stream {
        /// Stream identifier.
        id: StreamId,
        /// Offset of `data` in the stream.
        offset: u64,
        /// Whether this is the final stream frame.
        fin: bool,
        /// Stream payload.
        data: Bytes,
    },
    /// Abruptly terminate the peer's sending half.
    Reset {
        /// Stream identifier.
        id: StreamId,
        /// Application error code.
        error_code: VarInt,
        /// Final stream size.
        final_offset: VarInt,
    },
    /// Ask the peer to stop its sending half.
    StopSending {
        /// Stream identifier.
        id: StreamId,
        /// Application error code.
        error_code: VarInt,
    },
    /// Increase connection-level send credit.
    MaxData(VarInt),
    /// Increase one stream's send credit.
    MaxStreamData {
        /// Stream identifier.
        id: StreamId,
        /// New absolute stream offset limit.
        offset: u64,
    },
    /// Increase stream-count credit.
    MaxStreams {
        /// Stream direction.
        dir: Dir,
        /// New absolute stream-count limit.
        count: u64,
    },
    /// Peer reports connection-level flow-control blocking.
    DataBlocked {
        /// Offset at which the peer is blocked.
        offset: u64,
    },
    /// Peer reports stream-level flow-control blocking.
    StreamDataBlocked {
        /// Stream identifier.
        id: StreamId,
        /// Offset at which the peer is blocked.
        offset: u64,
    },
    /// Peer reports stream-count blocking.
    StreamsBlocked {
        /// Stream direction.
        dir: Dir,
        /// Limit at which the peer is blocked.
        limit: u64,
    },
}

/// QUIC stream semantics over a reliable, ordered byte carrier.
///
/// This is the reliable-carrier adapter for transports such as QMUX. It
/// deliberately excludes handshake, packet numbers, congestion control, loss
/// recovery, timers, datagrams, and connection close. Incoming and outgoing
/// bytes are QUIC v1 frame payloads suitable for wrapping in QMUX records.
pub struct Connection {
    state: StreamsState,
    pending: Pending,
    closed: bool,
}

impl Connection {
    /// Construct stream state for one side of a reliable connection.
    pub fn new(side: Side, config: Config) -> Self {
        Self {
            state: StreamsState::new(
                side,
                config.max_remote_uni,
                config.max_remote_bidi,
                config.send_window,
                config.receive_window,
                config.stream_receive_window,
            ),
            pending: Pending::default(),
            closed: false,
        }
    }

    /// Apply the stream-related parameters advertised by the peer.
    pub fn set_peer_parameters(&mut self, params: Parameters) {
        self.state.set_stream_params(params);
    }

    /// Access stream opening and acceptance operations.
    pub fn streams(&mut self) -> Streams<'_> {
        Streams {
            state: &mut self.state,
            closed: self.closed,
        }
    }

    /// Access one receive stream.
    pub fn recv_stream(&mut self, id: StreamId) -> RecvStream<'_> {
        assert!(id.dir() == Dir::Bi || id.initiator() != self.state.side);
        RecvStream {
            id,
            state: &mut self.state,
            pending: &mut self.pending,
        }
    }

    /// Access one send stream.
    pub fn send_stream(&mut self, id: StreamId) -> SendStream<'_> {
        assert!(id.dir() == Dir::Bi || id.initiator() == self.state.side);
        SendStream {
            id,
            state: &mut self.state,
            pending: &mut self.pending,
            closed: self.closed,
        }
    }

    /// Yield the next application-facing stream event.
    pub fn poll(&mut self) -> Option<Event> {
        self.state.poll()
    }

    /// Process one decoded stream-related frame.
    ///
    /// `allocation_size` is the size of the backing record or packet allocation
    /// retained by a STREAM frame's [`Bytes`]. It is used only for receive-buffer
    /// memory accounting and can be `data.len()` when the payload has an
    /// independent allocation. STREAM offsets must be contiguous for each stream,
    /// as required by QMUX; an out-of-order frame is a protocol violation.
    pub fn received_frame(
        &mut self,
        frame: Frame,
        allocation_size: usize,
    ) -> Result<(), TransportError> {
        self.state
            .received_frame_ordered(frame, allocation_size, &mut self.pending)
    }

    /// Build one QMUX record payload of pending stream and flow-control frames.
    pub fn poll_transmit(&mut self, max_record_size: usize) -> Option<Transmit> {
        if self.closed {
            return None;
        }
        let mut payload = Vec::with_capacity(max_record_size.min(4096));
        let mut control_frames = Pending::default();
        let mut stats = WriteStats::default();
        self.state.write_control_frames(
            &mut payload,
            &mut self.pending,
            &mut control_frames,
            &mut stats,
            max_record_size,
        );
        let stream_frames = self
            .state
            .write_stream_frames(&mut payload, max_record_size, true);
        if payload.is_empty() {
            return None;
        }
        Some(Transmit {
            payload: payload.into(),
            stream_frames,
            control_frames,
        })
    }

    /// Confirm that a batch was successfully written to the reliable carrier.
    ///
    /// Reliable ordered delivery makes a successful carrier write equivalent to
    /// a QUIC ACK for purposes of releasing buffered stream data.
    pub fn transmitted(&mut self, transmit: Transmit) {
        for frame in transmit.stream_frames {
            self.state.received_ack_of(frame);
        }
        for &(id, _) in &transmit.control_frames.reset_stream {
            self.state.reset_acked(id);
        }
    }

    /// Modify the number of peer-initiated streams allowed concurrently.
    pub fn set_max_concurrent_streams(&mut self, dir: Dir, count: VarInt) {
        self.state.set_max_concurrent(dir, count);
        self.state.queue_max_stream_id(&mut self.pending);
    }

    /// Current number of peer-initiated streams allowed concurrently.
    pub fn max_concurrent_streams(&self, dir: Dir) -> u64 {
        self.state.max_concurrent(dir)
    }

    /// Modify the connection receive window.
    pub fn set_receive_window(&mut self, receive_window: VarInt) {
        if self.state.set_receive_window(receive_window) {
            self.pending.max_data = true;
        }
    }

    /// Modify the amount of outgoing data retained until carrier writes complete.
    pub fn set_send_window(&mut self, send_window: u64) {
        self.state.set_send_window(send_window);
    }

    /// Stop opening, writing, or transmitting streams.
    pub fn close(&mut self) {
        self.closed = true;
    }
}

pub(super) fn public_frame(frame: WireFrame) -> Option<Frame> {
    Some(match frame {
        WireFrame::Stream(frame) => Frame::Stream {
            id: frame.id,
            offset: frame.offset,
            fin: frame.fin,
            data: frame.data,
        },
        WireFrame::ResetStream(frame) => Frame::Reset {
            id: frame.id,
            error_code: frame.error_code,
            final_offset: frame.final_offset,
        },
        WireFrame::StopSending(frame) => Frame::StopSending {
            id: frame.id,
            error_code: frame.error_code,
        },
        WireFrame::MaxData(max) => Frame::MaxData(max),
        WireFrame::MaxStreamData { id, offset } => Frame::MaxStreamData { id, offset },
        WireFrame::MaxStreams { dir, count } => Frame::MaxStreams { dir, count },
        WireFrame::DataBlocked { offset } => Frame::DataBlocked { offset },
        WireFrame::StreamDataBlocked { id, offset } => Frame::StreamDataBlocked { id, offset },
        WireFrame::StreamsBlocked { dir, limit } => Frame::StreamsBlocked { dir, limit },
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ReadableError, StreamEvent, streams as public};

    fn endpoint(side: Side) -> public::Connection {
        let mut endpoint = public::Connection::new(
            side,
            public::Config {
                max_remote_bidi: 4u32.into(),
                max_remote_uni: 4u32.into(),
                send_window: 64,
                receive_window: 64u32.into(),
                stream_receive_window: 64u32.into(),
            },
        );
        endpoint.set_peer_parameters(public::Parameters {
            initial_max_data: 64u32.into(),
            initial_max_stream_data_bidi_local: 64u32.into(),
            initial_max_stream_data_bidi_remote: 64u32.into(),
            initial_max_stream_data_uni: 64u32.into(),
            initial_max_streams_bidi: 4u32.into(),
            initial_max_streams_uni: 4u32.into(),
        });
        endpoint
    }

    fn transfer(from: &mut Connection, to: &mut Connection) {
        while let Some(transmit) = from.poll_transmit(1200) {
            let allocation_size = transmit.payload.len();
            for frame in frame::Iter::new(transmit.payload.clone()).unwrap() {
                let frame = public_frame(frame.unwrap()).unwrap();
                to.received_frame(frame, allocation_size).unwrap();
            }
            from.transmitted(transmit);
        }
    }

    #[test]
    fn reliable_carrier_drives_quinn_stream_state() {
        let mut client = endpoint(Side::Client);
        let mut server = endpoint(Side::Server);

        let id = client.streams().open(Dir::Bi).unwrap();
        client.send_stream(id).write(b"hello qmux").unwrap();
        client.send_stream(id).finish().unwrap();
        transfer(&mut client, &mut server);

        assert!(matches!(
            server.poll(),
            Some(StreamEvent::Opened { dir: Dir::Bi })
        ));
        assert_eq!(server.streams().accept(Dir::Bi), Some(id));
        assert!(matches!(
            server.poll(),
            Some(StreamEvent::Readable { id: readable }) if readable == id
        ));

        let mut recv = server.recv_stream(id);
        let mut chunks = recv.read(true).unwrap();
        let chunk = chunks.next(usize::MAX).unwrap().unwrap();
        assert_eq!(&chunk.bytes[..], b"hello qmux");
        assert!(chunks.next(usize::MAX).unwrap().is_none());
        let _ = chunks.finalize();

        assert!(matches!(
            client.poll(),
            Some(StreamEvent::Finished { id: finished }) if finished == id
        ));
        assert!(matches!(
            server.recv_stream(id).read(true),
            Err(ReadableError::ClosedStream)
        ));
    }

    #[test]
    fn typed_reset_drives_shared_stream_state() {
        let mut server = endpoint(Side::Server);
        let id = StreamId::new(Side::Client, Dir::Bi, 0);

        server
            .received_frame(
                Frame::Reset {
                    id,
                    error_code: 42u32.into(),
                    final_offset: 0u32.into(),
                },
                0,
            )
            .unwrap();

        assert!(matches!(
            server.poll(),
            Some(StreamEvent::Opened { dir: Dir::Bi })
        ));
        assert_eq!(server.streams().accept(Dir::Bi), Some(id));
        assert!(matches!(
            server.poll(),
            Some(StreamEvent::Readable { id: readable }) if readable == id
        ));
        assert!(matches!(
            server.recv_stream(id).read(true).unwrap().next(usize::MAX),
            Err(crate::ReadError::Reset(code)) if code == VarInt::from_u32(42)
        ));
    }

    #[test]
    fn rejects_out_of_order_stream_frames() {
        let mut server = endpoint(Side::Server);
        let id = StreamId::new(Side::Client, Dir::Bi, 0);

        let error = server
            .received_frame(
                Frame::Stream {
                    id,
                    offset: 1,
                    fin: false,
                    data: Bytes::from_static(b"x"),
                },
                1,
            )
            .unwrap_err();

        assert_eq!(error.code, crate::TransportErrorCode::PROTOCOL_VIOLATION);
    }

    #[test]
    fn close_stops_new_stream_work() {
        let mut client = endpoint(Side::Client);
        let id = client.streams().open(Dir::Uni).unwrap();
        client.send_stream(id).write(b"queued").unwrap();
        client.close();

        assert!(client.streams().open(Dir::Uni).is_none());
        assert_eq!(
            client.send_stream(id).write(b"more"),
            Err(crate::WriteError::Blocked)
        );
        assert!(client.poll_transmit(1200).is_none());
    }
}
