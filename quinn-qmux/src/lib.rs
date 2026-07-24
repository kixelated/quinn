//! Tokio runtime for QMux: QUIC stream multiplexing over reliable, ordered transports
//!
//! [QMux] (draft-ietf-quic-qmux-02) carries QUIC v1 streams, flow control, and datagrams
//! over any transport providing an ordered, reliable byte stream (TCP, TLS, UNIX sockets)
//! or record stream (WebSocket). It lets applications built on QUIC fall back to TCP when
//! UDP is blocked, without a second protocol implementation.
//!
//! The protocol logic lives in [`quinn_proto::qmux`] (re-exported here as [`proto`]),
//! where it drives quinn's stream state machine unmodified. This crate adds the async
//! layer: [`Session`] runs a connection over any `AsyncRead + AsyncWrite` transport.
//!
//! [QMux]: https://www.ietf.org/archive/id/draft-ietf-quic-qmux-02.html

#![warn(missing_docs)]
#![warn(unreachable_pub)]
#![warn(clippy::use_self)]

/// The sans-IO QMux state machine, from quinn-proto
pub use quinn_proto::qmux as proto;

pub use proto::{Config, ConnectionError, Event, SendDatagramError};

// Vocabulary types shared with quinn-proto
pub use quinn_proto::{
    Chunk, Dir, Side, StreamEvent, StreamId, TransportError, TransportErrorCode, VarInt,
};

mod runtime;
pub use runtime::{ReadError, RecvStream, SendStream, Session, WriteError};
