//! QMux: QUIC stream multiplexing over reliable, ordered transports
//!
//! An implementation of [draft-ietf-quic-qmux-02], which carries QUIC v1 streams, flow
//! control, and datagrams over any transport providing an ordered, reliable byte stream
//! (TCP, TLS, UNIX sockets) or record stream (WebSocket). It lets applications built on
//! QUIC fall back to TCP when UDP is blocked, without a second protocol implementation.
//!
//! The stream state machine is quinn-proto's, reused unmodified: because the underlying
//! transport is reliable, the draft treats data as acknowledged the moment it is handed to
//! the transport, and this crate simply drives quinn's acknowledgment path at
//! serialization time. There is no packetization, loss recovery, congestion control, or
//! cryptography at this layer.
//!
//! [`proto::Connection`] is the sans-IO core, mirroring `quinn_proto::Connection`. With
//! the default `runtime-tokio` feature, [`Session`] drives it over any
//! `AsyncRead + AsyncWrite` transport.
//!
//! [draft-ietf-quic-qmux-02]: https://www.ietf.org/archive/id/draft-ietf-quic-qmux-02.html

#![warn(missing_docs)]
#![warn(unreachable_pub)]
#![warn(clippy::use_self)]

pub mod proto;

mod config;
pub use config::Config;

// Re-export the quinn-proto vocabulary types that appear in this crate's API. The
// poll-level stream types (Chunks, WriteError, ...) live in `proto`, since the async
// layer wraps them with its own error types.
pub use quinn_proto::{
    Chunk, Dir, Side, StreamEvent, StreamId, TransportError, TransportErrorCode, VarInt,
};

pub use proto::{ConnectionError, Event, SendDatagramError};

#[cfg(feature = "runtime-tokio")]
mod runtime;
#[cfg(feature = "runtime-tokio")]
pub use runtime::{ReadError, RecvStream, SendStream, Session, WriteError};
