//! QMUX draft-02 record processing backed by [`quinn_proto::streams`].
//!
//! This crate intentionally owns the QMUX-specific layer—records, transport
//! parameters, QX frames, datagrams, and connection close—while delegating QUIC
//! stream lifecycle, flow control, buffering, scheduling, and resets to Quinn.

mod codec;
mod connection;
mod error;
mod parameters;

pub use connection::{Close, Config, Connection, Event, Transmit};
pub use error::Error;
pub use parameters::Parameters;

pub use quinn_proto::streams::{
    Chunk, Chunks, ClosedStream, Dir, FinishError, ReadError, ReadableError, RecvStream,
    SendStream, Side, StreamId, Streams, VarInt, WriteError, Written,
};

/// Default maximum size of a QMUX record's Frames field.
pub const DEFAULT_MAX_RECORD_SIZE: u64 = 16_382;
