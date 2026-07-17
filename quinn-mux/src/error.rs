use quinn_proto::{TransportError, VarIntBoundsExceeded};
use thiserror::Error;

/// Error while processing QMUX state or framing.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The input ended in the middle of a field or frame.
    #[error("truncated QMUX input")]
    Truncated,
    /// A QUIC variable-length integer was outside its representable range.
    #[error(transparent)]
    VarInt(#[from] VarIntBoundsExceeded),
    /// A frame type is prohibited or unsupported by this QMUX implementation.
    #[error("invalid QMUX frame type {0:#x}")]
    InvalidFrame(u64),
    /// A frame was structurally invalid.
    #[error("frame encoding error: {0}")]
    FrameEncoding(&'static str),
    /// A transport parameter was malformed or inconsistent.
    #[error("transport parameter error: {0}")]
    TransportParameter(&'static str),
    /// The peer sent more than one transport-parameters frame.
    #[error("duplicate QX_TRANSPORT_PARAMETERS frame")]
    DuplicateParameters,
    /// The peer's first frame was not QX_TRANSPORT_PARAMETERS.
    #[error("QX_TRANSPORT_PARAMETERS must be the first frame")]
    ParametersNotFirst,
    /// The QMUX record had trailing bytes or an incorrect size prefix.
    #[error("record size prefix does not match the Frames field")]
    RecordSizeMismatch,
    /// The peer exceeded our advertised record-size limit.
    #[error("record payload of {size} bytes exceeds limit {limit}")]
    RecordTooLarge { size: usize, limit: usize },
    /// A locally generated frame cannot fit in the peer's record-size limit.
    #[error("frame of {size} bytes exceeds peer record limit {limit}")]
    FrameTooLarge { size: usize, limit: usize },
    /// Datagram transmission was not negotiated.
    #[error("peer does not accept datagrams")]
    DatagramsUnsupported,
    /// A datagram exceeds the negotiated frame-size limit.
    #[error("datagram frame of {size} bytes exceeds limit {limit}")]
    DatagramTooLarge { size: usize, limit: u64 },
    /// A transmit token belongs to another connection.
    #[error("transmit belongs to another connection")]
    WrongConnection,
    /// Transmit completions were reported out of order.
    #[error("transmits must be completed in polling order")]
    OutOfOrderTransmit,
    /// The QMUX connection is closing or closed.
    #[error("QMUX connection is closing or closed")]
    ConnectionClosed,
    /// A locally requested QX_PING sequence did not strictly increase.
    #[error("QX_PING request sequence numbers must strictly increase")]
    PingSequence,
    /// Quinn's shared QUIC frame codec or stream state rejected a frame.
    #[error(transparent)]
    Protocol(#[from] TransportError),
}
