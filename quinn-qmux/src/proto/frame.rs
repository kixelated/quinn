//! Frame codec for draft-ietf-quic-qmux-02
//!
//! QMux reuses the QUIC version 1 frame formats for streams and flow control, and adds a
//! small number of extension frames. Frames the draft prohibits (ACK, CRYPTO, PING, path
//! and connection-ID related frames, ...) decode to a `FRAME_ENCODING_ERROR`.
//!
//! Only the frames quinn-proto does not already know how to serialize get encoders here;
//! STREAM, RESET_STREAM, STOP_SENDING, MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS and
//! STREAMS_BLOCKED are written directly by `StreamsState`.

use bytes::{Buf, BufMut, Bytes};
use quinn_proto::{
    Dir, StreamId, TransportError, TransportErrorCode, VarInt, coding::Codec,
    qmux_internal::{ResetStream, StreamFrame},
};

pub(crate) const PADDING: u64 = 0x00;
pub(crate) const RESET_STREAM: u64 = 0x04;
pub(crate) const STOP_SENDING: u64 = 0x05;
/// STREAM frames occupy `0x08..=0x0f`; OFF = 0x04, LEN = 0x02, FIN = 0x01
pub(crate) const STREAM_BASE: u64 = 0x08;
pub(crate) const STREAM_MAX: u64 = 0x0f;
pub(crate) const MAX_DATA: u64 = 0x10;
pub(crate) const MAX_STREAM_DATA: u64 = 0x11;
pub(crate) const MAX_STREAMS_BIDI: u64 = 0x12;
pub(crate) const MAX_STREAMS_UNI: u64 = 0x13;
pub(crate) const DATA_BLOCKED: u64 = 0x14;
pub(crate) const STREAM_DATA_BLOCKED: u64 = 0x15;
pub(crate) const STREAMS_BLOCKED_BIDI: u64 = 0x16;
pub(crate) const STREAMS_BLOCKED_UNI: u64 = 0x17;
pub(crate) const CONNECTION_CLOSE: u64 = 0x1c;
pub(crate) const APPLICATION_CLOSE: u64 = 0x1d;
/// From the Stream Resets with Partial Delivery extension; accepted but never sent
pub(crate) const RESET_STREAM_AT: u64 = 0x24;
pub(crate) const DATAGRAM: u64 = 0x30;
pub(crate) const DATAGRAM_LEN: u64 = 0x31;
/// Encodes as `\xffQMX\r\n\r\n` on the wire, disambiguating QMux from HTTP/1.1 and HTTP/2
pub(crate) const QX_TRANSPORT_PARAMETERS: u64 = 0x3f5153300d0a0d0a;
pub(crate) const QX_PING_REQUEST: u64 = 0x348c67529ef8c7bd;
pub(crate) const QX_PING_RESPONSE: u64 = 0x348c67529ef8c7be;

/// A decoded QMux frame
#[derive(Debug)]
pub(crate) enum Frame {
    Stream(StreamFrame),
    ResetStream(ResetStream),
    /// Validated at decode; the reliable size is irrelevant on a reliable transport
    ResetStreamAt(ResetStream),
    StopSending {
        id: StreamId,
        error_code: VarInt,
    },
    MaxData(VarInt),
    MaxStreamData {
        id: StreamId,
        offset: VarInt,
    },
    MaxStreams {
        dir: Dir,
        count: VarInt,
    },
    DataBlocked {
        offset: VarInt,
    },
    StreamDataBlocked {
        id: StreamId,
        offset: VarInt,
    },
    StreamsBlocked {
        dir: Dir,
        limit: VarInt,
    },
    Close(Close),
    Datagram(Bytes),
    TransportParameters(Bytes),
    PingRequest(VarInt),
    PingResponse(VarInt),
}

/// A CONNECTION_CLOSE (0x1c) or APPLICATION_CLOSE (0x1d) frame
#[derive(Debug, Clone)]
pub(crate) struct Close {
    pub(crate) is_application: bool,
    pub(crate) error_code: VarInt,
    /// Present only on CONNECTION_CLOSE
    pub(crate) frame_type: Option<VarInt>,
    pub(crate) reason: Bytes,
}

fn truncated() -> TransportError {
    TransportError::new(
        TransportErrorCode::FRAME_ENCODING_ERROR,
        "truncated frame".into(),
    )
}

fn get_varint(buf: &mut Bytes) -> Result<VarInt, TransportError> {
    VarInt::decode(buf).map_err(|_| truncated())
}

fn get_bytes(buf: &mut Bytes, len: u64) -> Result<Bytes, TransportError> {
    let len = usize::try_from(len).map_err(|_| truncated())?;
    if buf.remaining() < len {
        return Err(truncated());
    }
    Ok(buf.split_to(len))
}

impl Frame {
    /// Decode the next frame from a record, skipping padding
    ///
    /// Returns `None` once the record is exhausted. `buf` must be the frames portion of a
    /// single record; a frame never spans records.
    pub(crate) fn decode(buf: &mut Bytes) -> Result<Option<Self>, TransportError> {
        // Skip PADDING without recursing
        let ty = loop {
            if !buf.has_remaining() {
                return Ok(None);
            }
            let ty = get_varint(buf)?.into_inner();
            if ty != PADDING {
                break ty;
            }
        };

        let frame = match ty {
            STREAM_BASE..=STREAM_MAX => {
                let id = StreamId::decode(buf).map_err(|_| truncated())?;
                let offset = match ty & 0x04 != 0 {
                    true => get_varint(buf)?.into_inner(),
                    false => 0,
                };
                let data = match ty & 0x02 != 0 {
                    true => {
                        let len = get_varint(buf)?.into_inner();
                        get_bytes(buf, len)?
                    }
                    // No LEN: the frame extends to the end of the record
                    false => buf.split_to(buf.remaining()),
                };
                Self::Stream(StreamFrame {
                    id,
                    offset,
                    fin: ty & 0x01 != 0,
                    data,
                })
            }
            RESET_STREAM => Self::ResetStream(decode_reset(buf)?),
            RESET_STREAM_AT => {
                let reset = decode_reset(buf)?;
                let reliable_size = get_varint(buf)?;
                if reliable_size > reset.final_offset {
                    return Err(TransportError::new(
                        TransportErrorCode::FRAME_ENCODING_ERROR,
                        "RESET_STREAM_AT reliable size exceeds final size".into(),
                    ));
                }
                Self::ResetStreamAt(reset)
            }
            STOP_SENDING => Self::StopSending {
                id: StreamId::decode(buf).map_err(|_| truncated())?,
                error_code: get_varint(buf)?,
            },
            MAX_DATA => Self::MaxData(get_varint(buf)?),
            MAX_STREAM_DATA => Self::MaxStreamData {
                id: StreamId::decode(buf).map_err(|_| truncated())?,
                offset: get_varint(buf)?,
            },
            MAX_STREAMS_BIDI | MAX_STREAMS_UNI => Self::MaxStreams {
                dir: match ty == MAX_STREAMS_BIDI {
                    true => Dir::Bi,
                    false => Dir::Uni,
                },
                count: get_varint(buf)?,
            },
            DATA_BLOCKED => Self::DataBlocked {
                offset: get_varint(buf)?,
            },
            STREAM_DATA_BLOCKED => Self::StreamDataBlocked {
                id: StreamId::decode(buf).map_err(|_| truncated())?,
                offset: get_varint(buf)?,
            },
            STREAMS_BLOCKED_BIDI | STREAMS_BLOCKED_UNI => Self::StreamsBlocked {
                dir: match ty == STREAMS_BLOCKED_BIDI {
                    true => Dir::Bi,
                    false => Dir::Uni,
                },
                limit: get_varint(buf)?,
            },
            CONNECTION_CLOSE | APPLICATION_CLOSE => {
                let is_application = ty == APPLICATION_CLOSE;
                let error_code = get_varint(buf)?;
                let frame_type = match is_application {
                    true => None,
                    false => Some(get_varint(buf)?),
                };
                let len = get_varint(buf)?.into_inner();
                Self::Close(Close {
                    is_application,
                    error_code,
                    frame_type,
                    reason: get_bytes(buf, len)?,
                })
            }
            DATAGRAM => Self::Datagram(buf.split_to(buf.remaining())),
            DATAGRAM_LEN => {
                let len = get_varint(buf)?.into_inner();
                Self::Datagram(get_bytes(buf, len)?)
            }
            QX_TRANSPORT_PARAMETERS => {
                let len = get_varint(buf)?.into_inner();
                Self::TransportParameters(get_bytes(buf, len)?)
            }
            QX_PING_REQUEST => Self::PingRequest(get_varint(buf)?),
            QX_PING_RESPONSE => Self::PingResponse(get_varint(buf)?),
            _ => {
                // Both unknown frame types and the QUIC v1 frames QMux prohibits
                // (ACK, PING, CRYPTO, NEW_TOKEN, connection ID and path frames, ...)
                return Err(TransportError::new(
                    TransportErrorCode::FRAME_ENCODING_ERROR,
                    format!("prohibited or unknown frame type {ty:#x}"),
                ));
            }
        };
        Ok(Some(frame))
    }
}

fn decode_reset(buf: &mut Bytes) -> Result<ResetStream, TransportError> {
    Ok(ResetStream {
        id: StreamId::decode(buf).map_err(|_| truncated())?,
        error_code: get_varint(buf)?,
        final_offset: get_varint(buf)?,
    })
}

fn write_varint<B: BufMut>(buf: &mut B, x: u64) {
    VarInt::from_u64(x).expect("varint overflow").encode(buf);
}

/// Length of the variable-length encoding of `x`
pub(crate) fn varint_size(x: u64) -> usize {
    match x {
        _ if x < 1 << 6 => 1,
        _ if x < 1 << 14 => 2,
        _ if x < 1 << 30 => 4,
        _ => 8,
    }
}

pub(crate) fn encode_transport_parameters<B: BufMut>(buf: &mut B, params: &[u8]) {
    write_varint(buf, QX_TRANSPORT_PARAMETERS);
    write_varint(buf, params.len() as u64);
    buf.put_slice(params);
}

pub(crate) fn encode_ping<B: BufMut>(buf: &mut B, response: bool, seq: VarInt) {
    write_varint(
        buf,
        match response {
            true => QX_PING_RESPONSE,
            false => QX_PING_REQUEST,
        },
    );
    seq.encode(buf);
}

/// Size of an encoded QX_PING frame with the given sequence number
pub(crate) fn ping_size(seq: VarInt) -> usize {
    8 + varint_size(seq.into_inner())
}

pub(crate) fn encode_datagram<B: BufMut>(buf: &mut B, data: &[u8]) {
    write_varint(buf, DATAGRAM_LEN);
    write_varint(buf, data.len() as u64);
    buf.put_slice(data);
}

/// Total encoded size of a length-prefixed DATAGRAM frame carrying `len` payload bytes
pub(crate) fn datagram_frame_size(len: usize) -> usize {
    1 + varint_size(len as u64) + len
}

pub(crate) fn encode_close<B: BufMut>(buf: &mut B, close: &Close) {
    write_varint(
        buf,
        match close.is_application {
            true => APPLICATION_CLOSE,
            false => CONNECTION_CLOSE,
        },
    );
    close.error_code.encode(buf);
    if !close.is_application {
        close.frame_type.unwrap_or(VarInt::from_u32(0)).encode(buf);
    }
    write_varint(buf, close.reason.len() as u64);
    buf.put_slice(&close.reason);
}
